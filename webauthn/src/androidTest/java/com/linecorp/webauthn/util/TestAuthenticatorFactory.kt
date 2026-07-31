/*
 * Copyright 2024 LY Corporation
 *
 * LY Corporation licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

package com.linecorp.webauthn.util

import com.linecorp.webauthn.authenticator.Authenticator
import com.linecorp.webauthn.authenticator.AuthenticatorProvider
import com.linecorp.webauthn.authenticator.keygenerator.BiometricKeyGenerator
import com.linecorp.webauthn.authenticator.keygenerator.DeviceCredentialKeyGenerator
import com.linecorp.webauthn.authenticator.keygenerator.Fido2KeyGenerator
import com.linecorp.webauthn.authenticator.objectgenerator.AndroidKeyObjectGenerator
import com.linecorp.webauthn.authenticator.objectgenerator.Fido2ObjectGenerator
import com.linecorp.webauthn.authenticator.objectgenerator.NoneObjectGenerator
import com.linecorp.webauthn.db.CredentialSourceStorage
import com.linecorp.webauthn.handler.AuthenticationHandler
import com.linecorp.webauthn.model.AttestationStatementFormat
import com.linecorp.webauthn.model.AuthenticationMethod
import com.linecorp.webauthn.model.AuthenticatorType
import com.linecorp.webauthn.model.COSEAlgorithmIdentifier
import com.linecorp.webauthn.model.Fido2UserAuthResult
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import io.mockk.slot
import java.security.KeyStore
import java.security.Signature

/**
 * Builds an [Authenticator] that runs the real device path without a user-visible prompt.
 *
 * Only two things are replaced, and neither of them is the code under test:
 *
 * - the [AuthenticationHandler] is a mock that reports support and, instead of showing a
 *   `BiometricPrompt`, invokes the `signatureProvider` it was handed. That provider is what performs
 *   `initSign` on the real hardware key, so the signature the SDK goes on to use is a real one.
 * - the [Fido2KeyGenerator] is the real generator behind a mock that forces
 *   `userAuthenticationRequired = false`, so the generated key can be used for signing in the same pass.
 *   Everything else about the key - AndroidKeyStore, the algorithm, the attestation challenge, the
 *   StrongBox request - is unchanged.
 *
 * The object generator, `SecureExecutionHelper`, the KeyStore and the credential storage are all real.
 *
 * This is the same technique `com.linecorp.webauthn.AuthenticatorTest` sets up inline; it lives here so
 * that the tests which drive `PublicKeyCredential` and the failure paths do not each repeat it.
 */
internal object TestAuthenticatorFactory {

    /**
     * A handler that never shows UI: `authenticate` calls the provider it was given and returns the
     * resulting [Signature], which is exactly what a completed ceremony would hand back.
     */
    fun mockedAuthenticationHandler(): AuthenticationHandler {
        val handler = mockk<AuthenticationHandler>()
        every { handler.isSupported(any()) } returns true
        val signatureSlot = slot<(() -> Signature)?>()
        coEvery {
            handler.authenticate(any(), any(), captureNullable(signatureSlot))
        } coAnswers {
            Fido2UserAuthResult(signature = signatureSlot.captured?.invoke())
        }
        return handler
    }

    fun realAuthenticator(authType: AuthenticatorType, db: CredentialSourceStorage): Authenticator = Authenticator(
        db = db,
        authenticationHandler = mockedAuthenticationHandler(),
        fido2KeyGenerator = keyGeneratorWithoutUserAuthentication(authType),
        fido2ObjectGenerator = objectGenerator(authType),
        authType = authType,
    )

    /**
     * An [AuthenticatorProvider] that hands back [authenticator] for every combination.
     *
     * `PublicKeyCredential` takes its provider as a public constructor parameter, so this is what lets
     * `create`/`get` run end to end on a device without a prompt. The authenticator behind it is a real
     * one, not a mock, so everything after the provider call is production code.
     */
    fun mockedProviderReturning(authenticator: Authenticator): AuthenticatorProvider {
        val provider = mockk<AuthenticatorProvider>()
        every { provider.getAuthenticator(any(), any(), any()) } returns authenticator
        return provider
    }

    /** Deletes every alias in [aliases] that still exists, for use from a test's `@AfterEach`. */
    fun deleteAliases(keyStore: KeyStore, aliases: Collection<String>) {
        for (alias in aliases) {
            if (keyStore.containsAlias(alias)) {
                keyStore.deleteEntry(alias)
            }
        }
    }

    private fun keyGeneratorWithoutUserAuthentication(authType: AuthenticatorType): Fido2KeyGenerator {
        val realKeyGenerator = when (authType.getAuthenticationMethod()) {
            AuthenticationMethod.Biometric -> BiometricKeyGenerator()
            AuthenticationMethod.DeviceCredential -> DeviceCredentialKeyGenerator()
        }
        val mockKeyGenerator = mockk<Fido2KeyGenerator>()
        val keyAliasSlot = slot<String>()
        val challengeSlot = slot<ByteArray?>()
        val publicKeyAlgorithmSlot = slot<COSEAlgorithmIdentifier>()
        val isStrongBoxBackedSlot = slot<Boolean>()
        every {
            mockKeyGenerator.generateFido2Key(
                keyAlias = capture(keyAliasSlot),
                challenge = captureNullable(challengeSlot),
                publicKeyAlgorithm = capture(publicKeyAlgorithmSlot),
                isStrongBoxBacked = capture(isStrongBoxBackedSlot),
                userAuthenticationRequired = any()
            )
        } answers {
            realKeyGenerator.generateFido2Key(
                keyAlias = keyAliasSlot.captured,
                challenge = challengeSlot.captured,
                publicKeyAlgorithm = publicKeyAlgorithmSlot.captured,
                isStrongBoxBacked = isStrongBoxBackedSlot.captured,
                // Overridden so the key is usable for signing without an enrolled credential and a real
                // ceremony. The alias, the algorithm and the attestation challenge are the real ones.
                userAuthenticationRequired = false
            )
        }
        return mockKeyGenerator
    }

    private fun objectGenerator(authType: AuthenticatorType): Fido2ObjectGenerator =
        when (authType.getAttestationStatementFormat()) {
            AttestationStatementFormat.NONE -> NoneObjectGenerator()
            AttestationStatementFormat.ANDROID_KEY -> AndroidKeyObjectGenerator()
        }
}
