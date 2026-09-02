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

package com.linecorp.webauthn.authenticator

import com.google.common.truth.Truth.assertThat
import com.linecorp.webauthn.authenticator.keygenerator.BiometricKeyGenerator
import com.linecorp.webauthn.authenticator.objectgenerator.NoneObjectGenerator
import com.linecorp.webauthn.handler.BiometricAuthenticationHandler
import com.linecorp.webauthn.model.AuthenticatorType
import com.linecorp.webauthn.model.COSEAlgorithmIdentifier
import com.linecorp.webauthn.model.PublicKeyCredentialSource
import com.linecorp.webauthn.model.PublicKeyCredentialType
import com.linecorp.webauthn.util.Fido2Util
import com.linecorp.webauthn.util.MockCredentialSourceStorage
import com.linecorp.webauthn.util.SecureExecutionHelper
import com.linecorp.webauthn.util.toBase64url
import io.mockk.mockk
import java.security.KeyStore
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Test

/**
 * Checks key deletion against the real `AndroidKeyStore`.
 *
 * The unit-test coverage in `com.linecorp.webauthn.AuthenticatorTest` mocks
 * [SecureExecutionHelper], so it can only prove which alias was *asked* for. It cannot catch the
 * failure mode that mattered: `KeyStore.deleteEntry` is a silent no-op for an alias that does not
 * exist, so an alias derived differently from the one the key was generated under deletes nothing and
 * still reports success. Only a real keystore shows that.
 */
class CleanupAliasTest {

    private val generatedAliases = mutableListOf<String>()

    private val keyStore: KeyStore = KeyStore.getInstance("AndroidKeyStore").also { it.load(null) }

    private fun generateKeyFor(credId: String) {
        generatedAliases.add(credId)
        BiometricKeyGenerator().generateFido2Key(
            keyAlias = credId,
            challenge = null,
            publicKeyAlgorithm = COSEAlgorithmIdentifier.ES256,
            isStrongBoxBacked = false,
            // No enrolled biometric is needed to generate the key, which keeps this runnable on a bare
            // emulator. The alias handling under test is identical either way.
            userAuthenticationRequired = false
        )
    }

    @Test
    fun deleteKeyRemovesTheAliasUsedForGeneration() {
        val credId = Fido2Util.generateRandomByteArray(32).toBase64url()

        generateKeyFor(credId)
        assertThat(SecureExecutionHelper.containAlias(credId)).isTrue()

        SecureExecutionHelper.deleteKey(credId)

        assertThat(SecureExecutionHelper.containAlias(credId)).isFalse()
    }

    @Test
    fun deleteKeyIsANoOpForAnAliasThatIsAlreadyGone() {
        val credId = Fido2Util.generateRandomByteArray(32).toBase64url()
        assertThat(SecureExecutionHelper.containAlias(credId)).isFalse()

        // The contract `cleanup` relies on, and the reason it needs no existence check of its own:
        // cleanup runs on a failure path and `retryCleanup` calls it more than once, so a second pass
        // over an already-deleted alias has to succeed. AndroidKeyStoreSpi reports KEY_NOT_FOUND as
        // success on both keystore generations, but that is platform behaviour rather than something the
        // SDK enforces, so it is asserted here against the real keystore. Should a vendor keystore ever
        // throw instead, this fails and `cleanup` needs a containAlias guard restored.
        SecureExecutionHelper.deleteKey(credId)

        assertThat(SecureExecutionHelper.containAlias(credId)).isFalse()
    }

    @Test
    fun cleanupRemovesTheKeyGeneratedForTheCredentialId() {
        val credId = Fido2Util.generateRandomByteArray(32).toBase64url()
        val db = MockCredentialSourceStorage()
        val authType = AuthenticatorType.BiometricNone
        db.store(
            PublicKeyCredentialSource(
                type = PublicKeyCredentialType.PUBLIC_KEY.value,
                id = credId,
                rpId = "example.com",
                userHandle = "user123",
                aaguid = authType.aaguid,
            )
        )
        val authenticator = Authenticator(
            db = db,
            authenticationHandler = mockk<BiometricAuthenticationHandler>(),
            fido2KeyGenerator = BiometricKeyGenerator(),
            fido2ObjectGenerator = NoneObjectGenerator(),
            authType = authType,
        )

        generateKeyFor(credId)
        assertThat(keyStore.containsAlias(credId)).isTrue()

        runBlocking { authenticator.cleanup(credId) }

        // The end-to-end assertion the mocked unit test cannot make: the alias `cleanup` derives has to be
        // the one the key actually lives under, or the private key outlives the credential record.
        assertThat(keyStore.containsAlias(credId)).isFalse()
        assertThat(db.load(credId)).isNull()
    }

    @AfterEach
    fun tearDown() {
        // A failed assertion must not leave a hardware-backed key behind in the device's keystore, which
        // is precisely the leak this test exists to detect.
        for (alias in generatedAliases) {
            if (keyStore.containsAlias(alias)) {
                keyStore.deleteEntry(alias)
            }
        }
        generatedAliases.clear()
    }
}
