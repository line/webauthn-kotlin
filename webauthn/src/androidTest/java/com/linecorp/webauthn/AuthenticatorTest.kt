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

package com.linecorp.webauthn

import androidx.fragment.app.FragmentActivity
import androidx.test.core.app.ActivityScenario
import com.google.common.truth.Truth.assertThat
import com.google.common.truth.Truth.assertWithMessage
import com.linecorp.webauthn.authenticator.Authenticator
import com.linecorp.webauthn.authenticator.keygenerator.BiometricKeyGenerator
import com.linecorp.webauthn.authenticator.keygenerator.DeviceCredentialKeyGenerator
import com.linecorp.webauthn.authenticator.keygenerator.Fido2KeyGenerator
import com.linecorp.webauthn.authenticator.objectgenerator.AndroidKeyObjectGenerator
import com.linecorp.webauthn.authenticator.objectgenerator.NoneObjectGenerator
import com.linecorp.webauthn.handler.BiometricAuthenticationHandler
import com.linecorp.webauthn.model.AuthenticatorDataFlags
import com.linecorp.webauthn.model.AuthenticatorType
import com.linecorp.webauthn.model.COSEAlgorithmIdentifier
import com.linecorp.webauthn.model.Fido2UserAuthResult
import com.linecorp.webauthn.model.PublicKeyCredentialParams
import com.linecorp.webauthn.model.PublicKeyCredentialRpEntity
import com.linecorp.webauthn.model.PublicKeyCredentialType
import com.linecorp.webauthn.model.PublicKeyCredentialUserEntity
import com.linecorp.webauthn.util.MockCredentialSourceStorage
import com.linecorp.webauthn.util.TestFragmentActivity
import com.linecorp.webauthn.util.toBase64url
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import io.mockk.slot
import java.security.KeyStore
import java.security.Signature
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.MethodSource

class AuthenticatorTest {
    private lateinit var authenticator: Authenticator
    private var mockCredentialSourceStorage = MockCredentialSourceStorage()
    private val mockAuthenticationHandler: BiometricAuthenticationHandler = mockk()
    private val keyStore: KeyStore = KeyStore.getInstance("AndroidKeyStore").also {
        it.load(null)
    }

    private lateinit var dummyHash: ByteArray
    private lateinit var dummyRpEntity: PublicKeyCredentialRpEntity
    private lateinit var dummyUserEntity: PublicKeyCredentialUserEntity
    private lateinit var dummyCredParams: List<PublicKeyCredentialParams>
    private lateinit var dummyRpId: String
    private lateinit var dummyByteArray: ByteArray
    private lateinit var baselineAliases: Set<String>

    companion object {
        @JvmStatic
        fun authenticatorTypes() = listOf(
            AuthenticatorType.BiometricNone,
            AuthenticatorType.BiometricAndroidKey,
            AuthenticatorType.DeviceCredentialNone,
            AuthenticatorType.DeviceCredentialAndroidKey
        )
    }

    @BeforeEach
    fun setUp() {
        baselineAliases = keyStore.aliases().toList().toSet()
        dummyHash = ByteArray(32) { 0 }
        dummyRpEntity = PublicKeyCredentialRpEntity("example.com", "Example Relying Party")
        dummyUserEntity = PublicKeyCredentialUserEntity("user123", "User Name", "Display Name")
        dummyCredParams = listOf(
            PublicKeyCredentialParams(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256)
        )
        dummyRpId = "example.com"
        dummyByteArray = ByteArray(32) { 2 }

        coEvery { mockAuthenticationHandler.isSupported(any()) } returns true
        val signatureSlot = slot<(() -> Signature)?>()
        coEvery {
            mockAuthenticationHandler.authenticate(
                any(),
                any(),
                captureNullable(signatureSlot),
            )
        } coAnswers {
            val capturedSignature = signatureSlot.captured
            if (capturedSignature == null) {
                Fido2UserAuthResult(signature = null)
            } else {
                Fido2UserAuthResult(signature = capturedSignature())
            }
        }
    }

    private fun assignAuthenticator(authType: AuthenticatorType) {
        val mockKeyGenerator = mockk<Fido2KeyGenerator>()

        val keyAliasSlot = slot<String>()
        val challengeSlot = slot<ByteArray?>()
        val publicKeyAlgorithmSlot = slot<COSEAlgorithmIdentifier>()
        val isStrongBoxBackedSlot = slot<Boolean>()

        val realKeyGenerator = when (authType) {
            AuthenticatorType.BiometricNone -> BiometricKeyGenerator()
            AuthenticatorType.BiometricAndroidKey -> BiometricKeyGenerator()
            AuthenticatorType.DeviceCredentialNone -> DeviceCredentialKeyGenerator()
            AuthenticatorType.DeviceCredentialAndroidKey -> DeviceCredentialKeyGenerator()
        }

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
                userAuthenticationRequired = false // Override the value to false
            )
        }

        authenticator = when (authType) {
            AuthenticatorType.BiometricNone -> Authenticator(
                db = mockCredentialSourceStorage,
                authenticationHandler = mockAuthenticationHandler,
                fido2KeyGenerator = mockKeyGenerator,
                fido2ObjectGenerator = NoneObjectGenerator(),
                authType = authType,
            )

            AuthenticatorType.BiometricAndroidKey -> Authenticator(
                db = mockCredentialSourceStorage,
                authenticationHandler = mockAuthenticationHandler,
                fido2KeyGenerator = mockKeyGenerator,
                fido2ObjectGenerator = AndroidKeyObjectGenerator(),
                authType = authType,
            )

            AuthenticatorType.DeviceCredentialNone -> Authenticator(
                db = mockCredentialSourceStorage,
                authenticationHandler = mockAuthenticationHandler,
                fido2KeyGenerator = mockKeyGenerator,
                fido2ObjectGenerator = NoneObjectGenerator(),
                authType = authType,
            )

            AuthenticatorType.DeviceCredentialAndroidKey -> Authenticator(
                db = mockCredentialSourceStorage,
                authenticationHandler = mockAuthenticationHandler,
                fido2KeyGenerator = mockKeyGenerator,
                fido2ObjectGenerator = AndroidKeyObjectGenerator(),
                authType = authType,
            )
        }
    }

    private fun checkMakeCredentialAndGetAssertion(activity: FragmentActivity, authenticator: Authenticator) {
        runBlocking {
            val aliasListBefore = keyStore.aliases().toList()
            val makeCredentialResult = authenticator.makeCredential(
                activity = activity,
                hash = dummyHash,
                rpEntity = dummyRpEntity,
                userEntity = dummyUserEntity,
                credTypesAndPubKeyAlgs = dummyCredParams,
                excludeCredDescriptorList = null,
                extensions = null,
            )
            // The Result used to be discarded. A failure was only caught indirectly, through the alias count
            // below: handleMakeCredentialException cleans the key up, so the count does not rise. That works
            // only because the cleanup alias is now correct, and it says nothing about why it failed.
            assertWithMessage("makeCredential failed: ${makeCredentialResult.exceptionOrNull()}")
                .that(makeCredentialResult.isSuccess).isTrue()
            val aliasListAfter = keyStore.aliases().toList()

            assertThat(aliasListAfter.size).isEqualTo(aliasListBefore.size + 1)

            val newAlias = aliasListAfter.minus(aliasListBefore.toSet()).first()
            val newCredId = newAlias

            assertThat(mockCredentialSourceStorage.load(newCredId)).isNotNull()

            val getAssertionResult = authenticator.getAssertion(
                activity = activity,
                rpId = dummyRpId,
                hash = dummyByteArray,
                allowCredDescriptorList = null,
                extensions = null
            )

            // The assertion that was missing entirely. getAssertion catches every exception internally and
            // returns Result.failure, so authentication could fail completely - no key, no signature, a
            // storage error - while this test still passed.
            assertWithMessage("getAssertion failed: ${getAssertionResult.exceptionOrNull()}")
                .that(getAssertionResult.isSuccess).isTrue()
            val assertionResult = getAssertionResult.getOrThrow()
            assertThat(assertionResult.credentialId).hasLength(32)
            assertThat(assertionResult.credentialId.toBase64url()).isEqualTo(newAlias)
            // rpIdHash 32 + flags 1 + signCount 4, with no attested credential data and no extensions.
            assertThat(assertionResult.authenticatorData).hasLength(37)
            val flags = assertionResult.authenticatorData[32].toInt() and 0xff
            val userPresentAndVerified = (AuthenticatorDataFlags.UP.value or AuthenticatorDataFlags.UV.value)
                .toInt()
            assertThat(flags and userPresentAndVerified).isEqualTo(userPresentAndVerified)
            assertThat(assertionResult.signature).isNotEmpty()
            assertThat(assertionResult.userHandle).isNotNull()

            // Erase a key and a credential for next tests
            keyStore.deleteEntry(newAlias)
            mockCredentialSourceStorage.delete(newAlias)
            // The deletion used to be unchecked. KeyStore.deleteEntry is a silent no-op for an alias that
            // does not exist, so only this proves the key is really gone from the device.
            assertThat(keyStore.containsAlias(newAlias)).isFalse()
        }
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("authenticatorTypes")
    @DisplayName("Authenticators are functioning properly.")
    fun testAuthenticator(authType: AuthenticatorType) {
        ActivityScenario.launch(TestFragmentActivity::class.java).use { scenario ->
            var failure: Throwable? = null
            scenario.onActivity { activity: TestFragmentActivity ->
                assignAuthenticator(authType)
                try {
                    checkMakeCredentialAndGetAssertion(activity, authenticator)
                } catch (e: Throwable) {
                    // Kept rather than reported here. This block runs on the main thread, and an
                    // AssertionError raised there escapes into the Looper and takes the whole
                    // instrumentation run down instead of failing this one test - which is precisely what
                    // the assertions added above would do the first time they bite. `Exception` also let an
                    // AssertionError through unhandled.
                    failure = e
                }
            }
            failure?.let { e ->
                // The class name as well as the message: a message-less throwable used to report nothing.
                assertWithMessage("Expected no exception, but got: ${e::class.java.name}: ${e.message}")
                    .fail()
            }
        }
    }

    @AfterEach
    fun tearDown() {
        // The in-body cleanup above runs only on the success path. A failed assertion must not leave a
        // hardware-backed key behind on a shared device, so anything this invocation added goes here too.
        val leaked = keyStore.aliases().toList() - baselineAliases
        for (alias in leaked) {
            keyStore.deleteEntry(alias)
        }
        mockCredentialSourceStorage.removeAllData()
    }
}
