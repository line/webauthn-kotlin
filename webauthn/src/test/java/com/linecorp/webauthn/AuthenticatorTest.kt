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

import android.content.Context
import android.content.pm.PackageManager
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity
import com.google.common.truth.Truth.assertThat
import com.linecorp.webauthn.authenticator.Authenticator
import com.linecorp.webauthn.authenticator.keygenerator.BiometricKeyGenerator
import com.linecorp.webauthn.authenticator.keygenerator.DeviceCredentialKeyGenerator
import com.linecorp.webauthn.authenticator.keygenerator.Fido2KeyGenerator
import com.linecorp.webauthn.authenticator.objectgenerator.Fido2ObjectGenerator
import com.linecorp.webauthn.db.CredentialSourceStorage
import com.linecorp.webauthn.exceptions.WebAuthnException
import com.linecorp.webauthn.handler.AuthenticationHandler
import com.linecorp.webauthn.handler.BiometricAuthenticationHandler
import com.linecorp.webauthn.model.AssertionObject
import com.linecorp.webauthn.model.AttestationObject
import com.linecorp.webauthn.model.AuthenticatorType
import com.linecorp.webauthn.model.COSEAlgorithmIdentifier
import com.linecorp.webauthn.model.Fido2UserAuthResult
import com.linecorp.webauthn.model.PublicKeyCredentialDescriptor
import com.linecorp.webauthn.model.PublicKeyCredentialParams
import com.linecorp.webauthn.model.PublicKeyCredentialRpEntity
import com.linecorp.webauthn.model.PublicKeyCredentialSource
import com.linecorp.webauthn.model.PublicKeyCredentialType
import com.linecorp.webauthn.model.PublicKeyCredentialUserEntity
import com.linecorp.webauthn.util.Fido2Util
import com.linecorp.webauthn.util.MockCredentialSourceStorage
import com.linecorp.webauthn.util.SecureExecutionHelper
import com.linecorp.webauthn.util.toBase64url
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.spyk
import io.mockk.unmockkObject
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.cert.X509Certificate
import kotlin.reflect.KClass
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class AuthenticatorTest {

    private lateinit var mockActivity: FragmentActivity
    private lateinit var mockContext: Context
    private lateinit var mockPackageManager: PackageManager
    private lateinit var mockFido2Database: MockCredentialSourceStorage
    private lateinit var mockAuthenticationHandler: BiometricAuthenticationHandler
    private lateinit var mockObjectGenerator: Fido2ObjectGenerator
    private lateinit var mockKeyGenerator: Fido2KeyGenerator
    private lateinit var authenticator: Authenticator
    private lateinit var mockAttestationObject: AttestationObject
    private lateinit var mockAssertionObject: AssertionObject
    private lateinit var mockSignature: Signature
    private lateinit var mockCertificate: X509Certificate

    private lateinit var dummyHash: ByteArray
    private lateinit var dummyRpEntity: PublicKeyCredentialRpEntity
    private lateinit var dummyUserEntity: PublicKeyCredentialUserEntity
    private lateinit var dummyCredParams: List<PublicKeyCredentialParams>
    private lateinit var dummyCredId: String
    private lateinit var dummyByteArray: ByteArray
    private lateinit var es256CredParams: PublicKeyCredentialParams
    private lateinit var dummyCredSource: com.linecorp.webauthn.model.PublicKeyCredentialSource
    private lateinit var dummyKeyPair: KeyPair
    private lateinit var registeredCredId: String
    private lateinit var registeredRpEntity: PublicKeyCredentialRpEntity
    private lateinit var registeredUserEntity: PublicKeyCredentialUserEntity
    private lateinit var registeredCredSource: com.linecorp.webauthn.model.PublicKeyCredentialSource
    private lateinit var registeredCredDescriptor: PublicKeyCredentialDescriptor

    companion object {
        /**
         * Bounds the wait for the first cleanup attempt so a defect that never reaches it fails the test
         * instead of hanging the build. Generous, because the attempt crosses two real dispatchers.
         */
        private const val CLEANUP_CANCELLATION_TIMEOUT_MILLIS = 10_000L

        @JvmStatic
        fun authenticatorTypes() = listOf(
            AuthenticatorType.BiometricNone,
            AuthenticatorType.BiometricAndroidKey,
            AuthenticatorType.DeviceCredentialNone,
            AuthenticatorType.DeviceCredentialAndroidKey
        )
    }

    @BeforeAll
    fun beforeAllSetUp() {
        dummyHash = ByteArray(32) { 0 }
        dummyRpEntity = PublicKeyCredentialRpEntity("example.com", "Example Relying Party")
        dummyUserEntity = PublicKeyCredentialUserEntity("user123", "User Name", "Display Name")
        dummyCredParams = listOf(
            PublicKeyCredentialParams(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256)
        )
        dummyCredId = Fido2Util.generateRandomByteArray(32).toBase64url()
        dummyByteArray = ByteArray(32) { 2 }
        dummyCredSource = com.linecorp.webauthn.model.PublicKeyCredentialSource(
            id = dummyCredId,
            rpId = dummyRpEntity.id,
            userHandle = dummyUserEntity.id,
            aaguid = AuthenticatorType.BiometricAndroidKey.aaguid,
        )
        dummyKeyPair = KeyPairGenerator.getInstance("EC").apply { initialize(256) }
            .generateKeyPair()

        es256CredParams = PublicKeyCredentialParams(
            PublicKeyCredentialType.PUBLIC_KEY,
            COSEAlgorithmIdentifier.ES256
        )

        registeredCredId = Fido2Util.generateRandomByteArray(32).toBase64url()
        registeredRpEntity = PublicKeyCredentialRpEntity("registered.com", "Example Registered Relying Party")
        registeredUserEntity = PublicKeyCredentialUserEntity("reg_user", "Reg User", "Reg User")
        registeredCredSource = com.linecorp.webauthn.model.PublicKeyCredentialSource(
            id = registeredCredId,
            rpId = registeredRpEntity.id,
            userHandle = registeredUserEntity.id,
            aaguid = AuthenticatorType.BiometricAndroidKey.aaguid,
        )
        registeredCredDescriptor = PublicKeyCredentialDescriptor(
            type = PublicKeyCredentialType.PUBLIC_KEY.value,
            id = registeredCredSource.id,
            transports = null,
        )

        // activity
        mockActivity = mockk()
        mockContext = mockk()
        mockPackageManager = mockk()
        every { mockActivity.applicationContext } returns mockContext
        every { mockContext.packageManager } returns mockPackageManager
        every { mockPackageManager.hasSystemFeature(any()) } returns false

        // DB
        mockFido2Database = MockCredentialSourceStorage()

        // AuthenticationHandler
        mockAuthenticationHandler = mockk()
        mockSignature = mockk()
        every { mockAuthenticationHandler.isSupported(mockContext) } returns true
        every {
            mockAuthenticationHandler.canAuthenticateStatus(mockContext)
        } returns BiometricManager.BIOMETRIC_SUCCESS
        coEvery { mockAuthenticationHandler.authenticate(any(), any()) } returns Fido2UserAuthResult(mockSignature)

        // KeyGenerator
        mockKeyGenerator = mockk()
        mockAttestationObject = mockk()
        mockAssertionObject = mockk()
        every { mockKeyGenerator.generateFido2Key(any(), any(), any(), any()) } returns dummyKeyPair

        // ObjectGenerator
        mockObjectGenerator = mockk()
        coEvery {
            mockObjectGenerator.createAttestationObject(any(), any(), any(), any(), any(), any(), any())
        } returns mockAttestationObject
        coEvery {
            mockObjectGenerator.createAssertionObject(any(), any(), any(), any(), any())
        } returns mockAssertionObject
        coEvery { mockAttestationObject.toCBOR() } returns ByteArray(100)
        coEvery { mockAssertionObject.authenticatorData } returns ByteArray(100)
        coEvery { mockAssertionObject.signature } returns ByteArray(100)

        // SecureExecutionHelper
        mockCertificate = mockk()
        mockkObject(SecureExecutionHelper)
        every { SecureExecutionHelper.getKey(any()) } returns dummyKeyPair.private
        every { SecureExecutionHelper.deleteKey(any()) } returns Unit
        every { SecureExecutionHelper.getX509Certificate(any()) } returns mockCertificate
        every { mockCertificate.sigAlgName } returns "SHA256withECDSA"
        every { SecureExecutionHelper.containAlias(any()) } returns false

        authenticator = Authenticator(
            db = mockFido2Database,
            authenticationHandler = mockAuthenticationHandler,
            fido2KeyGenerator = mockKeyGenerator,
            fido2ObjectGenerator = mockObjectGenerator,
            authType = AuthenticatorType.BiometricAndroidKey,
        )
    }

    @BeforeEach
    fun beforeEachSetUp() {
        // By default, assume that the 'registeredCredSource' is always pre-registered in all tests.
        mockFido2Database.store(registeredCredSource)
    }

    @AfterEach
    fun afterEachTearDown() {
        mockFido2Database.removeAllData()
        // Restore the shared handler stub here rather than at the end of each test body: this class is
        // PER_CLASS, so a test that fails an assertion midway would otherwise leak its throwing stub into
        // every test that runs after it. Idempotent, so tests that also reset inline are unaffected.
        coEvery {
            mockAuthenticationHandler.authenticate(any(), any(), any())
        } returns Fido2UserAuthResult(mockSignature)
        // Same reasoning for the capability stubs: `checkAuthenticationSupport` now reads both, so a test
        // that makes the device look unsupported must not leak that state into the tests that follow.
        every { mockAuthenticationHandler.isSupported(mockContext) } returns true
        every {
            mockAuthenticationHandler.canAuthenticateStatus(mockContext)
        } returns BiometricManager.BIOMETRIC_SUCCESS
        // Same reasoning for the key generator stub: a test that makes key generation fail must not leak
        // the throwing stub into the tests that follow, even if it fails an assertion before restoring it.
        every { mockKeyGenerator.generateFido2Key(any(), any(), any(), any()) } returns dummyKeyPair
        // The SecureExecutionHelper stubs are restored here for a sharper reason than leakage alone:
        // `generateUniqueCredId` loops `do { ... } while (containAlias(credId))`, so a leaked
        // `containAlias(any()) returns true` would make every later `makeCredential` spin forever rather
        // than fail. Restoring after each test is what keeps that loop terminating.
        every { SecureExecutionHelper.containAlias(any()) } returns false
        every { SecureExecutionHelper.deleteKey(any()) } returns Unit
    }

    @AfterAll
    fun afterAllTearDown() {
        unmockkObject(SecureExecutionHelper)
    }

    private fun <T : Throwable> shouldThrowException(exceptionType: KClass<T>, block: suspend () -> Result<*>) {
        runBlocking {
            val result = block()
            if (result.isFailure) {
                val e: Throwable? = result.exceptionOrNull()
                assertThat(e).isInstanceOf(exceptionType.java)
            } else {
                Assertions.fail<String>(
                    "Expected ${exceptionType.qualifiedName} thrown, but successfully completed without exception."
                )
            }
        }
    }

    @Test
    fun `return success when makeCredential is called with valid parameters`(): Unit = runBlocking {
        try {
            authenticator.makeCredential(
                mockActivity,
                dummyHash,
                dummyRpEntity,
                dummyUserEntity,
                listOf(es256CredParams),
                listOf(registeredCredDescriptor),
                null
            )
        } catch (e: Exception) {
            Assertions.fail<String>(
                "makeCredential throws $e"
            )
        }
    }

    @Test
    fun `return success when getAssertion is called with valid parameters`(): Unit = runBlocking {
        try {
            authenticator.getAssertion(
                mockActivity,
                dummyRpEntity.id,
                dummyHash,
                null,
                null
            )
        } catch (e: Exception) {
            Assertions.fail<String>(
                "makeCredential throws $e"
            )
        }
    }

    @Test
    fun `should throw NotSupportedException when makeCredential is called with unsupported algorithm`() {
        val credTypesAndPubKeyAlgsWithUncompatibleAlg = mutableListOf(
            PublicKeyCredentialParams(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES512)
        )

        shouldThrowException(WebAuthnException.CoreException.NotSupportedException::class) {
            authenticator.makeCredential(
                mockActivity,
                dummyHash,
                dummyRpEntity,
                dummyUserEntity,
                credTypesAndPubKeyAlgsWithUncompatibleAlg,
                listOf(registeredCredDescriptor),
                null
            )
        }
    }

    @Test
    fun `should throw InvalidStateException when makeCredential is called with already registered credential`() {
        shouldThrowException(WebAuthnException.CoreException.InvalidStateException::class) {
            authenticator.makeCredential(
                mockActivity,
                dummyHash,
                registeredRpEntity,
                registeredUserEntity,
                listOf(es256CredParams),
                listOf(registeredCredDescriptor),
                null
            )
        }
    }

    @Test
    fun `should throw NotAllowedException when getAssertion is called with unregistered rpId`() {
        shouldThrowException(WebAuthnException.CoreException.NotAllowedException::class) {
            authenticator.getAssertion(
                mockActivity,
                "WrongRpId",
                dummyHash,
                null,
                null
            )
        }
    }

    @Test
    fun `should throw ConstraintException when authentication is not supported`() {
        every { mockAuthenticationHandler.isSupported(mockContext) } returns false

        shouldThrowException(WebAuthnException.CoreException.ConstraintException::class) {
            authenticator.makeCredential(
                mockActivity,
                dummyHash,
                dummyRpEntity,
                dummyUserEntity,
                listOf(es256CredParams),
                listOf(registeredCredDescriptor),
                null
            )
        }

        shouldThrowException(WebAuthnException.CoreException.ConstraintException::class) {
            authenticator.getAssertion(
                mockActivity,
                registeredRpEntity.id,
                dummyByteArray,
                null,
                null
            )
        }

        every { mockAuthenticationHandler.isSupported(mockContext) } returns true
    }

    @Test
    fun `should throw NotAllowedException when biometric authentication fails`() {
        coEvery {
            mockAuthenticationHandler.authenticate(any(), any(), any())
        } throws AuthenticationHandler.AuthenticationFailedException()

        shouldThrowException(WebAuthnException.CoreException.NotAllowedException::class) {
            authenticator.makeCredential(
                mockActivity,
                dummyByteArray,
                dummyRpEntity,
                dummyUserEntity,
                listOf(es256CredParams),
                listOf(registeredCredDescriptor),
                null
            )
        }

        shouldThrowException(WebAuthnException.CoreException.NotAllowedException::class) {
            authenticator.getAssertion(
                mockActivity,
                registeredRpEntity.id,
                dummyByteArray,
                null,
                null
            )
        }

        coEvery {
            mockAuthenticationHandler.authenticate(any(), any(), any())
        } returns Fido2UserAuthResult(mockSignature)
    }

    @Test
    fun `should throw NotAllowedException when biometric authentication throws error`() {
        coEvery {
            mockAuthenticationHandler.authenticate(any(), any(), any())
        } throws AuthenticationHandler.AuthenticationErrorException()

        shouldThrowException(WebAuthnException.CoreException.NotAllowedException::class) {
            authenticator.makeCredential(
                mockActivity,
                dummyByteArray,
                dummyRpEntity,
                dummyUserEntity,
                listOf(es256CredParams),
                listOf(registeredCredDescriptor),
                null
            )
        }

        shouldThrowException(WebAuthnException.CoreException.NotAllowedException::class) {
            authenticator.getAssertion(
                mockActivity,
                registeredRpEntity.id,
                dummyByteArray,
                null,
                null
            )
        }

        coEvery {
            mockAuthenticationHandler.authenticate(any(), any(), any())
        } returns Fido2UserAuthResult(mockSignature)
    }

    @Test
    fun `user cancellation surfaces as UserCancelledException carrying the error code`() {
        listOf(
            BiometricPrompt.ERROR_CANCELED,
            BiometricPrompt.ERROR_USER_CANCELED,
            BiometricPrompt.ERROR_NEGATIVE_BUTTON
        ).forEach { code ->
            val thrown = AuthenticationHandler.AuthenticationErrorException(errorCode = code, message = "cancelled")
            coEvery { mockAuthenticationHandler.authenticate(any(), any(), any()) } throws thrown

            runBlocking {
                val result = authenticator.getAssertion(mockActivity, registeredRpEntity.id, dummyByteArray, null, null)

                val e = result.exceptionOrNull()
                assertThat(e).isInstanceOf(WebAuthnException.CoreException.UserCancelledException::class.java)
                assertThat((e as WebAuthnException.CoreException.NotAllowedException).errorCode).isEqualTo(code)
                // Consumers built against 1.1.3 cannot see `errorCode`; they read the original handler
                // exception off `cause`. Dropping or re-wrapping it is a breaking change.
                assertThat(e.cause).isSameInstanceAs(thrown)
            }
        }
    }

    @Test
    fun `a genuine biometric error stays a plain NotAllowedException with its error code`() {
        val thrown = AuthenticationHandler.AuthenticationErrorException(
            errorCode = BiometricPrompt.ERROR_HW_UNAVAILABLE,
            message = "hardware unavailable"
        )
        coEvery { mockAuthenticationHandler.authenticate(any(), any(), any()) } throws thrown

        runBlocking {
            val result = authenticator.getAssertion(mockActivity, registeredRpEntity.id, dummyByteArray, null, null)

            val e = result.exceptionOrNull()
            assertThat(e).isInstanceOf(WebAuthnException.CoreException.NotAllowedException::class.java)
            assertThat(e).isNotInstanceOf(WebAuthnException.CoreException.UserCancelledException::class.java)
            assertThat((e as WebAuthnException.CoreException.NotAllowedException).errorCode)
                .isEqualTo(BiometricPrompt.ERROR_HW_UNAVAILABLE)
            assertThat(e.cause).isSameInstanceAs(thrown)
        }
    }

    @Test
    fun `the host-state-saved sentinel is not treated as a user cancellation`() {
        val thrown = AuthenticationHandler.AuthenticationErrorException(
            errorCode = AuthenticationHandler.ERROR_HOST_STATE_SAVED,
            message = "state saved"
        )
        coEvery { mockAuthenticationHandler.authenticate(any(), any(), any()) } throws thrown

        runBlocking {
            val result = authenticator.getAssertion(mockActivity, registeredRpEntity.id, dummyByteArray, null, null)

            val e = result.exceptionOrNull()
            assertThat(e).isNotInstanceOf(WebAuthnException.CoreException.UserCancelledException::class.java)
            assertThat(e).isInstanceOf(WebAuthnException.CoreException.NotAllowedException::class.java)
            assertThat((e as WebAuthnException.CoreException.NotAllowedException).errorCode)
                .isEqualTo(AuthenticationHandler.ERROR_HOST_STATE_SAVED)
            assertThat(e.cause).isSameInstanceAs(thrown)
        }
    }

    @Test
    fun `a permanently invalidated key is reported as such, not as a cancellation`() {
        // Guards the mapping rather than the handler: this passes whether or not
        // `DeviceCredentialAuthenticationHandler` wraps the exception, because it is injected at the handler
        // boundary. Its job is to keep the `KeyPermanentlyInvalidatedException` branch reachable if the order
        // of `authenticate`'s catch clauses is ever rearranged - the AuthenticationErrorException branch
        // matches first and would swallow a subtype of it.
        val thrown = android.security.keystore.KeyPermanentlyInvalidatedException()
        coEvery { mockAuthenticationHandler.authenticate(any(), any(), any()) } throws thrown

        runBlocking {
            val result = authenticator.getAssertion(mockActivity, registeredRpEntity.id, dummyByteArray, null, null)

            val e = result.exceptionOrNull()
            assertThat(e)
                .isInstanceOf(WebAuthnException.AuthenticationException.KeyPermanentlyInvalidatedException::class.java)
            // The two outcomes that would make re-registration undiscoverable: a bare NotAllowedException
            // looks like any other refusal, and UnknownException tells the app nothing at all.
            assertThat(e).isNotInstanceOf(WebAuthnException.CoreException.NotAllowedException::class.java)
            assertThat(e).isNotInstanceOf(WebAuthnException.UnknownException::class.java)
            assertThat(e?.cause).isSameInstanceAs(thrown)
        }
        // The throwing stub is restored in `afterEachTearDown`, not here, so a failed assertion above
        // cannot leak it into the tests that follow.
    }

    @Test
    fun `ConstraintException reports the canAuthenticate status that caused it`() {
        every { mockAuthenticationHandler.isSupported(mockContext) } returns false
        every {
            mockAuthenticationHandler.canAuthenticateStatus(mockContext)
        } returns BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED

        runBlocking {
            val result = authenticator.getAssertion(mockActivity, registeredRpEntity.id, dummyByteArray, null, null)

            val e = result.exceptionOrNull()
            assertThat(e).isInstanceOf(WebAuthnException.CoreException.ConstraintException::class.java)
            assertThat((e as WebAuthnException.CoreException.ConstraintException).canAuthenticateStatus)
                .isEqualTo(BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED)
        }
    }

    @Test
    fun `a keystore rejection surfaces as KeyGenerationException rather than UnknownException`() {
        val thrown = java.security.ProviderException("Failed to generate key pair.")
        every { mockKeyGenerator.generateFido2Key(any(), any(), any(), any()) } throws thrown

        runBlocking {
            val result = authenticator.makeCredential(
                mockActivity,
                dummyHash,
                dummyRpEntity,
                dummyUserEntity,
                listOf(es256CredParams),
                listOf(registeredCredDescriptor),
                null
            )

            val e = result.exceptionOrNull()
            assertThat(e).isInstanceOf(WebAuthnException.KeyGenerationException::class.java)
            assertThat(e).isInstanceOf(WebAuthnException.SecureExecutionException::class.java)
            assertThat(e).isNotInstanceOf(WebAuthnException.UnknownException::class.java)
            assertThat(e).hasMessageThat().contains("strongBoxRequested=")
            // The in-tree consumer reads the platform exception off `cause`; re-wrapping or dropping it
            // is a breaking change, so the identity is pinned here as well.
            assertThat(e?.cause).isSameInstanceAs(thrown)
        }
        // The throwing stub is restored in `afterEachTearDown`, not here, so a failed assertion above
        // cannot leak it into the tests that follow.
    }

    @Test
    fun `a keystore rejection reachable only through suppressed is still recognised`() {
        // The shape `generateWithStrongBoxFallback` produces when the TEE retry fails with something that
        // is not itself a keystore rejection: the StrongBox failure — the one carrying the KeyMint code —
        // rides on `suppressed`, not on `cause`. A cause-only classifier would miss it.
        val strongBoxFailure = java.security.ProviderException("Failed to generate key pair.")
        val retryFailure = IllegalStateException("retry failed").apply { addSuppressed(strongBoxFailure) }
        every { mockKeyGenerator.generateFido2Key(any(), any(), any(), any()) } throws retryFailure

        runBlocking {
            val result = authenticator.makeCredential(
                mockActivity,
                dummyHash,
                dummyRpEntity,
                dummyUserEntity,
                listOf(es256CredParams),
                listOf(registeredCredDescriptor),
                null
            )

            val e = result.exceptionOrNull()
            assertThat(e).isInstanceOf(WebAuthnException.KeyGenerationException::class.java)
            assertThat(e?.cause).isSameInstanceAs(retryFailure)
        }
    }

    @Test
    fun `a cancellation between cleanup attempts carries the triggering failure as suppressed`() {
        // The KeyMint error code exists only on the KeyGenerationException this path builds, so a
        // cancellation that replaced it would leave no record of why the platform refused the key. The
        // relying-party path in `PublicKeyCredential.create` already attaches its trigger the same way.
        val keystoreFailure = java.security.ProviderException("Failed to generate key pair.")
        every { mockKeyGenerator.generateFido2Key(any(), any(), any(), any()) } throws keystoreFailure
        val firstCleanupAttempt = CompletableDeferred<Unit>()
        // Fails every attempt, so the first failure is followed by the cancellable wait between attempts.
        val cleanupFailingDb = object : CredentialSourceStorage by mockFido2Database {
            override fun delete(credId: String) {
                firstCleanupAttempt.complete(Unit)
                throw IllegalStateException("the row is locked")
            }
        }
        val cleanupFailingAuthenticator = Authenticator(
            db = cleanupFailingDb,
            authenticationHandler = mockAuthenticationHandler,
            fido2KeyGenerator = mockKeyGenerator,
            fido2ObjectGenerator = mockObjectGenerator,
            authType = AuthenticatorType.BiometricAndroidKey,
        )

        runBlocking {
            var caught: Throwable? = null
            val job = launch(Dispatchers.Default) {
                try {
                    cleanupFailingAuthenticator.makeCredential(
                        mockActivity,
                        dummyHash,
                        dummyRpEntity,
                        dummyUserEntity,
                        listOf(es256CredParams),
                        listOf(registeredCredDescriptor),
                        null
                    )
                } catch (e: CancellationException) {
                    caught = e
                }
            }
            // Cancelling only after the first attempt has failed is what lands the cancellation on the wait
            // between attempts rather than somewhere in the ceremony. `cleanup` is NonCancellable, so it
            // does not matter whether the cancellation arrives before or after the job reaches the `delay`.
            withTimeout(CLEANUP_CANCELLATION_TIMEOUT_MILLIS) { firstCleanupAttempt.await() }
            job.cancel()
            job.join()

            assertThat(caught).isInstanceOf(CancellationException::class.java)
            val suppressed = caught?.suppressed?.toList()
            assertThat(suppressed).hasSize(1)
            assertThat(suppressed?.first()).isInstanceOf(WebAuthnException.KeyGenerationException::class.java)
            // The platform failure is still reachable, which is the point: `cause` is where the KeyMint
            // error code and the vendor message are read from.
            assertThat(suppressed?.first()?.cause).isSameInstanceAs(keystoreFailure)
        }
    }

    @Test
    fun `a pre-flight failure survives a cleanup that fails over state it never created`() {
        // The exclude-list check runs before key generation, and the database row is written after it, so
        // the cleanup that follows deletes an id that was never stored. `CredentialSourceStorage.delete`
        // is not required to be idempotent, and a consumer that rejects an unknown id used to have its
        // InvalidStateException replaced by a DeletionException - which is the exception consumers route
        // on to tell "already registered" apart from a real deletion fault.
        val deleteFailure = IllegalStateException("no row for that credId")
        val cleanupFailingDb = object : CredentialSourceStorage by mockFido2Database {
            override fun delete(credId: String): Unit = throw deleteFailure
        }
        val cleanupFailingAuthenticator = Authenticator(
            db = cleanupFailingDb,
            authenticationHandler = mockAuthenticationHandler,
            fido2KeyGenerator = mockKeyGenerator,
            fido2ObjectGenerator = mockObjectGenerator,
            authType = AuthenticatorType.BiometricAndroidKey,
        )

        runBlocking {
            val result = cleanupFailingAuthenticator.makeCredential(
                mockActivity,
                dummyHash,
                registeredRpEntity,
                registeredUserEntity,
                listOf(es256CredParams),
                listOf(registeredCredDescriptor),
                null
            )

            val e = result.exceptionOrNull()
            assertThat(e).isInstanceOf(WebAuthnException.CoreException.InvalidStateException::class.java)
            assertThat(e).isNotInstanceOf(WebAuthnException.DeletionException::class.java)
            // Demoted, not dropped: the storage fault is still printed with the stack trace. Compared by
            // type and message rather than identity, because the consumer's throwable crosses the database
            // dispatcher and kotlinx.coroutines' stack-trace recovery copies any exception whose class
            // declares no fields of its own - which IllegalStateException does not.
            val suppressed = e?.suppressed?.toList()
            assertThat(suppressed).hasSize(1)
            assertThat(suppressed?.first()).isInstanceOf(WebAuthnException.CredSrcStorageException::class.java)
            assertThat(suppressed?.first()?.cause).isInstanceOf(IllegalStateException::class.java)
            assertThat(suppressed?.first()?.cause).hasMessageThat().isEqualTo(deleteFailure.message)
        }
    }

    @Test
    fun `the key generator retries without StrongBox when the platform rejects the request`() {
        val attempts = mutableListOf<Boolean>()
        val recordingGenerator = object : Fido2KeyGenerator() {
            override fun generateFido2Key(
                keyAlias: String,
                challenge: ByteArray?,
                publicKeyAlgorithm: COSEAlgorithmIdentifier,
                isStrongBoxBacked: Boolean,
                userAuthenticationRequired: Boolean
            ): KeyPair = generateWithStrongBoxFallback(isStrongBoxBacked) { strongBox ->
                attempts.add(strongBox)
                if (strongBox) throw java.security.ProviderException("Failed to generate key pair.")
                dummyKeyPair
            }
        }

        val keyPair = recordingGenerator.generateFido2Key(
            keyAlias = "alias",
            challenge = null,
            publicKeyAlgorithm = COSEAlgorithmIdentifier.ES256,
            isStrongBoxBacked = true
        )

        assertThat(keyPair).isSameInstanceAs(dummyKeyPair)
        assertThat(attempts).containsExactly(true, false).inOrder()
    }

    @Test
    fun `BiometricKeyGenerator routes both StrongBox attempts through the shared fallback`() {
        val generator = spyk(BiometricKeyGenerator(), recordPrivateCalls = true)
        val attempts = mutableListOf<Boolean>()
        every {
            generator["generateBiometricFido2Key"](
                any<String>(),
                any<ByteArray>(),
                any<COSEAlgorithmIdentifier>(),
                any<Boolean>(),
                any<Boolean>()
            )
        } answers {
            val strongBoxBacked = arg<Boolean>(3)
            attempts.add(strongBoxBacked)
            if (strongBoxBacked) throw java.security.ProviderException("Failed to generate key pair.")
            dummyKeyPair
        }

        val keyPair = generator.generateFido2Key(
            keyAlias = "alias",
            challenge = null,
            publicKeyAlgorithm = COSEAlgorithmIdentifier.ES256,
            isStrongBoxBacked = true
        )

        assertThat(keyPair).isSameInstanceAs(dummyKeyPair)
        assertThat(attempts).containsExactly(true, false).inOrder()
    }

    @Test
    fun `DeviceCredentialKeyGenerator routes both StrongBox attempts through the shared fallback`() {
        val generator = spyk(DeviceCredentialKeyGenerator(), recordPrivateCalls = true)
        val attempts = mutableListOf<Boolean>()
        every {
            generator["generateDeviceCredentialFido2Key"](
                any<String>(),
                any<ByteArray>(),
                any<COSEAlgorithmIdentifier>(),
                any<Boolean>(),
                any<Boolean>(),
                any<Int>()
            )
        } answers {
            val strongBoxBacked = arg<Boolean>(3)
            attempts.add(strongBoxBacked)
            if (strongBoxBacked) throw java.security.ProviderException("Failed to generate key pair.")
            dummyKeyPair
        }

        val keyPair = generator.generateFido2Key(
            keyAlias = "alias",
            challenge = null,
            publicKeyAlgorithm = COSEAlgorithmIdentifier.ES256,
            isStrongBoxBacked = true
        )

        assertThat(keyPair).isSameInstanceAs(dummyKeyPair)
        assertThat(attempts).containsExactly(true, false).inOrder()
    }

    @Test
    fun `a generator that requested no StrongBox makes a single attempt`() {
        val generator = spyk(BiometricKeyGenerator(), recordPrivateCalls = true)
        val attempts = mutableListOf<Boolean>()
        every {
            generator["generateBiometricFido2Key"](
                any<String>(),
                any<ByteArray>(),
                any<COSEAlgorithmIdentifier>(),
                any<Boolean>(),
                any<Boolean>()
            )
        } answers {
            attempts.add(arg(3))
            throw java.security.ProviderException("Failed to generate key pair.")
        }

        // A device that never advertised StrongBox has nothing to fall back to: the failure must
        // propagate on the first attempt rather than being retried identically.
        val thrown = Assertions.assertThrows(java.security.ProviderException::class.java) {
            generator.generateFido2Key(
                keyAlias = "alias",
                challenge = null,
                publicKeyAlgorithm = COSEAlgorithmIdentifier.ES256,
                isStrongBoxBacked = false
            )
        }

        assertThat(attempts).containsExactly(false)
        assertThat(thrown.suppressed).isEmpty()
    }

    @Test
    fun `cleanup deletes the key under the same alias the key was created with`() {
        val deletedAliases = mutableListOf<String>()
        // Stubbed for this one alias rather than `any()`: `generateUniqueCredId` loops while
        // `containAlias` is true, so a blanket `true` here would hang any test that reuses this mock.
        every { SecureExecutionHelper.containAlias(registeredCredId) } returns true
        every { SecureExecutionHelper.deleteKey(capture(deletedAliases)) } returns Unit

        runBlocking { authenticator.cleanup(registeredCredId) }

        assertThat(deletedAliases).containsExactly(registeredCredId)
        // The regression this pins down: `credId` is already base64url and `makeCredential` uses it
        // verbatim as the KeyStore alias, so encoding it a second time names an alias no key was ever
        // stored under — and `KeyStore.deleteEntry` no-ops silently on a missing alias, so cleanup
        // reported success while leaving the private key behind.
        val doubleEncoded = registeredCredId.toBase64url()
        assertThat(deletedAliases).doesNotContain(doubleEncoded)
        // These two are the part that can fail independently of the assertion above, because they are
        // statements about `Encoding.kt` rather than about the captured list: the `ByteArray` and `String`
        // overloads of `toBase64url` must keep producing different aliases for 43 and 58 characters
        // respectively. Were `String.toBase64url` ever "fixed" into a passthrough — the wrong file to
        // change — the old double-encoding call site would satisfy every assertion above it while the
        // defect went unnoticed.
        assertThat(registeredCredId).hasLength(43)
        assertThat(doubleEncoded).hasLength(58)
        assertThat(mockFido2Database.load(registeredCredId)).isNull()
    }

    @Test
    fun `cleanup propagates a genuine key deletion failure instead of swallowing it`() {
        val thrown = WebAuthnException.SecureExecutionException("Cannot delete key from KeyStore.")
        every { SecureExecutionHelper.containAlias(registeredCredId) } returns true
        every { SecureExecutionHelper.deleteKey(registeredCredId) } throws thrown

        // This is the property that stops "reported success while the key survived" from coming back by
        // another route. A caller that cannot see the deletion failure cannot retry it:
        // `handleMakeCredentialException` would report the registration failure alone and the private key
        // would stay on the device forever. A future well-meaning
        // `try { deleteKeyIfPresent(credId) } catch (e: Exception) { }` has to break this test.
        val caught = Assertions.assertThrows(WebAuthnException.SecureExecutionException::class.java) {
            runBlocking { authenticator.cleanup(registeredCredId) }
        }

        assertThat(caught).isSameInstanceAs(thrown)
        // The row has to survive too. Deleting it while the key is still present is exactly what made the
        // orphaned keys unrecoverable: the credential ID is the only name the alias ever had.
        assertThat(mockFido2Database.load(registeredCredId)).isNotNull()
    }

    @Test
    fun `retryCleanup succeeds when the first attempt deleted the key and then failed on the database`() {
        // The precise sequence `cleanup`'s KDoc cites as the reason a missing alias must count as success,
        // exercised through `retryCleanup` rather than asserted in prose: attempt 1 removes the key and
        // then throws on the row, so attempt 2 necessarily runs against an alias that is legitimately
        // already gone. A `cleanup` that treated that as an error would turn a recoverable database blip
        // into a `DeletionException` that replaces the failure which triggered cleanup in the first place.
        val deletedAliases = mutableListOf<String>()
        var dbDeleteCalls = 0
        val flakyDb = object : CredentialSourceStorage by mockFido2Database {
            override fun delete(credId: String) {
                dbDeleteCalls++
                if (dbDeleteCalls == 1) {
                    throw IllegalStateException("the row is locked")
                }
                mockFido2Database.delete(credId)
            }
        }
        // True once, false afterwards: the key really is gone after attempt 1 deleted it.
        every { SecureExecutionHelper.containAlias(registeredCredId) } returns true andThen false
        every { SecureExecutionHelper.deleteKey(capture(deletedAliases)) } returns Unit
        val retryingAuthenticator = Authenticator(
            db = flakyDb,
            authenticationHandler = mockAuthenticationHandler,
            fido2KeyGenerator = mockKeyGenerator,
            fido2ObjectGenerator = mockObjectGenerator,
            authType = AuthenticatorType.BiometricAndroidKey,
        )

        runBlocking { retryingAuthenticator.retryCleanup(registeredCredId, maxTries = 2, delayMillis = 0) }

        assertThat(dbDeleteCalls).isEqualTo(2)
        // Attempted only while the alias existed. The second pass must not ask the keystore to delete a key
        // it has already deleted, which is the difference between idempotent and merely tolerant.
        assertThat(deletedAliases).containsExactly(registeredCredId)
        assertThat(mockFido2Database.load(registeredCredId)).isNull()
    }

    @Test
    fun `cleanup succeeds when the alias is already gone`() {
        val deletedAliases = mutableListOf<String>()
        every { SecureExecutionHelper.containAlias(registeredCredId) } returns false
        every { SecureExecutionHelper.deleteKey(capture(deletedAliases)) } returns Unit

        // Must not throw: cleanup runs on the failure path, so replacing the error that triggered it
        // with a "key not found" of its own would hide the real cause. It also has to stay idempotent
        // for `retryCleanup`, whose second attempt always finds the alias already deleted.
        runBlocking { authenticator.cleanup(registeredCredId) }

        // A capture list rather than `verify(exactly = 0)`: this class is PER_CLASS and the object mock
        // records every call made across the whole class, so a `verify` count here would depend on
        // whether the test above it has already run.
        assertThat(deletedAliases).isEmpty()
        assertThat(mockFido2Database.load(registeredCredId)).isNull()
    }
}
