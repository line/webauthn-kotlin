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
import androidx.fragment.app.FragmentActivity
import com.google.common.truth.Truth.assertThat
import com.linecorp.webauthn.authenticator.Authenticator
import com.linecorp.webauthn.authenticator.keygenerator.Fido2KeyGenerator
import com.linecorp.webauthn.authenticator.objectgenerator.Fido2ObjectGenerator
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
import io.mockk.unmockkObject
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.cert.X509Certificate
import kotlin.reflect.KClass
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeoutOrNull
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
    fun `cleanup runs when the job is cancelled while the key is being generated`(): Unit = runBlocking {
        // Regression guard: a key committed to the KeyStore during a cancelled keygen must
        // still be deleted. cryptoDispatcher must differ from the caller's context so
        // withContext's prompt-cancellation guarantee applies.
        val localAuthenticator = Authenticator(
            db = mockFido2Database,
            authenticationHandler = mockAuthenticationHandler,
            fido2KeyGenerator = mockKeyGenerator,
            fido2ObjectGenerator = mockObjectGenerator,
            authType = AuthenticatorType.BiometricAndroidKey,
            cryptoDispatcher = Dispatchers.Default,
        )

        val deletedAlias = CompletableDeferred<String>()
        every { SecureExecutionHelper.deleteKey(any()) } answers {
            deletedAlias.complete(firstArg())
            Unit
        }

        lateinit var job: Job
        // The key generator "creates" the key and then cancels the calling job, so that
        // withContext resumes the caller with CancellationException even though the key
        // was committed. With the flag set inside the block, cleanup must still run.
        every { mockKeyGenerator.generateFido2Key(any(), any(), any(), any()) } answers {
            job.cancel()
            dummyKeyPair
        }

        job = launch(Dispatchers.Default, start = CoroutineStart.LAZY) {
            try {
                localAuthenticator.makeCredential(
                    mockActivity,
                    dummyHash,
                    dummyRpEntity,
                    dummyUserEntity,
                    listOf(es256CredParams),
                    null,
                    null
                )
            } catch (_: Exception) {
                // CancellationException is expected; swallow so the test can assert cleanup.
            }
        }
        job.start()
        job.join()

        assertThat(withTimeoutOrNull(2000) { deletedAlias.await() }).isNotNull()

        // Restore the shared stub for subsequent tests.
        every { mockKeyGenerator.generateFido2Key(any(), any(), any(), any()) } returns dummyKeyPair
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
}
