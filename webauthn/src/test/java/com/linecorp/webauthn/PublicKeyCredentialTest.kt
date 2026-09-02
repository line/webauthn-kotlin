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
import android.util.Log
import androidx.fragment.app.FragmentActivity
import com.google.common.truth.Truth.assertThat
import com.linecorp.webauthn.authenticator.Authenticator
import com.linecorp.webauthn.authenticator.AuthenticatorProvider
import com.linecorp.webauthn.exceptions.WebAuthnException
import com.linecorp.webauthn.model.AttestationConveyancePreference
import com.linecorp.webauthn.model.AttestationStatementFormat
import com.linecorp.webauthn.model.AuthenticationAvailability
import com.linecorp.webauthn.model.AuthenticationMethod
import com.linecorp.webauthn.model.AuthenticatorGetAssertionResult
import com.linecorp.webauthn.model.AuthenticatorMakeCredentialResult
import com.linecorp.webauthn.model.AuthenticatorSelectionCriteria
import com.linecorp.webauthn.model.AuthenticatorType
import com.linecorp.webauthn.model.COSEAlgorithmIdentifier
import com.linecorp.webauthn.model.ClientExtensionInput
import com.linecorp.webauthn.model.CredentialProtection
import com.linecorp.webauthn.model.PublicKeyCredentialDescriptor
import com.linecorp.webauthn.model.PublicKeyCredentialParams
import com.linecorp.webauthn.model.PublicKeyCredentialRpEntity
import com.linecorp.webauthn.model.PublicKeyCredentialSource
import com.linecorp.webauthn.model.PublicKeyCredentialType
import com.linecorp.webauthn.model.PublicKeyCredentialUserEntity
import com.linecorp.webauthn.model.UserVerificationRequirement
import com.linecorp.webauthn.publickeycredential.PublicKeyCredential
import com.linecorp.webauthn.rp.AuthenticationData
import com.linecorp.webauthn.rp.AuthenticationOptions
import com.linecorp.webauthn.rp.RegistrationData
import com.linecorp.webauthn.rp.RegistrationOptions
import com.linecorp.webauthn.rp.RelyingParty
import com.linecorp.webauthn.util.Fido2Util
import com.linecorp.webauthn.util.MockCredentialSourceStorage
import com.linecorp.webauthn.util.SecureExecutionHelper
import com.linecorp.webauthn.util.toBase64url
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.unmockkObject
import java.security.KeyPairGenerator
import java.util.UUID
import kotlin.reflect.KClass
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withTimeout
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class PublicKeyCredentialTest {

    private val mockActivity = mockk<FragmentActivity>()
    private val mockContext = mockk<Context>()
    private val mockAuthenticatorProvider = mockk<AuthenticatorProvider>()
    private val mockRelyingParty = mockk<RelyingParty>()
    private val mockAuthenticator = mockk<Authenticator>()
    private val mockDb = MockCredentialSourceStorage()

    private lateinit var publicKeyCredential: PublicKeyCredential

    private val dummyByteArray = ByteArray(32) { 0 }
    private val dummyRpEntity = PublicKeyCredentialRpEntity("example.com", "Example Relying Party")
    private val dummyUserEntity = PublicKeyCredentialUserEntity("user123", "User Name", "Display Name")
    private val es256CredParams = PublicKeyCredentialParams(
        PublicKeyCredentialType.PUBLIC_KEY,
        COSEAlgorithmIdentifier.ES256
    )
    private val registeredCredId = Fido2Util.generateRandomByteArray(32).toBase64url()
    private val registeredRpEntity = PublicKeyCredentialRpEntity("registered.com", "Example Registered Relying Party")
    private val registeredUserEntity = PublicKeyCredentialUserEntity("reg_user", "Reg User", "Reg User")
    private val registeredCredSource = com.linecorp.webauthn.model.PublicKeyCredentialSource(
        id = registeredCredId,
        rpId = registeredRpEntity.id,
        userHandle = registeredUserEntity.id,
        aaguid = AuthenticatorType.BiometricAndroidKey.aaguid,
    )
    private val registeredCredDescriptor = PublicKeyCredentialDescriptor(
        type = PublicKeyCredentialType.PUBLIC_KEY.value,
        id = registeredCredSource.id,
        transports = null,
    )

    private val dummyRegistrationData: RegistrationData = RegistrationData(
        attestation = AttestationConveyancePreference.DIRECT,
        authenticatorSelection = AuthenticatorSelectionCriteria(null, UserVerificationRequirement.REQUIRED.value),
        challenge = Fido2Util.generateRandomByteArray(32).toBase64url(),
        excludeCredentials = emptyList(),
        extensions = ClientExtensionInput(),
        pubKeyCredParams = listOf(es256CredParams),
        rp = dummyRpEntity,
        user = dummyUserEntity,
    )
    private val dummyAuthenticationData: AuthenticationData = AuthenticationData(
        allowCredentials = listOf(registeredCredDescriptor),
        challenge = Fido2Util.generateRandomByteArray(32).toBase64url(),
        extensions = ClientExtensionInput(),
        rpId = dummyRpEntity.id,
        userVerification = UserVerificationRequirement.REQUIRED,
    )
    private val dummyRegistrationOptions: RegistrationOptions = RegistrationOptions(
        AttestationConveyancePreference.DIRECT,
        AuthenticatorSelectionCriteria(null, UserVerificationRequirement.PREFERRED.value),
        CredentialProtection(),
        dummyUserEntity.displayName,
        dummyUserEntity.name
    )
    private val dummyAuthenticationOptions: AuthenticationOptions = AuthenticationOptions(
        UserVerificationRequirement.PREFERRED,
        dummyUserEntity.name
    )

    private val keyPair = KeyPairGenerator.getInstance("EC").apply { initialize(256) }.generateKeyPair()

    @BeforeEach
    fun setUp() {
        publicKeyCredential = PublicKeyCredential(
            rpClient = mockRelyingParty,
            db = mockDb,
            authenticationMethod = AuthenticationMethod.Biometric,
            attestationStatement = AttestationStatementFormat.ANDROID_KEY,
            authenticatorProvider = mockAuthenticatorProvider,
        )

        // Mock static Log class
        mockkStatic(Log::class)
        every { Log.v(any(), any()) } returns 0
        every { Log.d(any(), any()) } returns 0
        every { Log.i(any(), any()) } returns 0
        every { Log.e(any(), any()) } returns 0

        // Mock Activity and Context
        coEvery { mockActivity.applicationContext } returns mockContext

        // Mock Biometric Authenticator actions
        coEvery {
            mockAuthenticator.makeCredential(any(), any(), any(), any(), any(), any(), any())
        } returns Result.success(AuthenticatorMakeCredentialResult(dummyByteArray, dummyByteArray))
        coEvery {
            mockAuthenticator.getAssertion(any(), any(), any(), any(), any())
        } returns Result.success(
            AuthenticatorGetAssertionResult(dummyByteArray, dummyByteArray, dummyByteArray, dummyByteArray)
        )

        // Mock AuthenticatorProvider
        coEvery { mockAuthenticatorProvider.getAuthenticator(any(), any()) } returns mockAuthenticator

        // Mock RelyingParty actions
        coEvery { mockRelyingParty.getRegistrationData(any()) } returns dummyRegistrationData
        coEvery { mockRelyingParty.verifyRegistration(any()) } returns Unit
        coEvery { mockRelyingParty.getAuthenticationData(any()) } returns dummyAuthenticationData
        coEvery { mockRelyingParty.verifyAuthentication(any()) } returns Unit

        // Mock Fido2Util object
        mockkObject(Fido2Util)
        coEvery { Fido2Util.getPackageFacetID(any()) } returns "TEST_FACET_ID"
    }

    @AfterEach
    fun tearDown() {
        mockDb.removeAllData()
        // Object mocks are JVM-wide and the whole module's tests share one JVM. A stubbed
        // SecureExecutionHelper leaking out of this class would reach AuthenticatorTest, whose
        // generateUniqueCredId loops until containAlias is false - that hangs the suite instead of
        // failing it. Unmocking here rather than at the end of each test also survives an assertion
        // failure part-way through one.
        unmockkObject(SecureExecutionHelper)
    }

    @Test
    fun `should throw TypeException when options user id length is invalid`() = runBlocking {
        listOf(
            generateString("a", 0),
            generateString("a", 65),
        ).forEach { invalidUserId ->
            coEvery {
                mockRelyingParty.getRegistrationData(any())
            } returns dummyRegistrationData.copy(user = dummyUserEntity.copy(id = invalidUserId))

            val result = publicKeyCredential.create(mockActivity, dummyRegistrationOptions, null)
            assertThat(result.isFailure).isTrue()
            assertThat(result.exceptionOrNull()).isInstanceOf(WebAuthnException.CoreException.TypeException::class.java)
        }
    }

    @Test
    fun `should work well when register and authenticate with valid parameters`() = runBlocking {
        coEvery { mockAuthenticatorProvider.getAuthenticator(any(), any()) } returns mockAuthenticator

        val regResult = publicKeyCredential.create(mockActivity, dummyRegistrationOptions, null)
        assertThat(regResult.isSuccess).isTrue()

        val authResult = publicKeyCredential.get(mockActivity, dummyAuthenticationOptions, null)
        assertThat(authResult.isSuccess).isTrue()
    }

    @Test
    fun `should allow concurrent execution of register with different rpEntity`(): Unit = runBlocking {
        val times = 10
        val registeredRpId = mutableListOf<String>()
        coEvery {
            mockAuthenticator.makeCredential(any(), any(), any(), any(), any(), any(), any())
        } coAnswers {
            val rpEntity: PublicKeyCredentialRpEntity = secondArg()
            if (rpEntity.id !in registeredRpId) {
                registeredRpId.add(rpEntity.id)
                Result.success(AuthenticatorMakeCredentialResult(dummyByteArray, dummyByteArray))
            } else {
                Result.failure(WebAuthnException.CoreException.InvalidStateException())
            }
        }

        performConcurrentExecution(times) {
            val newRpEntity = PublicKeyCredentialRpEntity("https://test-rp.com/$it", "test_rp")
            coEvery { mockRelyingParty.getRegistrationData(any()) } returns RegistrationData(
                attestation = AttestationConveyancePreference.DIRECT,
                authenticatorSelection = AuthenticatorSelectionCriteria(
                    null,
                    UserVerificationRequirement.REQUIRED.value
                ),
                challenge = Fido2Util.generateRandomByteArray(32).toBase64url(),
                excludeCredentials = emptyList(),
                extensions = ClientExtensionInput(),
                pubKeyCredParams = listOf(es256CredParams),
                rp = newRpEntity,
                user = dummyUserEntity,
            )
            publicKeyCredential.create(mockActivity, dummyRegistrationOptions, null)
        }
    }

    @Test
    fun `should propagate exception when Authenticator throws exception`() = runBlocking {
        listOf(
            WebAuthnException.CoreException.InvalidStateException::class,
            WebAuthnException.CoreException.NotAllowedException::class,
        ).forEach { exceptionType ->
            coEvery {
                mockAuthenticator.makeCredential(any(), any(), any(), any(), any(), any(), any())
            } returns Result.failure(getExceptionBasedOnType(exceptionType))

            val regResult = publicKeyCredential.create(mockActivity, dummyRegistrationOptions, null)
            assertThat(regResult.isFailure).isTrue()
            assertThat(regResult.exceptionOrNull()).isInstanceOf(exceptionType.java)

            coEvery {
                mockAuthenticator.getAssertion(any(), any(), any(), any(), any())
            } returns Result.failure(getExceptionBasedOnType(exceptionType))

            val authResult = publicKeyCredential.get(mockActivity, dummyAuthenticationOptions, null)
            assertThat(authResult.isFailure).isTrue()
            assertThat(authResult.exceptionOrNull()).isInstanceOf(exceptionType.java)
        }
    }

    @Test
    fun `checkAuthenticationAvailability answers UNKNOWN instead of propagating a platform failure`() {
        // SDK_INT reads 0 in a local unit test, so this takes the pre-API-30 device-credential path, which
        // casts the keyguard system service to a non-null KeyguardManager. A device that returns none must
        // not make a pre-flight API throw: its entire purpose is to spare the caller an exception.
        every { mockContext.getSystemService(any<String>()) } returns null

        val availability = PublicKeyCredential.checkAuthenticationAvailability(
            mockContext,
            AuthenticationMethod.DeviceCredential
        )

        assertThat(availability.isAvailable).isFalse()
        assertThat(availability.reason).isEqualTo(AuthenticationAvailability.Reason.UNKNOWN)
        assertThat(availability.status).isNull()
    }

    @Test
    fun `getAllAccounts returns each stored credential exactly once`(): Unit = runBlocking {
        every { mockAuthenticatorProvider.getAuthenticator(any(), any(), any()) } returns storageBackedAuthenticator()
        // Deliberately spread over several aaguids, one of them belonging to no AuthenticatorType at all:
        // loading must not be filtered by aaguid, or rows written by another authenticator type - or by a
        // future one - would silently disappear from account management.
        val ids = listOf("cred-1", "cred-2", "cred-3")
        storeCredential(ids[0], AuthenticatorType.BiometricNone.aaguid)
        storeCredential(ids[1], AuthenticatorType.DeviceCredentialAndroidKey.aaguid)
        storeCredential(ids[2], UUID.fromString("00000000-0000-0000-0000-0000000000ff"))

        val accounts = publicKeyCredential.getAllAccounts()

        assertThat(accounts.map { it.id }).containsExactlyElementsIn(ids)
    }

    @Test
    fun `deleteAllAccounts removes the key material as well as the row`(): Unit = runBlocking {
        mockkObject(SecureExecutionHelper)
        val deletedAliases = mutableListOf<String>()
        every { SecureExecutionHelper.deleteKey(capture(deletedAliases)) } returns Unit
        every { mockAuthenticatorProvider.getAuthenticator(any(), any(), any()) } returns storageBackedAuthenticator()
        storeCredential("cred-1", AuthenticatorType.BiometricNone.aaguid)
        storeCredential("cred-2", AuthenticatorType.DeviceCredentialAndroidKey.aaguid)

        publicKeyCredential.deleteAllAccounts()

        // Exactly once each: the alias is the credential id verbatim, and no credential is visited twice.
        assertThat(deletedAliases).containsExactly("cred-1", "cred-2")
        assertThat(publicKeyCredential.getAllAccounts()).isEmpty()
    }

    @Test
    fun `deleteAllAccounts attempts every credential when one key deletion fails`(): Unit = runBlocking {
        mockkObject(SecureExecutionHelper)
        val attemptedAliases = mutableListOf<String>()
        every { SecureExecutionHelper.deleteKey(capture(attemptedAliases)) } answers {
            if (firstArg<String>() == "broken") {
                throw WebAuthnException.SecureExecutionException("Cannot delete key from KeyStore.")
            }
        }
        every { mockAuthenticatorProvider.getAuthenticator(any(), any(), any()) } returns storageBackedAuthenticator()
        listOf("first", "broken", "last").forEach { storeCredential(it) }

        val failure = runCatching { publicKeyCredential.deleteAllAccounts() }.exceptionOrNull()

        // One unusable credential must not strand the rest of the batch, and the failure must still surface.
        assertThat(attemptedAliases).containsExactly("first", "broken", "last")
        assertThat(failure).isInstanceOf(WebAuthnException.SecureExecutionException::class.java)
        // The row of the credential whose key survived is kept: it is the only record of the KeyStore
        // alias, so dropping it would orphan that key for the lifetime of the app's keystore.
        assertThat(publicKeyCredential.getAllAccounts().map { it.id }).containsExactly("broken")
    }

    @Test
    fun `deleteAccount removes one credential and its key`(): Unit = runBlocking {
        mockkObject(SecureExecutionHelper)
        val deletedAliases = mutableListOf<String>()
        every { SecureExecutionHelper.deleteKey(capture(deletedAliases)) } returns Unit
        every { mockAuthenticatorProvider.getAuthenticator(any(), any(), any()) } returns storageBackedAuthenticator()
        listOf("keep", "drop").forEach { storeCredential(it) }

        publicKeyCredential.deleteAccount("drop")

        assertThat(deletedAliases).containsExactly("drop")
        assertThat(publicKeyCredential.getAllAccounts().map { it.id }).containsExactly("keep")
    }

    @Test
    fun `deleteAllAccounts attaches later failures to the first as suppressed`(): Unit = runBlocking {
        mockkObject(SecureExecutionHelper)
        val perAlias = mapOf(
            "broken-1" to WebAuthnException.SecureExecutionException("first key"),
            "broken-2" to WebAuthnException.SecureExecutionException("second key"),
        )
        every { SecureExecutionHelper.deleteKey(any()) } answers {
            val alias = firstArg<String>()
            if (alias in perAlias) {
                throw perAlias.getValue(alias)
            }
        }
        every { mockAuthenticatorProvider.getAuthenticator(any(), any(), any()) } returns storageBackedAuthenticator()
        listOf("broken-1", "broken-2").forEach { storeCredential(it) }

        val thrown = runCatching { publicKeyCredential.deleteAllAccounts() }.exceptionOrNull()

        // No failure is dropped: the first is thrown as-is and the rest ride along on it, so a printed
        // stack trace shows the whole set rather than only whichever credential happened to be first.
        assertThat(thrown).isSameInstanceAs(perAlias.getValue("broken-1"))
        assertThat(thrown?.suppressed?.toList()).containsExactly(perAlias.getValue("broken-2"))
    }

    @Test
    fun `deleteAllAccounts survives the same failure instance for every credential`(): Unit = runBlocking {
        mockkObject(SecureExecutionHelper)
        // One instance for both credentials, which is what MockK's `throws` gives you and what a cached or
        // singleton exception gives you in production. Throwable.addSuppressed documents an
        // IllegalArgumentException for self-suppression, so aggregating unguarded would replace the
        // documented failure with an undocumented one.
        //
        // Measured caveat: this assertion is inert under :webauthn:testDebugUnitTest. In that JVM
        // `Throwable.addSuppressed(self)` neither throws nor records - the Android unit-test runtime
        // appends AGP's mockable android.jar to the bootstrap classpath - while the same call throws
        // IllegalArgumentException on plain OpenJDK 21 and Corretto 19, and per the documented contract on
        // a device. The test is kept because it does bite wherever the contract is enforced; do not read a
        // green run here as proof that the guard in deleteAllAccounts is unnecessary.
        val sharedFailure = WebAuthnException.SecureExecutionException("Cannot delete key from KeyStore.")
        every { SecureExecutionHelper.deleteKey(any()) } throws sharedFailure
        every { mockAuthenticatorProvider.getAuthenticator(any(), any(), any()) } returns storageBackedAuthenticator()
        listOf("broken-1", "broken-2").forEach { storeCredential(it) }

        val thrown = runCatching { publicKeyCredential.deleteAllAccounts() }.exceptionOrNull()

        assertThat(thrown).isSameInstanceAs(sharedFailure)
        assertThat(thrown?.suppressed?.toList()).isEmpty()
    }

    @Test
    fun `account management does not take the create mutex`(): Unit = runBlocking {
        // create() holds a non-reentrant Mutex across the consumer's RelyingParty callbacks, so an account
        // management API that took the same mutex would deadlock this call - and with it the process -
        // instead of failing. The timeout is what makes that a red suite rather than a hung one.
        every { mockAuthenticator.db } returns mockDb
        var nestedAccounts: List<PublicKeyCredentialSource>? = null
        coEvery { mockRelyingParty.verifyRegistration(any()) } coAnswers {
            publicKeyCredential.deleteAllAccounts()
            nestedAccounts = publicKeyCredential.getAllAccounts()
        }

        val result = withTimeout(MUTEX_REENTRANCY_TIMEOUT_MILLIS) {
            publicKeyCredential.create(mockActivity, dummyRegistrationOptions, null)
        }

        assertThat(result.isSuccess).isTrue()
        // Non-null proves the nested calls really ran inside the callback rather than being skipped.
        assertThat(nestedAccounts).isEmpty()
    }

    private fun storeCredential(credId: String, aaguid: UUID = AuthenticatorType.BiometricNone.aaguid) {
        mockDb.store(
            PublicKeyCredentialSource(
                id = credId,
                rpId = dummyRpEntity.id,
                userHandle = dummyUserEntity.id,
                aaguid = aaguid,
            )
        )
    }

    /**
     * A real [Authenticator] over [mockDb], rather than [mockAuthenticator].
     *
     * The account-management APIs delegate deletion to [Authenticator.cleanup], so a strict mock would
     * only prove that the delegation happened; the real instance proves the key is deleted under the
     * credential id verbatim and that the row goes with it.
     */
    private fun storageBackedAuthenticator(): Authenticator = Authenticator(
        db = mockDb,
        authenticationHandler = mockk(),
        fido2KeyGenerator = mockk(),
        fido2ObjectGenerator = mockk(),
        authType = AuthenticatorType.BiometricNone,
    )

    private fun generateString(pattern: String, length: Int): String =
        pattern.repeat((length + pattern.length - 1) / pattern.length).take(length)

    private fun performConcurrentExecution(times: Int, block: suspend (Int) -> Unit) = runTest {
        (1..times).map {
            async {
                block(it)
            }
        }.map { it.await() }
    }

    private fun getExceptionBasedOnType(exceptionClass: KClass<out Throwable>): Throwable = when (exceptionClass) {
        WebAuthnException.CoreException.NotAllowedException::class ->
            WebAuthnException.CoreException.NotAllowedException()
        WebAuthnException.CoreException.InvalidStateException::class ->
            WebAuthnException.CoreException.InvalidStateException()
        else -> Exception("Unknown exception type")
    }
    private companion object {
        /**
         * Long enough that a loaded CI machine cannot make the mutex re-entrancy test flaky, short enough
         * that a regression is reported in seconds. Only a deadlock can reach it: the work it bounds is a
         * handful of in-memory calls.
         */
        private const val MUTEX_REENTRANCY_TIMEOUT_MILLIS = 10_000L
    }
}
