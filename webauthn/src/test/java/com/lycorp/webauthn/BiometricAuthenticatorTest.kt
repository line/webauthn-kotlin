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

package com.lycorp.webauthn

import android.content.Context
import android.content.pm.PackageManager
import androidx.fragment.app.FragmentActivity
import com.lycorp.webauthn.authenticator.BiometricAuthenticator
import com.lycorp.webauthn.authenticator.Fido2ObjectFactory
import com.lycorp.webauthn.exceptions.WebAuthnException
import com.lycorp.webauthn.handler.BiometricAuthenticationHandler
import com.lycorp.webauthn.model.AssertionObject
import com.lycorp.webauthn.model.AttestationObject
import com.lycorp.webauthn.model.AuthenticatorExtensionsInput
import com.lycorp.webauthn.model.COSEAlgorithmIdentifier
import com.lycorp.webauthn.model.Fido2PromptInfo
import com.lycorp.webauthn.model.Fido2UserAuthResult
import com.lycorp.webauthn.model.PublicKeyCredentialDescriptor
import com.lycorp.webauthn.model.PublicKeyCredentialParams
import com.lycorp.webauthn.model.PublicKeyCredentialRpEntity
import com.lycorp.webauthn.model.PublicKeyCredentialType
import com.lycorp.webauthn.model.PublicKeyCredentialUserEntity
import com.lycorp.webauthn.util.DataFactory
import com.lycorp.webauthn.util.MockCredentialSourceStorage
import com.lycorp.webauthn.util.SecureExecutionHelper
import io.kotest.assertions.fail
import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.core.spec.style.BehaviorSpec
import io.kotest.core.spec.style.scopes.BehaviorSpecGivenContainerScope
import io.kotest.core.test.isRootTest
import io.kotest.matchers.should
import io.kotest.matchers.types.beInstanceOf
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.unmockkObject
import java.security.Signature
import java.security.cert.X509Certificate
import kotlin.reflect.KClass

class BiometricAuthenticatorTest : BehaviorSpec({
    val mockActivity: FragmentActivity = mockk()
    val mockContext: Context = mockk()
    val mockPackageManager: PackageManager = mockk()
    val mockFido2Database = MockCredentialSourceStorage()
    val mockAuthenticationHandler: BiometricAuthenticationHandler = mockk()
    val mockFido2PromptInfo: Fido2PromptInfo = mockk()
    val mockAuthObjectFactory: Fido2ObjectFactory = mockk()
    val biometricAuthenticator =
        BiometricAuthenticator(
            activity = mockActivity,
            db = mockFido2Database,
            fido2ObjectFactory = mockAuthObjectFactory,
            fido2PromptInfo = mockFido2PromptInfo,
            authenticationHandler = mockAuthenticationHandler,
        )
    val mockAttestationObject: AttestationObject = mockk()
    val mockAssertionObject: AssertionObject = mockk()
    val mockSignature: Signature = mockk()
    val mockCertificate: X509Certificate = mockk()

    suspend fun <T : Throwable> shouldThrowException(exceptionType: KClass<T>, block: suspend () -> Unit) {
        try {
            block()
        } catch (e: Throwable) {
            e should beInstanceOf(exceptionType)
            return
        }
        fail("Expected exception of type: ${exceptionType.qualifiedName} but successfully completed without exception.")
    }

    suspend fun <T : Throwable> BehaviorSpecGivenContainerScope.makeCredentialShouldThrowException(
        exceptionType: KClass<T>,
        clientDataHash: ByteArray = DataFactory.DUMMY_BYTEARRAY,
        rpEntity: PublicKeyCredentialRpEntity = DataFactory.newRpEntity,
        userEntity: PublicKeyCredentialUserEntity = DataFactory.newUserEntity,
        credTypesAndPubKeyAlgs: List<PublicKeyCredentialParams> = listOf(DataFactory.ES256_CRED_PARAMS),
        excludeCredDescriptorList: List<PublicKeyCredentialDescriptor>? = listOf(DataFactory.registeredCredDescriptor),
        extensions: AuthenticatorExtensionsInput? = null,
    ) {
        `when`("makeCredential is called") {
            then("throw ${exceptionType.simpleName}") {
                shouldThrowException(exceptionType) {
                    biometricAuthenticator.makeCredential(
                        clientDataHash,
                        rpEntity,
                        userEntity,
                        credTypesAndPubKeyAlgs,
                        excludeCredDescriptorList,
                        extensions
                    ).getOrThrow()
                }
            }
        }
    }

    suspend fun <T : Throwable> BehaviorSpecGivenContainerScope.getAssertionShouldThrowException(
        exceptionType: KClass<T>,
        rpId: String = DataFactory.registeredRpId,
        hash: ByteArray = DataFactory.DUMMY_BYTEARRAY,
        allowCredDescriptorList: List<PublicKeyCredentialDescriptor>? = null,
        extensions: AuthenticatorExtensionsInput? = null,
    ) {
        `when`("getAssertion is called") {
            then("throw ${exceptionType.simpleName}") {
                shouldThrowException(exceptionType) {
                    biometricAuthenticator.getAssertion(rpId, hash, allowCredDescriptorList, extensions).getOrThrow()
                }
            }
        }
    }

    beforeTest {
        if (it.isRootTest()) {
            mockkObject(SecureExecutionHelper)
            coEvery { mockAuthenticationHandler.isSupported() } returns true
            coEvery { mockAuthenticationHandler.authenticate(any(), any()) } returns Fido2UserAuthResult(mockSignature)
            coEvery {
                mockAuthObjectFactory.createAttestationObject(any(), any(), any(), any(), any(), any(), any())
            } returns mockAttestationObject
            coEvery {
                mockAuthObjectFactory.createAssertionObject(any(), any(), any(), any(), any())
            } returns mockAssertionObject
            coEvery { mockAttestationObject.toCBOR() } returns ByteArray(100)
            coEvery { mockAssertionObject.authenticatorData } returns ByteArray(100)
            coEvery { mockAssertionObject.signature } returns ByteArray(100)
            every { SecureExecutionHelper.generateKey(any(), any(), any(), any()) } returns DataFactory.keyPair
            every { SecureExecutionHelper.generateKey(any(), any(), any(), any(), any()) } returns DataFactory.keyPair
            every {
                SecureExecutionHelper.generateKey(any(), any(), any(), any(), any(), any())
            } returns DataFactory.keyPair
            every {
                SecureExecutionHelper.generateKey(any(), any(), any(), any(), any(), any(), any())
            } returns DataFactory.keyPair
            every { SecureExecutionHelper.getKey(any()) } returns DataFactory.keyPair.private
            every { SecureExecutionHelper.deleteKey(any()) } returns Unit
            every { SecureExecutionHelper.getX509Certificate(any()) } returns mockCertificate
            every { mockCertificate.sigAlgName } returns "SHA256withECDSA"
            every { SecureExecutionHelper.containAlias(any()) } returns false
            every { mockActivity.applicationContext } returns mockContext
            every { mockContext.packageManager } returns mockPackageManager
            every { mockPackageManager.hasSystemFeature(any()) } returns false

            // By default, assume that the 'registeredCredSource' is always pre-registered in all tests.
            mockFido2Database.store(DataFactory.registeredCredSource)
        }
    }

    afterTest {
        if (it.a.isRootTest()) {
            unmockkObject(SecureExecutionHelper)
            mockFido2Database.removeAllData()
        }
    }

    given("Valid parameters & behaviors") {
        `when`("makeCredential is called") {
            then("function works normally without exception occurrence") {
                shouldNotThrowAny {
                    biometricAuthenticator.makeCredential(
                        // Default parameters
                        DataFactory.DUMMY_BYTEARRAY,
                        DataFactory.newRpEntity,
                        DataFactory.newUserEntity,
                        listOf(DataFactory.ES256_CRED_PARAMS),
                        listOf(DataFactory.registeredCredDescriptor),
                        null
                    )
                }
            }
        }
        `when`("getAssertion is called") {
            then("function works normally without exception occurrence") {
                shouldNotThrowAny {
                    biometricAuthenticator.getAssertion(
                        // Default parameters
                        DataFactory.registeredRpId,
                        DataFactory.DUMMY_BYTEARRAY,
                        null,
                        null
                    )
                }
            }
        }
    }

    given("CredTypesAndPubKeyAlgs does not including ES256") {
        val credTypesAndPubKeyAlgsWithUncompatibleAlg =
            mutableListOf(PublicKeyCredentialParams(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES512))

        makeCredentialShouldThrowException(
            WebAuthnException.CoreException.NotSupportedException::class,
            credTypesAndPubKeyAlgs = credTypesAndPubKeyAlgsWithUncompatibleAlg
        )
    }

    given("A credential corresponding to a particular rpId is already registered") {
        makeCredentialShouldThrowException(
            WebAuthnException.CoreException.InvalidStateException::class,
            rpEntity = PublicKeyCredentialRpEntity(
                DataFactory.registeredRpId,
                DataFactory.RP_NAME
            ),
            excludeCredDescriptorList = listOf(DataFactory.registeredCredDescriptor)
        )
    }

    given("A credential corresponding to a particular rpId was not registered") {
        getAssertionShouldThrowException(
            WebAuthnException.CoreException.NotAllowedException::class,
            rpId = DataFactory.newRpId,
        )
    }

    given("Biometric authentication is not supported") {
        coEvery { mockAuthenticationHandler.isSupported() } returns false

        makeCredentialShouldThrowException(WebAuthnException.CoreException.ConstraintException::class)
        getAssertionShouldThrowException(WebAuthnException.CoreException.ConstraintException::class)
    }

    given("Biometric authentication is failed") {
        coEvery {
            mockAuthenticationHandler.authenticate(any(), any())
        } throws BiometricAuthenticationHandler.AuthenticationFailedException()

        makeCredentialShouldThrowException(WebAuthnException.CoreException.NotAllowedException::class)
        getAssertionShouldThrowException(WebAuthnException.CoreException.NotAllowedException::class)
    }

    given("Biometric authentication throws error") {
        coEvery {
            mockAuthenticationHandler.authenticate(any(), any())
        } throws BiometricAuthenticationHandler.AuthenticationErrorException()

        makeCredentialShouldThrowException(WebAuthnException.CoreException.NotAllowedException::class)
        getAssertionShouldThrowException(WebAuthnException.CoreException.NotAllowedException::class)
    }
})
