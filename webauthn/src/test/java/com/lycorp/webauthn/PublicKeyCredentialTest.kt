@file:OptIn(ExperimentalCoroutinesApi::class, ExperimentalKotest::class)

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
import androidx.fragment.app.FragmentActivity
import com.lycorp.webauthn.authenticator.AuthenticatorProvider
import com.lycorp.webauthn.authenticator.BiometricAuthenticator
import com.lycorp.webauthn.exceptions.WebAuthnException
import com.lycorp.webauthn.model.Fido2PromptInfo
import com.lycorp.webauthn.model.PublicKeyCredentialRpEntity
import com.lycorp.webauthn.model.PublicKeyCredentialUserEntity
import com.lycorp.webauthn.publickeycredential.Biometric
import com.lycorp.webauthn.rp.AuthenticationOptions
import com.lycorp.webauthn.rp.RegistrationOptions
import com.lycorp.webauthn.rp.RelyingParty
import com.lycorp.webauthn.util.DataFactory
import com.lycorp.webauthn.util.MockCredentialSourceStorage
import com.lycorp.webauthn.util.TestUtil
import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.common.ExperimentalKotest
import io.kotest.core.spec.style.BehaviorSpec
import io.kotest.core.test.isRootTest
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.types.shouldBeTypeOf
import io.mockk.coEvery
import io.mockk.mockk
import kotlinx.coroutines.ExperimentalCoroutinesApi

val mockActivity = mockk<FragmentActivity>()
val mockContext = mockk<Context>()
val mockAuthenticatorProvider = mockk<AuthenticatorProvider>()
val mockRelyingParty = mockk<RelyingParty>()
internal val mockBiometricAuthenticator = mockk<BiometricAuthenticator>()
val mockDb = MockCredentialSourceStorage()

typealias RegisterParams = Pair<RegistrationOptions, Fido2PromptInfo?>
typealias AuthenticateParams = Pair<AuthenticationOptions, Fido2PromptInfo?>

class PublicKeyCredentialTest : BehaviorSpec({

    val publicKeyCredential = Biometric(
        rpClient = mockRelyingParty,
        activity = mockActivity,
        db = mockDb,
        authenticatorProvider = mockAuthenticatorProvider,
    )
    val defaultRegParams = DataFactory.getRegParams()
    val defaultAuthParams = DataFactory.getAuthParams()

    beforeTest {
        if (it.isRootTest()) {
            TestUtil.mockLogClass()
            TestUtil.mockActivity(mockActivity, mockContext)
            TestUtil.mockDefaultBiometricAuthenticatorAction(mockBiometricAuthenticator)
            TestUtil.mockDefaultReyingPartyAction(mockRelyingParty)
            TestUtil.mockDefaultAuthenticatorProviderAction(mockAuthenticatorProvider)
            TestUtil.mockDefaultFido2UtilAction()
        }
    }

    // Testcases
    listOf(
        DataFactory.generateString("a", 0),
        DataFactory.generateString("a", 65),
    ).forEach { invalidUserId ->
        given("options.user.id with invalid length(${invalidUserId.length})") {
            coEvery {
                mockRelyingParty.getRegistrationData(any())
            } returns DataFactory.getRegistrationData(
                user = PublicKeyCredentialUserEntity(id = invalidUserId, name = "test", displayName = "test"),
            )

            val (options, fido2PromptInfo) = DataFactory.getRegParams()
            `when`("register is called") {
                then("throw TypeException") {
                    val result = publicKeyCredential.create(options, fido2PromptInfo)
                    result.isFailure shouldBe true
                    result.exceptionOrNull().shouldBeTypeOf<WebAuthnException.CoreException.TypeException>()
                }
            }
        }
    }

    given("AuthenticatorProvider returns BiometricAuthenticator") {
        coEvery { mockAuthenticatorProvider.getAuthenticator(any(), any()) } returns mockBiometricAuthenticator
        `when`("register is called with valid parameters") {
            val regParams = DataFactory.getRegParams()
            then("works well") {
                val result = publicKeyCredential.create(regParams.first, regParams.second)
                result.isSuccess shouldBe true
            }
        }
        `when`("authenticate is called with valid parameters") {
            val authParams = DataFactory.getAuthParams()
            then("works well") {
                val result = publicKeyCredential.get(authParams.first, authParams.second)
                result.isSuccess shouldBe true
            }
        }
    }

    given("default inputs") {
        val (regOptions, regFido2PromptInfo) = defaultRegParams
        val (authOptions, authFido2PromptInfo) = defaultAuthParams

        // Concurrency test
        val times = 10
        `when`("'register's are called $times times simultaneously with different rpEntity") {
            val registeredRpId = mutableListOf<String>()
            coEvery {
                mockBiometricAuthenticator.makeCredential(any(), any(), any(), any(), any(), any())
            } coAnswers {
                val rpEntity: PublicKeyCredentialRpEntity = secondArg()
                if (rpEntity.id !in registeredRpId) {
                    registeredRpId.add(rpEntity.id)
                    Result.success(DataFactory.getMakeCredentialResult())
                } else {
                    throw WebAuthnException.CoreException.InvalidStateException()
                }
            }
            then("works well $times times") {
                shouldNotThrowAny {
                    TestUtil.performConcurrentExecution(times) {
                        val (newRegOptions, newRegFido2PromptInfo) =
                            DataFactory.getRegParams()
                        coEvery { mockRelyingParty.getRegistrationData(any()) } returns DataFactory.getRegistrationData(
                            rp = PublicKeyCredentialRpEntity(
                                id = "https://test-rp.com/$it",
                                name = "test_rp",
                            ),
                        )
                        publicKeyCredential.create(newRegOptions, newRegFido2PromptInfo)
                    }
                }
            }
        }
        `when`(
            "'register's are called $times times simultaneously with multiple instances" +
                " under the assumption that makeCredentials succeed only the first time",
        ) {
            val registeredRpId = mutableListOf<String>()
            coEvery {
                mockBiometricAuthenticator.makeCredential(any(), any(), any(), any(), any(), any())
            } answers {
                val rpEntity: PublicKeyCredentialRpEntity = secondArg()
                if (rpEntity.id !in registeredRpId) {
                    registeredRpId.add(rpEntity.id)
                    Result.success(DataFactory.getMakeCredentialResult())
                } else {
                    throw WebAuthnException.CoreException.InvalidStateException()
                }
            }
            then("only the first register call should succeed and throw InvalidStateException for the rest") {
                var invalidStateExceptionCount = 0
                TestUtil.performConcurrentExecution(times) {
                    val newPublicKeyCredential =
                        Biometric(
                            rpClient = mockRelyingParty,
                            activity = mockActivity,
                            db = mockDb,
                            authenticatorProvider = mockAuthenticatorProvider,
                        )
                    val result = newPublicKeyCredential.create(regOptions, regFido2PromptInfo)
                    if (result.exceptionOrNull() is WebAuthnException.CoreException.InvalidStateException) {
                        invalidStateExceptionCount++
                    }
                }
                invalidStateExceptionCount shouldBe times - 1
            }
            // initialize conditions
            coEvery {
                mockBiometricAuthenticator.makeCredential(any(), any(), any(), any(), any(), any())
            } returns Result.success(DataFactory.getMakeCredentialResult())
        }

        `when`("'authenticate's are called $times times simultaneously") {
            then("works well $times times") {
                shouldNotThrowAny {
                    TestUtil.performConcurrentExecution(
                        times
                    ) { publicKeyCredential.get(authOptions, authFido2PromptInfo) }
                }
            }
        }

        // Authenticator action test
        listOf(
            WebAuthnException.CoreException.InvalidStateException::class,
            WebAuthnException.CoreException.NotAllowedException::class,
        ).forEach { exceptionType ->
            `when`("Authenticator.makeCredential throws ${exceptionType.simpleName}") {
                coEvery {
                    mockBiometricAuthenticator.makeCredential(any(), any(), any(), any(), any(), any())
                } throws TestUtil.getExceptionBasedOnType(exceptionType)
                then("register propagates the exception") {
                    val result = publicKeyCredential.create(regOptions, regFido2PromptInfo)
                    result.isFailure shouldBe true
                    val exception = result.exceptionOrNull()
                    exception shouldNotBe null
                    exception!!::class shouldBe exceptionType
                }
            }

            `when`("Authenticator.getAssertion throws ${exceptionType.simpleName}") {
                coEvery {
                    mockBiometricAuthenticator.getAssertion(any(), any(), any(), any())
                } throws TestUtil.getExceptionBasedOnType(exceptionType)
                then("authenticate propagates the exception") {
                    val result = publicKeyCredential.get(authOptions, authFido2PromptInfo)
                    result.isFailure shouldBe true
                    val exception = result.exceptionOrNull()
                    exception shouldNotBe null
                    exception!!::class shouldBe exceptionType
                }
            }
        }
    }
})
