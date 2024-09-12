@file:OptIn(ExperimentalCoroutinesApi::class)

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

import androidx.test.core.app.ActivityScenario
import com.lycorp.webauthn.authenticator.DeviceCredentialAuthenticator
import com.lycorp.webauthn.db.CredentialSourceStorage
import com.lycorp.webauthn.handler.DeviceCredentialAuthenticationHandler
import com.lycorp.webauthn.model.Fido2UserAuthResult
import com.lycorp.webauthn.util.DataFactory
import com.lycorp.webauthn.util.MockCredentialSourceStorage
import com.lycorp.webauthn.util.SecureExecutionHelper
import com.lycorp.webauthn.util.TestFragmentActivity
import com.lycorp.webauthn.util.base64urlToString
import io.mockk.coEvery
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.slot
import io.mockk.unmockkObject
import java.security.KeyStore
import java.security.Signature
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.runBlocking
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatCode
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test

class DeviceCredentialAuthenticatorTest {
    private lateinit var deviceCredentialAuthenticator: DeviceCredentialAuthenticator
    private var mockCredentialSourceStorage = MockCredentialSourceStorage()

    private val fido2Database: CredentialSourceStorage = mockCredentialSourceStorage
    private val mockAuthenticationHandler: DeviceCredentialAuthenticationHandler = mockk()
    private val keyStore: KeyStore = KeyStore.getInstance("AndroidKeyStore").also {
        it.load(null)
    }

    @BeforeEach
    fun beforeEachSetUp() {
        ActivityScenario.launch(TestFragmentActivity::class.java).use { scenario ->
            scenario.onActivity { activity: TestFragmentActivity ->
                deviceCredentialAuthenticator = DeviceCredentialAuthenticator(
                    activity, fido2Database, authenticationHandler = mockAuthenticationHandler
                )
            }
        }

        mockkObject(SecureExecutionHelper)
        coEvery {
            SecureExecutionHelper.generateKey(
                keyAlias = any(),
                challenge = any(),
                publicKeyAlgorithm = any(),
                useBiometricOnly = any(),
                userAuthenticationValidityDurationSeconds = any(),
                isStrongBoxBacked = any(),
            )
        } coAnswers {
            SecureExecutionHelper.generateKey(
                keyAlias = arg(0),
                challenge = arg(1),
                publicKeyAlgorithm = arg(2),
                useBiometricOnly = arg(3),
                userAuthenticationValidityDurationSeconds = arg(4),
                isStrongBoxBacked = arg(6),
                userAuthenticationRequired = false,
            )
        }

        coEvery { mockAuthenticationHandler.isSupported() } returns true
        val signatureSlot = slot<() -> Signature>()
        coEvery {
            mockAuthenticationHandler.authenticate(
                capture(signatureSlot),
                any(),
            )
        } coAnswers { Fido2UserAuthResult(signature = signatureSlot.captured()) }
    }

    @AfterEach
    fun afterEachTearDown() {
        unmockkObject(SecureExecutionHelper)
    }

    @Test
    @DisplayName(
        "Given valid parameters & behaviors, both makeCredential and getAssertion should not throw any exception"
    )
    fun checkGetAssertion() {
        assertThatCode {
            runBlocking {
                val aliasListBefore = keyStore.aliases().toList()
                deviceCredentialAuthenticator.makeCredential(
                    // Default parameters
                    hash = DataFactory.DUMMY_BYTEARRAY,
                    rpEntity = DataFactory.newRpEntity,
                    userEntity = DataFactory.newUserEntity,
                    credTypesAndPubKeyAlgs = listOf(DataFactory.ES256_CRED_PARAMS),
                    excludeCredDescriptorList = null,
                    extensions = null,
                )
                val aliasListAfter = keyStore.aliases().toList()

                assertThat(aliasListAfter.size).isEqualTo(aliasListBefore.size + 1)

                val newAlias = aliasListAfter.minus(aliasListBefore.toSet()).first()
                val newCredId = newAlias.base64urlToString()

                assertThat(
                    fido2Database.load(newCredId)
                ).isNotNull

                deviceCredentialAuthenticator.getAssertion(
                    // Default parameters
                    DataFactory.newRpId,
                    DataFactory.DUMMY_BYTEARRAY,
                    null,
                    null
                )

                // Erase a key and a credential for next tests
                keyStore.deleteEntry(newAlias)
                fido2Database.delete(newAlias)
            }
        }.doesNotThrowAnyException()
    }
}
