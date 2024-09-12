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

package com.lycorp.webauthn.util

import android.content.Context
import android.util.Log
import androidx.fragment.app.FragmentActivity
import com.lycorp.webauthn.authenticator.AuthenticatorProvider
import com.lycorp.webauthn.authenticator.BiometricAuthenticator
import com.lycorp.webauthn.authenticator.DeviceCredentialAuthenticator
import com.lycorp.webauthn.exceptions.WebAuthnException
import com.lycorp.webauthn.mockBiometricAuthenticator
import com.lycorp.webauthn.rp.RelyingParty
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockkObject
import io.mockk.mockkStatic
import kotlin.reflect.KClass
import kotlinx.coroutines.async
import kotlinx.coroutines.test.runTest

class TestUtil {
    companion object {
        fun mockLogClass() {
            mockkStatic(Log::class)
            every { Log.v(any(), any()) } returns 0
            every { Log.d(any(), any()) } returns 0
            every { Log.i(any(), any()) } returns 0
            every { Log.e(any(), any()) } returns 0
        }

        suspend fun mockActivity(mockActivity: FragmentActivity, mockContext: Context) {
            coEvery {
                mockActivity.applicationContext
            } returns mockContext
        }

        internal suspend fun mockDefaultBiometricAuthenticatorAction(
            mockBiometricAuthenticator: BiometricAuthenticator
        ) {
            coEvery {
                mockBiometricAuthenticator.makeCredential(any(), any(), any(), any(), any(), any())
            } returns Result.success(DataFactory.getMakeCredentialResult())
            coEvery {
                mockBiometricAuthenticator.getAssertion(any(), any(), any(), any())
            } returns Result.success(DataFactory.getGetAssertionResult())
        }

        internal suspend fun mockDefaultDeviceCredentialAuthenticatorAction(
            mockDeviceCredentialAuthenticator: DeviceCredentialAuthenticator
        ) {
            coEvery {
                mockDeviceCredentialAuthenticator.makeCredential(any(), any(), any(), any(), any(), any())
            } returns Result.success(DataFactory.getMakeCredentialResult())
            coEvery {
                mockDeviceCredentialAuthenticator.getAssertion(any(), any(), any(), any())
            } returns Result.success(DataFactory.getGetAssertionResult())
        }

        suspend fun mockDefaultAuthenticatorProviderAction(mockAuthenticatorProvider: AuthenticatorProvider) {
            coEvery {
                mockAuthenticatorProvider.getAuthenticator(any(), any())
            } returns mockBiometricAuthenticator
        }

        suspend fun mockDefaultReyingPartyAction(mockRelyingParty: RelyingParty) {
            coEvery {
                mockRelyingParty.getRegistrationData(any())
            } returns DataFactory.getRegistrationData()
            coEvery {
                mockRelyingParty.verifyRegistration(any())
            } returns Unit
            coEvery {
                mockRelyingParty.getAuthenticationData(any())
            } returns DataFactory.getAuthenticationData()
            coEvery {
                mockRelyingParty.verifyAuthentication(any())
            } returns Unit
        }

        suspend fun mockDefaultFido2UtilAction() {
            mockkObject(Fido2Util)
            coEvery {
                Fido2Util.getPackageFacetID(any())
            } returns "TEST_FACET_ID"
        }

        fun getExceptionBasedOnType(exceptionClass: KClass<out Throwable>): Throwable {
            return when (exceptionClass) {
                WebAuthnException.CoreException.NotAllowedException::class ->
                    WebAuthnException.CoreException.NotAllowedException()
                WebAuthnException.CoreException.InvalidStateException::class ->
                    WebAuthnException.CoreException.InvalidStateException()
                else -> Exception("Unknown exception type")
            }
        }

        fun performConcurrentExecution(times: Int, block: suspend (Int) -> Unit) = runTest {
            (1..times).map {
                async {
                    block(it)
                }
            }.map { it.await() }
        }
    }
}
