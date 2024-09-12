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

package com.lycorp.webauthn.handler

import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import com.lycorp.webauthn.model.Fido2PromptInfo
import com.lycorp.webauthn.model.Fido2UserAuthResult
import java.security.Signature
import kotlin.coroutines.resumeWithException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext

internal class BiometricAuthenticationHandler(
    private val activity: FragmentActivity,
    private val authHandlerDispatcher: CoroutineDispatcher = Dispatchers.Main,
) : AuthenticationHandler {
    class AuthenticationFailedException : Exception()

    class AuthenticationErrorException : Exception()

    override fun isSupported(): Boolean {
        val biometricManager = BiometricManager.from(activity.applicationContext)
        return biometricManager.canAuthenticate(
            BiometricManager.Authenticators.BIOMETRIC_STRONG
        ) == BiometricManager.BIOMETRIC_SUCCESS
    }

    override suspend fun authenticate(
        signatureProvider: () -> Signature,
        fido2PromptInfo: Fido2PromptInfo?
    ): Fido2UserAuthResult {
        return authenticateUserWithBiometricPrompt(signatureProvider, fido2PromptInfo)
    }

    private suspend fun authenticateUserWithBiometricPrompt(
        signatureProvider: () -> Signature,
        fido2PromptInfo: Fido2PromptInfo?
    ): Fido2UserAuthResult = withContext(authHandlerDispatcher) {
        suspendCancellableCoroutine { continuation ->
            val promptInfo =
                BiometricPrompt.PromptInfo.Builder()
                    .setTitle(fido2PromptInfo?.title ?: "Biometric Authentication")
                    .setSubtitle(fido2PromptInfo?.subtitle ?: "Enter biometric credentials to proceed")
                    .setDescription(
                        fido2PromptInfo?.description
                            ?: "Input your Fingerprint or FaceID to ensure it's you!",
                    )
                    .setNegativeButtonText(fido2PromptInfo?.negativeButtonText ?: "Cancel")
                    .build()

            val cryptoObject: BiometricPrompt.CryptoObject = BiometricPrompt.CryptoObject(signatureProvider())

            val biometricPrompt =
                BiometricPrompt(
                    activity,
                    ContextCompat.getMainExecutor(activity.applicationContext),
                    object : BiometricPrompt.AuthenticationCallback() {
                        override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                            if (continuation.isActive) {
                                continuation.resumeWith(
                                    Result.success(
                                        Fido2UserAuthResult(
                                            signature = result.cryptoObject?.signature
                                        )
                                    )
                                )
                            }
                        }

                        override fun onAuthenticationFailed() {
                            // In the event of an authentication failure, the user is allowed to try again.
                        }

                        override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                            if (continuation.isActive) {
                                continuation.resumeWithException(AuthenticationErrorException())
                            }
                        }
                    },
                )

            continuation.invokeOnCancellation {
                biometricPrompt.cancelAuthentication()
            }

            biometricPrompt.authenticate(promptInfo, cryptoObject)
        }
    }
}
