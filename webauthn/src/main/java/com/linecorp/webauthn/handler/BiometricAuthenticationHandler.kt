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

package com.linecorp.webauthn.handler

import android.content.Context
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import com.linecorp.webauthn.model.Fido2PromptInfo
import com.linecorp.webauthn.model.Fido2UserAuthResult
import java.security.Signature
import kotlin.coroutines.resumeWithException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext

internal const val HOST_STATE_SAVED_MESSAGE =
    "Cannot show the authentication prompt: the host activity has saved its state."

internal class BiometricAuthenticationHandler(
    private val authHandlerDispatcher: CoroutineDispatcher = Dispatchers.Main,
) : AuthenticationHandler,
    AuthenticationCapability {

    override fun canAuthenticateStatus(context: Context): Int =
        BiometricManager.from(context).canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)

    override fun isSupported(context: Context): Boolean =
        canAuthenticateStatus(context) == BiometricManager.BIOMETRIC_SUCCESS

    override suspend fun authenticate(
        activity: FragmentActivity,
        fido2PromptInfo: Fido2PromptInfo?,
        signatureProvider: (() -> Signature)?
    ): Fido2UserAuthResult = authenticateUserWithBiometricPrompt(activity, fido2PromptInfo, signatureProvider)

    private suspend fun authenticateUserWithBiometricPrompt(
        activity: FragmentActivity,
        fido2PromptInfo: Fido2PromptInfo?,
        signatureProvider: (() -> Signature)?
    ): Fido2UserAuthResult = withContext(authHandlerDispatcher) {
        suspendCancellableCoroutine { continuation ->
            // androidx.biometric returns from authenticate() without invoking any callback when the host
            // FragmentManager has saved state (BiometricPrompt.authenticateInternal). That would leave
            // this continuation unresumed forever, and the caller holds a process-wide lock. Fail fast.
            if (activity.supportFragmentManager.isStateSaved) {
                continuation.resumeWithException(
                    AuthenticationHandler.AuthenticationErrorException(
                        errorCode = AuthenticationHandler.ERROR_HOST_STATE_SAVED,
                        message = HOST_STATE_SAVED_MESSAGE
                    )
                )
                return@suspendCancellableCoroutine
            }

            val promptInfo = buildPromptInfo(fido2PromptInfo)

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
                                continuation.resumeWithException(
                                    AuthenticationHandler.AuthenticationErrorException(
                                        errorCode = errorCode,
                                        message = "Biometric authentication error: $errString"
                                    )
                                )
                            }
                        }
                    },
                )

            continuation.invokeOnCancellation {
                ContextCompat.getMainExecutor(activity.applicationContext).execute {
                    biometricPrompt.cancelAuthentication()
                }
            }

            if (signatureProvider != null) {
                val cryptoObject = BiometricPrompt.CryptoObject(signatureProvider())
                biometricPrompt.authenticate(promptInfo, cryptoObject)
            } else {
                biometricPrompt.authenticate(promptInfo)
            }
        }
    }

    internal fun buildPromptInfo(fido2PromptInfo: Fido2PromptInfo?): BiometricPrompt.PromptInfo =
        BiometricPrompt.PromptInfo.Builder()
            .setTitle(fido2PromptInfo?.title ?: "Biometric Authentication")
            .setSubtitle(fido2PromptInfo?.subtitle ?: "Enter biometric credentials to proceed")
            .setDescription(
                fido2PromptInfo?.description ?: "Input your Fingerprint or FaceID to ensure it's you!",
            )
            .setNegativeButtonText(fido2PromptInfo?.negativeButtonText ?: "Cancel")
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            .build()
}
