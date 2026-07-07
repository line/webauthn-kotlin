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
import androidx.lifecycle.Lifecycle
import com.linecorp.webauthn.model.Fido2PromptInfo
import com.linecorp.webauthn.model.Fido2UserAuthResult
import java.security.Signature
import kotlin.coroutines.resumeWithException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext

internal class BiometricAuthenticationHandler(
    private val authHandlerDispatcher: CoroutineDispatcher = Dispatchers.Main,
) : AuthenticationHandler {
    /**
     * Returns the raw BiometricManager.canAuthenticate() status code for the
     * BIOMETRIC_STRONG authenticator class required by this handler.
     */
    internal fun capabilityStatus(context: Context): Int = BiometricManager.from(context).canAuthenticate(
        BiometricManager.Authenticators.BIOMETRIC_STRONG
    )

    override fun isSupported(context: Context): Boolean =
        capabilityStatus(context) == BiometricManager.BIOMETRIC_SUCCESS

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
        if (!activity.lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED)) {
            throw AuthenticationHandler.AuthenticationErrorException(
                message = "BiometricPrompt requires Activity to be in RESUMED state. " +
                    "Current state: ${activity.lifecycle.currentState}"
            )
        }

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
                    // Without this, the prompt defaults to allowing Class 2 (WEAK)
                    // biometrics on the no-CryptoObject path, even though this handler
                    // gates support on BIOMETRIC_STRONG and the assertion claims UV.
                    .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                    .build()

            val biometricPrompt =
                BiometricPrompt(
                    activity,
                    ContextCompat.getMainExecutor(activity),
                    object : BiometricPrompt.AuthenticationCallback() {
                        override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                            if (continuation.isActive) {
                                val signature = result.cryptoObject?.signature
                                if (signatureProvider != null && signature == null) {
                                    // A CryptoObject was requested but none came back:
                                    // fail loudly here instead of crashing later on a
                                    // null signature during assertion generation.
                                    continuation.resumeWithException(
                                        AuthenticationHandler.AuthenticationErrorException(
                                            message = "Authentication succeeded but no signature " +
                                                "was returned from the CryptoObject."
                                        )
                                    )
                                } else {
                                    continuation.resumeWith(
                                        Result.success(Fido2UserAuthResult(signature = signature))
                                    )
                                }
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
                // invokeOnCancellation may be invoked from any thread, while
                // cancelAuthentication() performs fragment operations that must run on
                // the main thread. Post it to the main executor to avoid a crash when
                // the calling scope is cancelled from a background thread.
                ContextCompat.getMainExecutor(activity).execute {
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
}
