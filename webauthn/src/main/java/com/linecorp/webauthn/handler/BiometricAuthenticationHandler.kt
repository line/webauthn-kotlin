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
import android.os.Build
import android.os.Looper
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import com.linecorp.webauthn.model.Fido2PromptInfo
import com.linecorp.webauthn.model.Fido2UserAuthResult
import java.security.Signature
import java.util.concurrent.Executor
import kotlin.coroutines.resumeWithException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext

internal class BiometricAuthenticationHandler(
    private val authHandlerDispatcher: CoroutineDispatcher = Dispatchers.Main,
    private val promptFactory: (FragmentActivity, Executor, BiometricPrompt.AuthenticationCallback) -> BiometricPrompt =
        ::BiometricPrompt,
) : AuthenticationHandler {
    /**
     * On API 28 and 29 a fingerprint enrolled with the platform also counts, because androidx.biometric
     * answers fingerprint availability there through a class the application's androidx.core can reduce
     * to a no-op. See [LegacyFingerprintFallback].
     */
    override fun isSupported(context: Context): Boolean {
        val biometricManager = BiometricManager.from(context)
        val strongBiometricAvailable = biometricManager.canAuthenticate(
            BiometricManager.Authenticators.BIOMETRIC_STRONG
        ) == BiometricManager.BIOMETRIC_SUCCESS
        return strongBiometricAvailable ||
            (Build.VERSION.SDK_INT < Build.VERSION_CODES.R && LegacyFingerprintFallback.isAvailable(context))
    }

    override suspend fun authenticate(
        activity: FragmentActivity,
        fido2PromptInfo: Fido2PromptInfo?,
        signatureProvider: (() -> Signature)?
    ): Fido2UserAuthResult = withContext(authHandlerDispatcher) {
        val signature = signatureProvider?.invoke()
        if (signature != null && LegacyFingerprintFallback.requiresFingerprintForCrypto(activity)) {
            Fido2UserAuthResult(
                signature = LegacyFingerprintFallback.authenticate(
                    activity,
                    buildPromptInfo(fido2PromptInfo),
                    signature
                )
            )
        } else {
            authenticateUserWithBiometricPrompt(activity, fido2PromptInfo, signature)
        }
    }

    private suspend fun authenticateUserWithBiometricPrompt(
        activity: FragmentActivity,
        fido2PromptInfo: Fido2PromptInfo?,
        signature: Signature?
    ): Fido2UserAuthResult = withContext(Dispatchers.Main) {
        suspendCancellableCoroutine { continuation ->
            val promptInfo = buildPromptInfo(fido2PromptInfo)
            val mainExecutor = ContextCompat.getMainExecutor(activity.applicationContext)

            val biometricPrompt =
                promptFactory(
                    activity,
                    mainExecutor,
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
                if (Looper.myLooper() == Looper.getMainLooper()) {
                    biometricPrompt.cancelAuthentication()
                } else {
                    mainExecutor.execute { biometricPrompt.cancelAuthentication() }
                }
            }

            if (!continuation.isActive) return@suspendCancellableCoroutine
            if (signature != null) {
                val cryptoObject = BiometricPrompt.CryptoObject(signature)
                biometricPrompt.authenticate(promptInfo, cryptoObject)
            } else {
                biometricPrompt.authenticate(promptInfo)
            }
        }
    }

    private fun buildPromptInfo(
        info: Fido2PromptInfo?,
        defaultDescription: String =
            "Input your Fingerprint or FaceID to ensure it's you!",
    ): BiometricPrompt.PromptInfo =
        BiometricPrompt.PromptInfo.Builder()
            .setTitle(info?.title ?: "Biometric Authentication")
            .setSubtitle(info?.subtitle ?: "Enter biometric credentials to proceed")
            .setDescription(info?.description ?: defaultDescription)
            .setNegativeButtonText(info?.negativeButtonText ?: "Cancel")
            .build()
}
