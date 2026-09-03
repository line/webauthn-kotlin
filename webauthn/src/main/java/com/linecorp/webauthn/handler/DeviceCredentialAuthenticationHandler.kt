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

internal class DeviceCredentialAuthenticationHandler(
    private val authHandlerDispatcher: CoroutineDispatcher = Dispatchers.Main,
) : AuthenticationHandler {

    private val keyguardManagerWrapper = KeyguardManagerWrapper()

    override fun isSupported(context: Context): Boolean = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
        // API level >= 30
        val biometricManager = BiometricManager.from(context)
        biometricManager.canAuthenticate(
            BiometricManager.Authenticators.BIOMETRIC_STRONG or
                BiometricManager.Authenticators.DEVICE_CREDENTIAL
        ) == BiometricManager.BIOMETRIC_SUCCESS
    } else {
        // API level < 30
        keyguardManagerWrapper.isSupported(context)
    }

    override suspend fun authenticate(
        activity: FragmentActivity,
        fido2PromptInfo: Fido2PromptInfo?,
        signatureProvider: (() -> Signature)?
    ): Fido2UserAuthResult = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
        authenticateUserWithBiometricPrompt(activity, fido2PromptInfo, signatureProvider)
    } else {
        authenticateUserWithKeyguardManager(activity, fido2PromptInfo, signatureProvider)
    }

    private suspend fun authenticateUserWithBiometricPrompt(
        activity: FragmentActivity,
        fido2PromptInfo: Fido2PromptInfo?,
        signatureProvider: (() -> Signature)?
    ): Fido2UserAuthResult = withContext(authHandlerDispatcher) {
        suspendCancellableCoroutine { continuation ->
            val promptInfo =
                BiometricPrompt.PromptInfo.Builder()
                    .setTitle(fido2PromptInfo?.title ?: "Device Credential Authentication")
                    .setSubtitle(fido2PromptInfo?.subtitle ?: "Enter device credentials to proceed")
                    .setDescription(
                        fido2PromptInfo?.description
                            ?: "Input your Fingerprint or device credential to ensure it's you!",
                    )
                    .setAllowedAuthenticators(
                        BiometricManager.Authenticators.BIOMETRIC_STRONG or
                            BiometricManager.Authenticators.DEVICE_CREDENTIAL
                    )
                    .build()

            val biometricPrompt =
                BiometricPrompt(
                    activity,
                    ContextCompat.getMainExecutor(activity.applicationContext),
                    object : BiometricPrompt.AuthenticationCallback() {
                        override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                            continuation.resumeWith(
                                Result.success(
                                    Fido2UserAuthResult(
                                        signature = result.cryptoObject?.signature
                                    )
                                )
                            )
                        }

                        override fun onAuthenticationFailed() {
                            // In the event of an authentication failure, the user is allowed to try again.
                        }

                        override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                            continuation.resumeWithException(
                                AuthenticationHandler.AuthenticationErrorException(
                                    errorCode,
                                    "Biometric authentication error: $errString"
                                )
                            )
                        }
                    },
                )

            continuation.invokeOnCancellation {
                biometricPrompt.cancelAuthentication()
            }

            if (signatureProvider != null) {
                val cryptoObject = BiometricPrompt.CryptoObject(signatureProvider())
                biometricPrompt.authenticate(promptInfo, cryptoObject)
            } else {
                biometricPrompt.authenticate(promptInfo)
            }
        }
    }

    private suspend fun authenticateUserWithKeyguardManager(
        activity: FragmentActivity,
        fido2PromptInfo: Fido2PromptInfo?,
        signatureProvider: (() -> Signature)?
    ): Fido2UserAuthResult = withContext(authHandlerDispatcher) {
        try {
            keyguardManagerWrapper.authenticate(activity, fido2PromptInfo)
            val signature = signatureProvider?.invoke()
            return@withContext Fido2UserAuthResult(signature = signature)
        } catch (e: KeyguardManagerWrapper.KeyguardNotSecuredException) {
            throw AuthenticationHandler.AuthenticationErrorException(
                message = "Keyguard not secured",
                cause = e
            )
        } catch (e: KeyguardManagerWrapper.KeyguardManagerAuthenticationFailedException) {
            throw AuthenticationHandler.AuthenticationErrorException(
                errorCode = e.errorCode,
                message = e.message,
                cause = e
            )
        } catch (e: Exception) {
            throw AuthenticationHandler.AuthenticationErrorException(
                message = "An unexpected error occurred",
                cause = e
            )
        }
    }
}
