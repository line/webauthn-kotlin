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
import android.security.keystore.KeyPermanentlyInvalidatedException
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import com.linecorp.webauthn.model.Fido2PromptInfo
import com.linecorp.webauthn.model.Fido2UserAuthResult
import java.security.Signature
import kotlin.coroutines.resumeWithException
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext

internal class DeviceCredentialAuthenticationHandler(
    private val authHandlerDispatcher: CoroutineDispatcher = Dispatchers.Main,
    private val keyguardManagerWrapper: KeyguardManagerWrapper = KeyguardManagerWrapper(),
) : AuthenticationHandler,
    AuthenticationCapability {

    override fun canAuthenticateStatus(context: Context): Int = if (
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.R
    ) {
        BiometricManager.from(context).canAuthenticate(
            BiometricManager.Authenticators.BIOMETRIC_STRONG or
                BiometricManager.Authenticators.DEVICE_CREDENTIAL
        )
    } else if (keyguardManagerWrapper.isSupported(context)) {
        BiometricManager.BIOMETRIC_SUCCESS
    } else {
        BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED
    }

    override fun isSupported(context: Context): Boolean =
        canAuthenticateStatus(context) == BiometricManager.BIOMETRIC_SUCCESS

    override suspend fun authenticate(
        activity: FragmentActivity,
        fido2PromptInfo: Fido2PromptInfo?,
        signatureProvider: (() -> Signature)?
    ): Fido2UserAuthResult {
        if (activity.supportFragmentManager.isStateSaved) {
            throw AuthenticationHandler.AuthenticationErrorException(
                errorCode = AuthenticationHandler.ERROR_HOST_STATE_SAVED,
                message = HOST_STATE_SAVED_MESSAGE
            )
        }
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            authenticateUserWithBiometricPrompt(activity, fido2PromptInfo, signatureProvider)
        } else {
            authenticateUserWithKeyguardManager(activity, fido2PromptInfo, signatureProvider)
        }
    }

    private suspend fun authenticateUserWithBiometricPrompt(
        activity: FragmentActivity,
        fido2PromptInfo: Fido2PromptInfo?,
        signatureProvider: (() -> Signature)?
    ): Fido2UserAuthResult = withContext(authHandlerDispatcher) {
        suspendCancellableCoroutine { continuation ->
            if (activity.supportFragmentManager.isStateSaved) {
                continuation.resumeWithException(
                    AuthenticationHandler.AuthenticationErrorException(
                        errorCode = AuthenticationHandler.ERROR_HOST_STATE_SAVED,
                        message = HOST_STATE_SAVED_MESSAGE
                    )
                )
                return@suspendCancellableCoroutine
            }

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
                                        errorCode,
                                        "Biometric authentication error: $errString"
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

    private suspend fun authenticateUserWithKeyguardManager(
        activity: FragmentActivity,
        fido2PromptInfo: Fido2PromptInfo?,
        signatureProvider: (() -> Signature)?
    ): Fido2UserAuthResult = withContext(authHandlerDispatcher) {
        if (activity.supportFragmentManager.isStateSaved) {
            throw AuthenticationHandler.AuthenticationErrorException(
                errorCode = AuthenticationHandler.ERROR_HOST_STATE_SAVED,
                message = HOST_STATE_SAVED_MESSAGE
            )
        }
        try {
            keyguardManagerWrapper.authenticate(activity, fido2PromptInfo)
            val signature = signatureProvider?.invoke()
            return@withContext Fido2UserAuthResult(signature = signature)
        } catch (e: KeyguardManagerWrapper.KeyguardNotSecuredException) {
            throw AuthenticationHandler.AuthenticationErrorException(
                message = "Keyguard not secured",
                cause = e
            )
        } catch (e: KeyguardManagerWrapper.DeviceCredentialIntentNotAvailableException) {
            throw AuthenticationHandler.AuthenticationErrorException(
                message = "Device credential intent not available",
                cause = e
            )
        } catch (e: KeyguardManagerWrapper.KeyguardManagerAuthenticationFailedException) {
            throw AuthenticationHandler.AuthenticationErrorException(
                errorCode = e.errorCode,
                message = e.message,
                cause = e
            )
        } catch (e: KeyPermanentlyInvalidatedException) {
            // Must not be wrapped. `Authenticator.authenticate` maps this to
            // `WebAuthnException.AuthenticationException.KeyPermanentlyInvalidatedException`, but its
            // AuthenticationErrorException branch matches first, so a wrapped one reaches the caller as a
            // bare NotAllowedException - indistinguishable from a user cancellation, when in fact the
            // credential needs re-registration. Not extended to `UserNotAuthenticatedException`, which has
            // no such mapping: rethrowing it would only turn a NotAllowedException into an UnknownException.
            // Only this path needs the rethrow: from API 30 up `signatureProvider()` runs inside
            // `suspendCancellableCoroutine` with no catch around it.
            throw e
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            throw AuthenticationHandler.AuthenticationErrorException(
                message = "An unexpected error occurred: ${e::class.java.name}: ${e.message}",
                cause = e
            )
        }
    }
}
