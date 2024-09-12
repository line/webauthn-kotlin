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

import android.app.Activity
import android.app.KeyguardManager
import android.content.Context
import android.content.Intent
import android.os.Build
import android.util.Log
import androidx.activity.result.ActivityResultLauncher
import androidx.activity.result.contract.ActivityResultContract
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

internal class DeviceCredentialAuthenticationHandler(
    private val activity: FragmentActivity,
    private val authHandlerDispatcher: CoroutineDispatcher = Dispatchers.Main,
) : AuthenticationHandler {
    class AuthenticationFailedException : Exception()
    class AuthenticationErrorException : Exception()

    internal interface OnConfirmation {
        fun onConfirmation(result: Boolean)
    }

    private var onConfirmation: OnConfirmation? = null
    private var confirmCredentialLauncher: ActivityResultLauncher<Fido2PromptInfo?> =
        activity.registerForActivityResult(
            ConfirmDeviceCredentialContract(getKeyguardManager(activity.applicationContext)!!)
        ) { result: Boolean ->
            if (onConfirmation != null) {
                onConfirmation!!.onConfirmation(result)
                onConfirmation = null
            }
        }

    override fun isSupported(): Boolean {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            // API level >= 30
            val biometricManager = BiometricManager.from(activity.applicationContext)
            biometricManager.canAuthenticate(
                BiometricManager.Authenticators.BIOMETRIC_STRONG or
                    BiometricManager.Authenticators.DEVICE_CREDENTIAL
            ) == BiometricManager.BIOMETRIC_SUCCESS
        } else {
            // API level < 30
            val keyguardManager = getKeyguardManager(activity.applicationContext) ?: return false
            return keyguardManager.isDeviceSecure
        }
    }

    override suspend fun authenticate(
        signatureProvider: () -> Signature,
        fido2PromptInfo: Fido2PromptInfo?
    ): Fido2UserAuthResult {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            authenticateUserWithBiometricPrompt(signatureProvider, fido2PromptInfo)
        } else {
            authenticateUserWithKeyguardManager(signatureProvider, fido2PromptInfo)
        }
    }

    private suspend fun authenticateUserWithBiometricPrompt(
        signatureProvider: () -> Signature,
        fido2PromptInfo: Fido2PromptInfo?
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

            val cryptoObject: BiometricPrompt.CryptoObject = BiometricPrompt.CryptoObject(signatureProvider())

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
                            continuation.resumeWithException(AuthenticationFailedException())
                        }

                        override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                            continuation.resumeWithException(AuthenticationErrorException())
                        }
                    },
                )

            continuation.invokeOnCancellation {
                biometricPrompt.cancelAuthentication()
            }

            biometricPrompt.authenticate(promptInfo, cryptoObject)
        }
    }

    private suspend fun authenticateUserWithKeyguardManager(
        signatureProvider: () -> Signature,
        fido2PromptInfo: Fido2PromptInfo?
    ): Fido2UserAuthResult = withContext(authHandlerDispatcher) {
        suspendCancellableCoroutine { continuation ->
            val keyguardManager = getKeyguardManager(activity.applicationContext)
            if (keyguardManager == null) {
                Log.e("DeviceCredentialAuthenticator", "Could not get KeyguardManager")
                throw AuthenticationErrorException()
            }

            onConfirmation = object : OnConfirmation {
                override fun onConfirmation(result: Boolean) {
                    if (result) {
                        val signature = signatureProvider()
                        continuation.resumeWith(
                            Result.success(
                                Fido2UserAuthResult(
                                    signature = signature
                                )
                            )
                        )
                    } else {
                        continuation.resumeWithException(AuthenticationFailedException())
                    }
                }
            }
            confirmCredentialLauncher.launch(fido2PromptInfo)

            continuation.invokeOnCancellation {
                continuation.resumeWithException(AuthenticationErrorException())
            }
        }
    }

    private fun getKeyguardManager(context: Context): KeyguardManager? {
        val keyguardManager = try {
            context.getSystemService(KeyguardManager::class.java)
        } catch (e: Exception) {
            null
        }
        return keyguardManager
    }
}

class ConfirmDeviceCredentialContract(
    private val keyguardManager: KeyguardManager
) : ActivityResultContract<Fido2PromptInfo?, Boolean>() {
    override fun createIntent(context: Context, input: Fido2PromptInfo?): Intent {
        return keyguardManager.createConfirmDeviceCredentialIntent(
            input?.title ?: "Device Credential Authentication",
            input?.description ?: "Input your Fingerprint or device credential to ensure it's you!"
        )
    }

    override fun parseResult(resultCode: Int, intent: Intent?): Boolean {
        return resultCode == Activity.RESULT_OK
    }
}
