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

import android.app.Activity
import android.app.KeyguardManager
import android.content.Context
import android.content.Intent
import android.hardware.biometrics.BiometricPrompt
import android.os.Bundle
import android.util.Log
import com.linecorp.webauthn.model.Fido2PromptInfo
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlinx.coroutines.suspendCancellableCoroutine

class KeyguardManagerWrapper {

    class KeyguardNotSecuredException(message: String) : Exception(message)
    class DeviceCredentialIntentNotAvailableException(message: String) : Exception(message)
    class KeyguardManagerAuthenticationFailedException(val errorCode: Int?, message: String) : Exception(message)

    fun isSupported(context: Context): Boolean {
        val keyguardManager = context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
        return keyguardManager.isDeviceSecure
    }

    suspend fun authenticate(context: Context, fido2PromptInfo: Fido2PromptInfo?): Boolean {
        val keyguardManager = context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager

        if (!keyguardManager.isKeyguardSecure) {
            throw KeyguardNotSecuredException("Keyguard not secured")
        }

        val title = fido2PromptInfo?.title ?: "Device Credential Authentication"
        val description = fido2PromptInfo?.description
            ?: "Input your Fingerprint or device credential to ensure it's you!"

        keyguardManager.createConfirmDeviceCredentialIntent(title, description)
            ?: throw DeviceCredentialIntentNotAvailableException("Device credential intent not available")

        return suspendCancellableCoroutine { continuation ->
            val callback: (Boolean, Int?) -> Unit = { result, errorCode ->
                if (continuation.isActive) {
                    if (result) {
                        Log.d("KeyguardManagerWrapper", "Authentication succeeded")
                        continuation.resume(true)
                    } else {
                        Log.d("KeyguardManagerWrapper", "Authentication failed")
                        continuation.resumeWithException(
                            KeyguardManagerAuthenticationFailedException(
                                errorCode = errorCode,
                                message = "Authentication failed with errorCode: $errorCode"
                            )
                        )
                    }
                }
            }
            continuation.invokeOnCancellation { AuthenticationActivity.clearCallback(callback) }
            if (!continuation.isActive) {
                return@suspendCancellableCoroutine
            }
            Log.d("KeyguardManagerWrapper", "Starting AuthenticationActivity")
            AuthenticationActivity.start(context, title, description, callback)
        }
    }

    class AuthenticationActivity : Activity() {

        companion object {
            private const val REQUEST_CODE_CONFIRM_DEVICE_CREDENTIAL = 1
            private const val EXTRA_TITLE = "fido2_auth_title"
            private const val EXTRA_DESCRIPTION = "fido2_auth_description"

            private val callbackRef = java.util.concurrent.atomic.AtomicReference<((Boolean, Int?) -> Unit)?>(null)

            @JvmSynthetic
            internal fun start(
                context: Context,
                title: CharSequence,
                description: CharSequence,
                callback: (Boolean, Int?) -> Unit
            ) {
                callbackRef.set(callback)
                val activityIntent = Intent(context, AuthenticationActivity::class.java).apply {
                    putExtra(EXTRA_TITLE, title)
                    putExtra(EXTRA_DESCRIPTION, description)
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                }
                try {
                    Log.d("AuthenticationActivity", "Starting activity")
                    context.startActivity(activityIntent)
                } catch (e: Throwable) {
                    clearCallback(callback)
                    throw e
                }
            }

            @JvmSynthetic
            internal fun clearCallback(callback: (Boolean, Int?) -> Unit) {
                callbackRef.compareAndSet(callback, null)
            }

            private fun takeCallback(): ((Boolean, Int?) -> Unit)? = callbackRef.getAndSet(null)
        }

        override fun onCreate(savedInstanceState: Bundle?) {
            super.onCreate(savedInstanceState)
            if (savedInstanceState != null) {
                if (callbackRef.get() == null) {
                    finish()
                }
                return
            }
            val keyguardManager = getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
            val confirmIntent = keyguardManager.createConfirmDeviceCredentialIntent(
                intent.getCharSequenceExtra(EXTRA_TITLE),
                intent.getCharSequenceExtra(EXTRA_DESCRIPTION)
            )
            if (confirmIntent == null) {
                Log.d("AuthenticationActivity", "Confirm intent is null, finishing activity")
                takeCallback()?.invoke(false, BiometricPrompt.BIOMETRIC_ERROR_UNABLE_TO_PROCESS)
                finish()
                return
            }
            Log.d("AuthenticationActivity", "Starting activity for result")
            startActivityForResult(confirmIntent, REQUEST_CODE_CONFIRM_DEVICE_CREDENTIAL)
        }

        override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
            super.onActivityResult(requestCode, resultCode, data)
            if (requestCode == REQUEST_CODE_CONFIRM_DEVICE_CREDENTIAL) {
                Log.d("AuthenticationActivity", "Received result: $resultCode")
                when (resultCode) {
                    RESULT_OK -> {
                        Log.d("AuthenticationActivity", "Authentication succeeded")
                        takeCallback()?.invoke(true, null)
                    }
                    RESULT_CANCELED -> {
                        Log.d("AuthenticationActivity", "Authentication canceled")
                        takeCallback()?.invoke(false, BiometricPrompt.BIOMETRIC_ERROR_USER_CANCELED)
                    }
                    else -> {
                        Log.d("AuthenticationActivity", "Authentication failed")
                        takeCallback()?.invoke(false, BiometricPrompt.BIOMETRIC_ERROR_UNABLE_TO_PROCESS)
                    }
                }
            }
            finish()
        }
    }
}
