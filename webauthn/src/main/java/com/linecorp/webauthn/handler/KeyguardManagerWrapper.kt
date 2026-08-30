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

import android.app.KeyguardManager
import android.content.Context
import android.content.Intent
import android.hardware.biometrics.BiometricPrompt
import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import com.linecorp.webauthn.model.Fido2PromptInfo
import com.linecorp.webauthn.util.WebAuthnLog
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

        // Confirm the intent can be built before starting the activity, so an unavailable keyguard
        // surfaces here rather than inside onCreate where there is no continuation to fail.
        keyguardManager.createConfirmDeviceCredentialIntent(title, description)
            ?: throw DeviceCredentialIntentNotAvailableException("Device credential intent not available")

        return suspendCancellableCoroutine { continuation ->
            val callback: (Boolean, Int?) -> Unit = { result, errorCode ->
                if (continuation.isActive) {
                    if (result) {
                        continuation.resume(true)
                    } else {
                        continuation.resumeWithException(
                            KeyguardManagerAuthenticationFailedException(
                                errorCode = errorCode,
                                message = "Authentication failed with errorCode: $errorCode"
                            )
                        )
                    }
                }
            }
            // Registered before start so cancellation is never unhandled, not even in the window
            // between installing the callback and returning from start.
            continuation.invokeOnCancellation { AuthenticationActivity.clearCallback(callback) }
            AuthenticationActivity.start(context, title, description, callback)
        }
    }

    class AuthenticationActivity : AppCompatActivity() {

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
            // On recreation the credential prompt is already in flight. Relaunching it would show the
            // user a second prompt for one request, and reporting failure would abort a request that is
            // still going to deliver a result.
            if (savedInstanceState != null) {
                return
            }
            val keyguardManager = getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
            val confirmIntent = keyguardManager.createConfirmDeviceCredentialIntent(
                intent.getCharSequenceExtra(EXTRA_TITLE),
                intent.getCharSequenceExtra(EXTRA_DESCRIPTION)
            )
            if (confirmIntent == null) {
                takeCallback()?.invoke(false, BiometricPrompt.BIOMETRIC_ERROR_UNABLE_TO_PROCESS)
                finish()
                return
            }
            WebAuthnLog.d("Launching the confirm-device-credential prompt.")
            startActivityForResult(confirmIntent, REQUEST_CODE_CONFIRM_DEVICE_CREDENTIAL)
        }

        override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
            super.onActivityResult(requestCode, resultCode, data)
            if (requestCode == REQUEST_CODE_CONFIRM_DEVICE_CREDENTIAL) {
                when (resultCode) {
                    RESULT_OK -> {
                        WebAuthnLog.d("The device credential was confirmed.")
                        takeCallback()?.invoke(true, null)
                    }
                    RESULT_CANCELED -> {
                        WebAuthnLog.d("The confirm-device-credential prompt was dismissed.")
                        takeCallback()?.invoke(false, BiometricPrompt.BIOMETRIC_ERROR_USER_CANCELED)
                    }
                    else -> takeCallback()?.invoke(false, BiometricPrompt.BIOMETRIC_ERROR_UNABLE_TO_PROCESS)
                }
            }
            finish()
        }
    }
}
