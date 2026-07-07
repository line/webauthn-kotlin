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
import android.util.Log
import androidx.appcompat.app.AppCompatActivity
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

        val intent = keyguardManager.createConfirmDeviceCredentialIntent(
            fido2PromptInfo?.title ?: "Device Credential Authentication",
            fido2PromptInfo?.description ?: "Input your Fingerprint or device credential to ensure it's you!"
        ) ?: throw DeviceCredentialIntentNotAvailableException("Device credential intent not available")

        Log.d("KeyguardManagerWrapper", "Starting AuthenticationActivity with intent")

        return suspendCancellableCoroutine { continuation ->
            AuthenticationActivity.start(context, intent) { result, errorCode ->
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
    }

    class AuthenticationActivity : AppCompatActivity() {

        companion object {
            private const val REQUEST_CODE_CONFIRM_DEVICE_CREDENTIAL = 1
            private var callback: ((Boolean, Int?) -> Unit)? = null

            fun start(context: Context, intent: Intent, callback: (Boolean, Int?) -> Unit) {
                this.callback = callback
                val activityIntent = Intent(context, AuthenticationActivity::class.java).apply {
                    putExtra("fido2_auth_intent", intent)
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                }
                Log.d("AuthenticationActivity", "Starting activity with intent")
                context.startActivity(activityIntent)
            }

            /**
             * Delivers the result exactly once and releases the callback reference so a
             * re-created activity cannot deliver a second result (which would crash the
             * already-resumed continuation) and the captured continuation is not leaked.
             */
            private fun deliverResult(result: Boolean, errorCode: Int?) {
                callback?.invoke(result, errorCode)
                callback = null
            }
        }

        override fun onCreate(savedInstanceState: Bundle?) {
            super.onCreate(savedInstanceState)
            if (savedInstanceState != null) {
                // Re-created (configuration change / process restore): the confirmation
                // launched from the original instance is still in flight; do not fire a
                // second one.
                return
            }
            val intent = intent.getParcelableExtra<Intent>("fido2_auth_intent")
            if (intent != null) {
                Log.d("AuthenticationActivity", "Starting activity for result")
                startActivityForResult(intent, REQUEST_CODE_CONFIRM_DEVICE_CREDENTIAL)
            } else {
                Log.d("AuthenticationActivity", "Intent is null, finishing activity")
                deliverResult(false, BiometricPrompt.BIOMETRIC_ERROR_UNABLE_TO_PROCESS)
                finish()
            }
        }

        override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
            super.onActivityResult(requestCode, resultCode, data)
            if (requestCode == REQUEST_CODE_CONFIRM_DEVICE_CREDENTIAL) {
                Log.d("AuthenticationActivity", "Received result: $resultCode")
                when (resultCode) {
                    RESULT_OK -> {
                        deliverResult(true, null)
                        Log.d("AuthenticationActivity", "Authentication succeeded")
                    }
                    RESULT_CANCELED -> {
                        Log.d("AuthenticationActivity", "Authentication canceled")
                        deliverResult(false, BiometricPrompt.BIOMETRIC_ERROR_USER_CANCELED)
                    }
                    else -> {
                        Log.d("AuthenticationActivity", "Authentication failed")
                        deliverResult(false, BiometricPrompt.BIOMETRIC_ERROR_UNABLE_TO_PROCESS)
                    }
                }
            }
            finish()
        }
    }
}
