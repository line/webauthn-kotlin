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

@file:Suppress("DEPRECATION")

package com.linecorp.webauthn.handler

import android.annotation.SuppressLint
import android.app.AlertDialog
import android.app.Dialog
import android.app.KeyguardManager
import android.content.Context
import android.content.DialogInterface
import android.content.pm.PackageManager
import android.hardware.fingerprint.FingerprintManager
import android.os.Build
import android.os.Bundle
import android.os.CancellationSignal
import android.os.Handler
import android.os.Looper
import androidx.biometric.BiometricPrompt
import androidx.fragment.app.DialogFragment
import androidx.fragment.app.FragmentActivity
import java.security.Signature
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext

/**
 * Replaces the FingerprintManagerCompat paths disabled by androidx.core 1.18 on API 28 and 29.
 * Device lists and dialog strings follow androidx.biometric's fingerprint fallback.
 */
@SuppressLint("PrivateResource")
internal object LegacyFingerprintFallback {

    internal fun interface FingerprintRequest {
        fun authenticate(
            signature: Signature,
            cancellationSignal: CancellationSignal,
            callback: FingerprintManager.AuthenticationCallback,
            handler: Handler,
        )
    }

    /**
     * Whether an enrolled fingerprint can authorise a key that requires user authentication for every use.
     *
     * The platform annotates these queries with `USE_FINGERPRINT`, but `FingerprintService` on API 28
     * and 29 accepts `USE_BIOMETRIC`, which the SDK manifest declares, in its place.
     */
    @SuppressLint("MissingPermission")
    fun isAvailable(context: Context): Boolean {
        if (!context.packageManager.hasSystemFeature(PackageManager.FEATURE_FINGERPRINT)) {
            return false
        }
        val keyguardManager = context.getSystemService(KeyguardManager::class.java) ?: return false
        if (!keyguardManager.isDeviceSecure) {
            return false
        }
        val fingerprintManager = context.getSystemService(FingerprintManager::class.java) ?: return false
        return fingerprintManager.isHardwareDetected && fingerprintManager.hasEnrolledFingerprints()
    }

    /**
     * Whether androidx.biometric runs crypto-based authentication on this device through
     * `FingerprintManagerCompat` instead of `BiometricPrompt`. It does so on API 28 for the vendors and
     * model prefixes in its `crypto_fingerprint_fallback_vendors` and `crypto_fingerprint_fallback_prefixes`
     * resources, where `BiometricPrompt` can offer a weak biometric that cannot authorise the key.
     */
    fun requiresFingerprintForCrypto(
        context: Context,
        sdkInt: Int = Build.VERSION.SDK_INT,
        manufacturer: String? = Build.MANUFACTURER,
        model: String? = Build.MODEL,
    ): Boolean {
        if (sdkInt != Build.VERSION_CODES.P) {
            return false
        }
        val resources = context.resources
        val vendors = resources.getStringArray(androidx.biometric.R.array.crypto_fingerprint_fallback_vendors)
        val modelPrefixes = resources.getStringArray(androidx.biometric.R.array.crypto_fingerprint_fallback_prefixes)
        return vendors.any { manufacturer.equals(it, ignoreCase = true) } ||
            modelPrefixes.any { model?.startsWith(it) == true }
    }

    /**
     * Whether [authenticate] leaves its dialog undrawn. On API 28 androidx.biometric does not draw its
     * fingerprint dialog on the model prefixes in its `hide_fingerprint_instantly_prefixes` resource,
     * where the dialog would sit behind a system overlay.
     */
    fun hidesDialog(context: Context, sdkInt: Int = Build.VERSION.SDK_INT, model: String? = Build.MODEL): Boolean {
        if (sdkInt != Build.VERSION_CODES.P) {
            return false
        }
        val modelPrefixes = context.resources.getStringArray(
            androidx.biometric.R.array.hide_fingerprint_instantly_prefixes
        )
        return modelPrefixes.any { model?.startsWith(it) == true }
    }

    /**
     * The [BiometricPrompt] code for a [FingerprintManager] error code. The platform reports the errors
     * that [BiometricPrompt] defines with the same values, and a vendor error as 1000 plus the vendor's
     * code. Any code [BiometricPrompt] does not define becomes `ERROR_VENDOR`, as in androidx.biometric.
     */
    fun toBiometricPromptError(errorCode: Int): Int =
        if (errorCode in biometricPromptErrors) errorCode else BiometricPrompt.ERROR_VENDOR

    private val biometricPromptErrors = setOf(
        BiometricPrompt.ERROR_HW_UNAVAILABLE,
        BiometricPrompt.ERROR_UNABLE_TO_PROCESS,
        BiometricPrompt.ERROR_TIMEOUT,
        BiometricPrompt.ERROR_NO_SPACE,
        BiometricPrompt.ERROR_CANCELED,
        BiometricPrompt.ERROR_LOCKOUT,
        BiometricPrompt.ERROR_VENDOR,
        BiometricPrompt.ERROR_LOCKOUT_PERMANENT,
        BiometricPrompt.ERROR_USER_CANCELED,
        BiometricPrompt.ERROR_NO_BIOMETRICS,
        BiometricPrompt.ERROR_HW_NOT_PRESENT,
        BiometricPrompt.ERROR_NEGATIVE_BUTTON,
        BiometricPrompt.ERROR_NO_DEVICE_CREDENTIAL,
        BiometricPrompt.ERROR_SECURITY_UPDATE_REQUIRED,
    )

    @SuppressLint("MissingPermission")
    suspend fun authenticate(
        activity: FragmentActivity,
        promptInfo: BiometricPrompt.PromptInfo,
        signature: Signature,
        fingerprintRequest: FingerprintRequest? = null,
    ): Signature = withContext(Dispatchers.Main) {
        suspendCancellableCoroutine { continuation ->
            val mainHandler = Handler(Looper.getMainLooper())
            val cancellationSignal = CancellationSignal()
            val prompt = FingerprintDialogFragment().apply { this.promptInfo = promptInfo }
            var finished = false
            var callbackRelay: CallbackRelay? = null

            fun cleanup() {
                callbackRelay?.target = null
                prompt.onError = null
                if (prompt.isAdded) prompt.dismissAllowingStateLoss()
            }

            fun finish(block: () -> Unit) {
                if (finished || !continuation.isActive) return
                finished = true
                cleanup()
                block()
            }

            fun fail(errorCode: Int, reason: CharSequence?, cause: Throwable? = null) {
                finish {
                    cancellationSignal.cancel()
                    continuation.resumeWithException(
                        AuthenticationHandler.AuthenticationErrorException(
                            errorCode = errorCode,
                            message = "Biometric authentication error: $reason",
                            cause = cause,
                        )
                    )
                }
            }

            val context = activity.applicationContext
            val manager = context.getSystemService(FingerprintManager::class.java)
            if (fingerprintRequest == null && manager == null) {
                fail(BiometricPrompt.ERROR_HW_NOT_PRESENT, "Fingerprint hardware is not available.")
                return@suspendCancellableCoroutine
            }
            if (activity.isDestroyed || activity.supportFragmentManager.isStateSaved) {
                fail(BiometricPrompt.ERROR_CANCELED, "The activity is not in the foreground.")
                return@suspendCancellableCoroutine
            }
            val request = fingerprintRequest ?: FingerprintRequest { requestedSignature, signal, callback, handler ->
                manager!!.authenticate(
                    FingerprintManager.CryptoObject(requestedSignature),
                    signal,
                    0,
                    callback,
                    handler
                )
            }
            prompt.onError = { code, message -> fail(code, message) }

            continuation.invokeOnCancellation {
                mainHandler.post {
                    if (!finished) {
                        finished = true
                        cleanup()
                        cancellationSignal.cancel()
                    }
                }
            }

            val callback = object : FingerprintManager.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: FingerprintManager.AuthenticationResult) {
                    val unlocked = result.cryptoObject?.signature
                    if (unlocked == null) {
                        fail(BiometricPrompt.ERROR_UNABLE_TO_PROCESS, "The crypto object was not returned.")
                    } else {
                        finish { continuation.resume(unlocked) }
                    }
                }

                override fun onAuthenticationFailed() {
                    prompt.updateStatus(context.getString(androidx.biometric.R.string.fingerprint_not_recognized))
                }

                override fun onAuthenticationHelp(helpCode: Int, helpString: CharSequence?) {
                    helpString?.let { prompt.updateStatus(it) }
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence?) {
                    fail(toBiometricPromptError(errorCode), errString)
                }
            }
            val relay = CallbackRelay(callback).also { callbackRelay = it }
            try {
                prompt.showNow(activity.supportFragmentManager, "webauthn.fingerprint")
                if (!finished && continuation.isActive) {
                    request.authenticate(signature, cancellationSignal, relay, mainHandler)
                }
            } catch (e: RuntimeException) {
                fail(BiometricPrompt.ERROR_HW_UNAVAILABLE, e.message, e)
            }
        }
    }

    @Suppress("DEPRECATION")
    class FingerprintDialogFragment : DialogFragment() {
        var promptInfo: BiometricPrompt.PromptInfo? = null
        var onError: ((Int, CharSequence?) -> Unit)? = null
        private var status: CharSequence? = null

        override fun onCreate(savedInstanceState: Bundle?) {
            super.onCreate(savedInstanceState)
            retainInstance = true
            showsDialog = promptInfo != null && !hidesDialog(requireContext())
        }

        override fun onCreateDialog(savedInstanceState: Bundle?): Dialog {
            val info = requireNotNull(promptInfo)
            val negativeText = info.negativeButtonText
            return AlertDialog.Builder(requireContext())
                .setTitle(info.title)
                .setMessage(
                    messageWith(status ?: getString(androidx.biometric.R.string.fingerprint_dialog_touch_sensor))
                )
                .setNegativeButton(negativeText) { _, _ ->
                    onError?.invoke(BiometricPrompt.ERROR_NEGATIVE_BUTTON, negativeText)
                }
                .create()
                .also { it.setCanceledOnTouchOutside(false) }
        }

        override fun onStart() {
            super.onStart()
            if (onError == null) dismissAllowingStateLoss()
        }

        override fun onCancel(dialog: DialogInterface) {
            onError?.invoke(BiometricPrompt.ERROR_USER_CANCELED, "Fingerprint operation canceled by user.")
        }

        override fun onStop() {
            super.onStop()
            if (activity?.isChangingConfigurations == false) {
                onError?.invoke(
                    BiometricPrompt.ERROR_CANCELED,
                    "The activity left the foreground during authentication."
                )
            }
        }

        override fun onDestroy() {
            onError?.invoke(BiometricPrompt.ERROR_CANCELED, "The activity was destroyed during authentication.")
            super.onDestroy()
        }

        fun updateStatus(message: CharSequence) {
            status = message
            (dialog as? AlertDialog)?.setMessage(messageWith(message))
        }

        private fun messageWith(message: CharSequence): String =
            listOf(promptInfo?.subtitle, promptInfo?.description, message)
                .filterNot { it.isNullOrEmpty() }.joinToString("\n\n")
    }

    // FingerprintManager retains its last callback; clear the target when the request ends.
    internal class CallbackRelay(var target: FingerprintManager.AuthenticationCallback?) :
        FingerprintManager.AuthenticationCallback() {
        override fun onAuthenticationSucceeded(result: FingerprintManager.AuthenticationResult) {
            target?.onAuthenticationSucceeded(result)
        }

        override fun onAuthenticationFailed() {
            target?.onAuthenticationFailed()
        }

        override fun onAuthenticationHelp(helpCode: Int, helpString: CharSequence?) {
            target?.onAuthenticationHelp(helpCode, helpString)
        }

        override fun onAuthenticationError(errorCode: Int, errString: CharSequence?) {
            target?.onAuthenticationError(errorCode, errString)
        }
    }
}
