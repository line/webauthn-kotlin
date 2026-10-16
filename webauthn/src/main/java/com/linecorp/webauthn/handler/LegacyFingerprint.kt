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
import android.app.KeyguardManager
import android.content.Context
import android.content.pm.PackageManager
import android.hardware.fingerprint.FingerprintManager
import android.os.Build
import android.os.CancellationSignal
import android.os.Handler
import android.os.Looper
import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleOwner
import com.linecorp.webauthn.model.Fido2PromptInfo
import java.security.Signature
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlinx.coroutines.suspendCancellableCoroutine

/**
 * Fingerprint support for API 28 and 29 that talks to the platform [FingerprintManager] directly.
 *
 * On these API levels androidx.biometric answers `canAuthenticate(BIOMETRIC_STRONG)` through
 * `androidx.core.hardware.fingerprint.FingerprintManagerCompat`, and on API 28 it also runs crypto-based
 * authentication through that class on the devices named in its `crypto_fingerprint_fallback_*`
 * resources. androidx.core ships that class as a no-op that reports no fingerprint hardware and never
 * calls back. The application, not this SDK, decides which androidx.core ends up in the APK, so the SDK
 * answers these two paths itself.
 *
 * The device lists and dialog strings are androidx.biometric resources, read so that this class acts on
 * exactly the devices androidx.biometric would hand to `FingerprintManagerCompat`.
 */
@SuppressLint("PrivateResource")
internal object LegacyFingerprint {

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

    /**
     * Authenticates with the platform [FingerprintManager] and returns the unlocked [signature].
     * The dialog shows the texts and defaults of the `BiometricPrompt` path. Errors are reported with
     * the same codes as [BiometricPrompt], so callers that branch on `BiometricPrompt.ERROR_*` keep
     * working. As with androidx.biometric on API 28, the request ends with `ERROR_CANCELED` when the
     * activity stops for a reason other than a configuration change, and also when it is destroyed.
     *
     * Must be called on the main thread.
     */
    suspend fun authenticate(
        activity: FragmentActivity,
        fido2PromptInfo: Fido2PromptInfo?,
        signature: Signature,
    ): Signature = suspendCancellableCoroutine { continuation ->
        val mainHandler = Handler(Looper.getMainLooper())
        val cancellationSignal = CancellationSignal()
        var dialog: AlertDialog? = null
        var lifecycleObserver: DefaultLifecycleObserver? = null
        var callbackRelay: CallbackRelay? = null

        fun finish(block: () -> Unit) {
            if (!continuation.isActive) return
            callbackRelay?.target = null
            lifecycleObserver?.let { activity.lifecycle.removeObserver(it) }
            dialog?.setOnCancelListener(null)
            dialog?.dismiss()
            block()
        }

        fun fail(errorCode: Int, reason: CharSequence?, cause: Throwable? = null) {
            if (!cancellationSignal.isCanceled) cancellationSignal.cancel()
            finish {
                continuation.resumeWithException(
                    AuthenticationHandler.AuthenticationErrorException(
                        errorCode = errorCode,
                        message = "Biometric authentication error: $reason",
                        cause = cause,
                    )
                )
            }
        }

        // The fingerprint service can hold this manager after the request ends, and the application
        // context's instance keeps the activity out of that reference. See CallbackRelay.
        val fingerprintManager = activity.applicationContext.getSystemService(FingerprintManager::class.java)
        if (fingerprintManager == null) {
            fail(BiometricPrompt.ERROR_HW_NOT_PRESENT, "Fingerprint hardware is not available.")
            return@suspendCancellableCoroutine
        }
        if (!activity.lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)) {
            fail(BiometricPrompt.ERROR_CANCELED, "The activity is not in the foreground.")
            return@suspendCancellableCoroutine
        }

        val touchSensorMessage = activity.getString(androidx.biometric.R.string.fingerprint_dialog_touch_sensor)
        val baseMessage = listOf(
            fido2PromptInfo?.subtitle ?: "Enter biometric credentials to proceed",
            fido2PromptInfo?.description ?: "Input your Fingerprint or FaceID to ensure it's you!",
        ).filter { it.isNotEmpty() }.joinToString("\n")
        fun messageWith(status: CharSequence): String =
            if (baseMessage.isEmpty()) status.toString() else "$baseMessage\n\n$status"

        if (!hidesDialog(activity)) {
            val negativeText = fido2PromptInfo?.negativeButtonText ?: "Cancel"
            dialog = AlertDialog.Builder(activity)
                .setTitle(fido2PromptInfo?.title ?: "Biometric Authentication")
                .setMessage(messageWith(touchSensorMessage))
                .setNegativeButton(negativeText) { _, _ -> fail(BiometricPrompt.ERROR_NEGATIVE_BUTTON, negativeText) }
                .setOnCancelListener {
                    fail(BiometricPrompt.ERROR_USER_CANCELED, "Fingerprint operation canceled by user.")
                }
                .create()
                .also { it.setCanceledOnTouchOutside(false) }
        }

        lifecycleObserver = object : DefaultLifecycleObserver {
            override fun onStop(owner: LifecycleOwner) {
                if (!activity.isChangingConfigurations) {
                    fail(BiometricPrompt.ERROR_CANCELED, "The activity left the foreground during authentication.")
                }
            }

            override fun onDestroy(owner: LifecycleOwner) {
                fail(BiometricPrompt.ERROR_CANCELED, "The activity was destroyed during authentication.")
            }
        }.also { activity.lifecycle.addObserver(it) }

        continuation.invokeOnCancellation {
            mainHandler.post {
                callbackRelay?.target = null
                if (!cancellationSignal.isCanceled) cancellationSignal.cancel()
                lifecycleObserver?.let { activity.lifecycle.removeObserver(it) }
                dialog?.setOnCancelListener(null)
                dialog?.dismiss()
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
                // The sensor keeps listening; the user may try again.
                dialog?.setMessage(
                    messageWith(activity.getString(androidx.biometric.R.string.fingerprint_not_recognized))
                )
            }

            override fun onAuthenticationHelp(helpCode: Int, helpString: CharSequence?) {
                helpString?.let { dialog?.setMessage(messageWith(it)) }
            }

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence?) {
                fail(toBiometricPromptError(errorCode), errString)
            }
        }
        val relay = CallbackRelay(callback).also { callbackRelay = it }

        // Nothing may escape this block: the caller would receive the exception while the dialog, the
        // observer and the continuation stay live, and a later fail() would resume it a second time.
        try {
            dialog?.show()
            fingerprintManager.authenticate(
                FingerprintManager.CryptoObject(signature),
                cancellationSignal,
                0,
                relay,
                mainHandler,
            )
        } catch (e: RuntimeException) {
            fail(BiometricPrompt.ERROR_HW_UNAVAILABLE, e.message, e)
        }
    }

    /**
     * Forwards platform callbacks to [target] while it is set. A [FingerprintManager] keeps the last
     * callback it was given until its next `authenticate` call, and the application context's instance
     * lives as long as the process, so the callback it holds must not keep the request's activity
     * reachable once the request has ended. [authenticate] clears [target] when it finishes or is
     * cancelled.
     */
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
