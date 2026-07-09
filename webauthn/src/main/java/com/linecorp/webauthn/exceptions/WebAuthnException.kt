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

package com.linecorp.webauthn.exceptions

import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt

sealed class WebAuthnException(override val message: String?, override val cause: Throwable? = null) :
    Exception(message, cause) {

    sealed class CoreException(message: String?, cause: Throwable? = null) : WebAuthnException(message, cause) {
        class ConstraintException(
            message: String? = "A mutation operation in a transaction failed because a constraint was not satisfied.",
            cause: Throwable? = null
        ) : CoreException(message, cause) {
            /**
             * The raw status code from BiometricManager.canAuthenticate() explaining why
             * authentication is unavailable (e.g. BIOMETRIC_ERROR_NONE_ENROLLED = 11,
             * BIOMETRIC_ERROR_NO_HARDWARE = 12, BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED = 15),
             * or null when the reason is unknown.
             */
            var capabilityStatus: Int? = null
                internal set

            /**
             * Human-readable constant name for [capabilityStatus]
             * (e.g. 11 -> "BIOMETRIC_ERROR_NONE_ENROLLED"), or null when unavailable.
             * Intended for logs and telemetry.
             */
            val capabilityStatusName: String?
                get() = capabilityStatus?.let { biometricManagerStatusName(it) }
        }
        class InvalidStateException(message: String? = "The object is in an invalid state.", cause: Throwable? = null) :
            CoreException(message, cause)
        class NotAllowedException(
            message: String? = "The request is not allowed by the user agent or the platform in the current context, " +
                "possibly because the user denied permission.",
            cause: Throwable? = null
        ) : CoreException(message, cause) {
            /**
             * The androidx.biometric BiometricPrompt error code delivered by
             * AuthenticationCallback.onAuthenticationError(errorCode, errString),
             * or null when unavailable. Use this instead of matching the localized
             * error message (errString), which varies by locale and vendor.
             *
             * Constants (androidx.biometric.BiometricPrompt, verified against 1.1.0):
             * -  1 ERROR_HW_UNAVAILABLE          hardware temporarily unavailable (retry later)
             * -  2 ERROR_UNABLE_TO_PROCESS       sensor could not process the input (retryable)
             * -  3 ERROR_TIMEOUT                 prompt timed out with no input
             * -  4 ERROR_NO_SPACE                not enough device storage
             * -  5 ERROR_CANCELED                canceled by the system/app (e.g. backgrounded)
             * -  7 ERROR_LOCKOUT                 too many attempts, temporary lockout
             * -  8 ERROR_VENDOR                  vendor-specific error
             * -  9 ERROR_LOCKOUT_PERMANENT       locked out until device credential unlock
             * - 10 ERROR_USER_CANCELED           user dismissed the prompt
             * - 11 ERROR_NO_BIOMETRICS           no biometrics enrolled
             * - 12 ERROR_HW_NOT_PRESENT          no biometric hardware
             * - 13 ERROR_NEGATIVE_BUTTON         user tapped the negative (cancel) button
             * - 14 ERROR_NO_DEVICE_CREDENTIAL    no PIN/pattern/password configured
             * - 15 ERROR_SECURITY_UPDATE_REQUIRED sensor disabled pending a security update
             */
            var errorCode: Int? = null
                internal set

            /**
             * Human-readable constant name for [errorCode]
             * (e.g. 10 -> "ERROR_USER_CANCELED"), or null when unavailable.
             * Intended for logs and telemetry.
             */
            val errorCodeName: String?
                get() = errorCode?.let { biometricPromptErrorName(it) }

            /**
             * True when this failure is a user or system cancellation of the authentication
             * prompt (ERROR_CANCELED, ERROR_USER_CANCELED, ERROR_NEGATIVE_BUTTON) rather than
             * a genuine error. Cancellations are expected user behavior and should not be
             * reported as errors in telemetry.
             */
            val isUserCancellation: Boolean
                get() = errorCode == BiometricPrompt.ERROR_CANCELED ||
                    errorCode == BiometricPrompt.ERROR_USER_CANCELED ||
                    errorCode == BiometricPrompt.ERROR_NEGATIVE_BUTTON
        }
        class NotSupportedException(message: String? = "The operation is not supported.", cause: Throwable? = null) :
            CoreException(message, cause)
        class TypeException(message: String? = null, cause: Throwable? = null) : CoreException(message, cause)
    }

    class CredSrcStorageException(message: String?, cause: Throwable? = null) : WebAuthnException(message, cause)
    class RpException(message: String? = null, cause: Throwable? = null) : WebAuthnException(message, cause)
    sealed class AuthenticationException(message: String? = null, cause: Throwable? = null) :
        WebAuthnException(message, cause) {
        class KeyPermanentlyInvalidatedException(
            message: String? =
                "The key can no longer be used. Check if a new fingerprint is enrolled or the secure lock is disabled.",
            cause: Throwable? = null
        ) : AuthenticationException(message, cause)
    }
    class SecureExecutionException(message: String? = null, cause: Throwable? = null) :
        WebAuthnException(message, cause)
    class KeyNotFoundException(message: String? = null, cause: Throwable? = null) : WebAuthnException(message, cause)
    class UnknownException(message: String, cause: Throwable? = null) : WebAuthnException(message, cause)
    class UtilityException(message: String, cause: Throwable? = null) : WebAuthnException(message, cause)
    class EncodingException(message: String, cause: Throwable? = null) : WebAuthnException(message, cause)

    /**
     * Error occurs when an exception is raised during the FIDO2 operation,
     * triggering the deletion of intermediate data,
     * but an issue arises during the deletion process.
     *
     * @param message The error message.
     * @param cause The cause of the issue during the deletion process.
     * @param trigger The exception that triggered the deletion - the original failure
     * that the caller most likely wants to diagnose.
     */
    class DeletionException(message: String, cause: Throwable? = null, val trigger: Throwable? = null) :
        WebAuthnException(message, cause)
}

/**
 * Maps an androidx.biometric.BiometricPrompt ERROR_* code to its constant name
 * (verified against biometric 1.1.0). Used for logs so services can act on the
 * failure without a lookup table.
 */
internal fun biometricPromptErrorName(code: Int): String = when (code) {
    BiometricPrompt.ERROR_HW_UNAVAILABLE -> "ERROR_HW_UNAVAILABLE"
    BiometricPrompt.ERROR_UNABLE_TO_PROCESS -> "ERROR_UNABLE_TO_PROCESS"
    BiometricPrompt.ERROR_TIMEOUT -> "ERROR_TIMEOUT"
    BiometricPrompt.ERROR_NO_SPACE -> "ERROR_NO_SPACE"
    BiometricPrompt.ERROR_CANCELED -> "ERROR_CANCELED"
    BiometricPrompt.ERROR_LOCKOUT -> "ERROR_LOCKOUT"
    BiometricPrompt.ERROR_VENDOR -> "ERROR_VENDOR"
    BiometricPrompt.ERROR_LOCKOUT_PERMANENT -> "ERROR_LOCKOUT_PERMANENT"
    BiometricPrompt.ERROR_USER_CANCELED -> "ERROR_USER_CANCELED"
    BiometricPrompt.ERROR_NO_BIOMETRICS -> "ERROR_NO_BIOMETRICS"
    BiometricPrompt.ERROR_HW_NOT_PRESENT -> "ERROR_HW_NOT_PRESENT"
    BiometricPrompt.ERROR_NEGATIVE_BUTTON -> "ERROR_NEGATIVE_BUTTON"
    BiometricPrompt.ERROR_NO_DEVICE_CREDENTIAL -> "ERROR_NO_DEVICE_CREDENTIAL"
    BiometricPrompt.ERROR_SECURITY_UPDATE_REQUIRED -> "ERROR_SECURITY_UPDATE_REQUIRED"
    else -> "UNKNOWN_ERROR"
}

/**
 * Maps an androidx.biometric.BiometricManager.canAuthenticate() status code to its
 * constant name (verified against biometric 1.1.0). Note this is a different constant
 * set from BiometricPrompt ERROR_* codes.
 */
internal fun biometricManagerStatusName(code: Int): String = when (code) {
    BiometricManager.BIOMETRIC_SUCCESS -> "BIOMETRIC_SUCCESS"
    BiometricManager.BIOMETRIC_STATUS_UNKNOWN -> "BIOMETRIC_STATUS_UNKNOWN"
    BiometricManager.BIOMETRIC_ERROR_UNSUPPORTED -> "BIOMETRIC_ERROR_UNSUPPORTED"
    BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> "BIOMETRIC_ERROR_HW_UNAVAILABLE"
    BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> "BIOMETRIC_ERROR_NONE_ENROLLED"
    BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> "BIOMETRIC_ERROR_NO_HARDWARE"
    BiometricManager.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED -> "BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED"
    else -> "UNKNOWN_STATUS"
}
