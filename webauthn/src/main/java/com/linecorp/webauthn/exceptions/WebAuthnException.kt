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
        }
        class InvalidStateException(message: String? = "The object is in an invalid state.", cause: Throwable? = null) :
            CoreException(message, cause)
        class NotAllowedException(
            message: String? = "The request is not allowed by the user agent or the platform in the current context, " +
                "possibly because the user denied permission.",
            cause: Throwable? = null
        ) : CoreException(message, cause) {
            /**
             * The androidx.biometric BiometricPrompt error code that caused this failure
             * (e.g. ERROR_USER_CANCELED = 10, ERROR_LOCKOUT = 7), or null when unavailable.
             * Use this instead of matching the localized error message.
             */
            var errorCode: Int? = null
                internal set

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
