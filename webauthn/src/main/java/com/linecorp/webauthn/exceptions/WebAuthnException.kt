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

sealed class WebAuthnException(override val message: String?, override val cause: Throwable? = null) :
    Exception(message, cause) {

    sealed class CoreException(message: String?, cause: Throwable? = null) : WebAuthnException(message, cause) {
        class ConstraintException(
            message: String? = "A mutation operation in a transaction failed because a constraint was not satisfied.",
            cause: Throwable? = null
        ) : CoreException(message, cause) {
            /**
             * The `BiometricManager.canAuthenticate()` status that caused this exception, when known.
             *
             * Compare against the `BiometricManager.BIOMETRIC_*` constants; before treating
             * `BIOMETRIC_ERROR_NO_HARDWARE` as permanent, see
             * [com.linecorp.webauthn.model.AuthenticationAvailability.Reason.NO_HARDWARE]. Below API 30 the
             * device-credential path has no platform status code, so it reports
             * `BIOMETRIC_ERROR_NONE_ENROLLED` derived from `KeyguardManager.isDeviceSecure`. `null` only
             * if the authentication handler in use exposes no status at all.
             */
            var canAuthenticateStatus: Int? = null
                internal set
        }
        class InvalidStateException(message: String? = "The object is in an invalid state.", cause: Throwable? = null) :
            CoreException(message, cause)
        open class NotAllowedException(
            message: String? = "The request is not allowed by the user agent or the platform in the current context, " +
                "possibly because the user denied permission.",
            cause: Throwable? = null
        ) : CoreException(message, cause) {
            /**
             * The `BiometricPrompt.ERROR_*` code that caused this exception, when known.
             *
             * Negative values are SDK-defined and never collide with a `BiometricPrompt.ERROR_*`
             * constant; see [com.linecorp.webauthn.handler.AuthenticationHandler.ERROR_HOST_STATE_SAVED].
             * A `BiometricManager.BIOMETRIC_*` status is a different value space that overlaps numerically
             * (`BIOMETRIC_STATUS_UNKNOWN` is -1) and is reported through
             * [ConstraintException.canAuthenticateStatus], never here.
             *
             * **`errorCode == -1` is retryable.** It is
             * [com.linecorp.webauthn.handler.AuthenticationHandler.ERROR_HOST_STATE_SAVED]: the prompt was
             * never shown because the host activity had already saved its instance state, so the user was
             * given no chance to authenticate. Call `create()`/`get()` again once the host is interactive
             * rather than reporting a terminal authentication failure.
             */
            var errorCode: Int? = null
                internal set
        }

        /**
         * The user dismissed the authentication prompt: a normal outcome, not a failure to report as an
         * error. A subtype of [NotAllowedException] so existing `catch` clauses keep matching.
         */
        class UserCancelledException(
            message: String? = "The user cancelled the authentication prompt.",
            cause: Throwable? = null
        ) : NotAllowedException(message, cause)
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
    open class SecureExecutionException(message: String? = null, cause: Throwable? = null) :
        WebAuthnException(message, cause)

    /**
     * The platform keystore rejected an operation during credential creation: key generation usually, but
     * signing and the attestation certificate-chain read reach the same handler too.
     *
     * A subtype of [SecureExecutionException] rather than a new direct subclass, so that consumer `when`
     * blocks over the sealed [WebAuthnException] stay exhaustive.
     */
    class KeyGenerationException(message: String? = null, cause: Throwable? = null) :
        SecureExecutionException(message, cause) {
        /** `android.security.KeyStoreException.getNumericErrorCode()` when it could be read. */
        var keyStoreErrorCode: Int? = null
            internal set
    }
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
     * @param trigger The exception that triggered the deletion.
     */
    class DeletionException(message: String, cause: Throwable? = null, val trigger: Throwable? = null) :
        WebAuthnException(message, cause) {
        init {
            if (trigger != null && trigger !== cause && trigger !== this) {
                addSuppressed(trigger)
            }
        }
    }
}
