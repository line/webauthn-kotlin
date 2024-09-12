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

package com.lycorp.webauthn.exceptions

sealed class WebAuthnException(
    override val message: String?,
    override val cause: Throwable? = null
) : Exception(message, cause) {

    sealed class CoreException(message: String?, cause: Throwable? = null) : WebAuthnException(message, cause) {
        class ConstraintException(
            message: String? = "A mutation operation in a transaction failed because a constraint was not satisfied.",
            cause: Throwable? = null
        ) : CoreException(message, cause)
        class InvalidStateException(
            message: String? = "The object is in an invalid state.",
            cause: Throwable? = null
        ) : CoreException(message, cause)
        class NotAllowedException(
            message: String? = "The request is not allowed by the user agent or the platform in the current context, " +
                "possibly because the user denied permission.",
            cause: Throwable? = null
        ) : CoreException(message, cause)
        class NotSupportedException(
            message: String? = "The operation is not supported.",
            cause: Throwable? = null
        ) : CoreException(message, cause)
        class TypeException(
            message: String? = null,
            cause: Throwable? = null
        ) : CoreException(message, cause)
    }

    class CredSrcStorageException(message: String?, cause: Throwable? = null) : WebAuthnException(message, cause)
    class RpException(message: String? = null, cause: Throwable? = null) : WebAuthnException(message, cause)
    class AuthenticationException(
        message: String? = null,
        cause: Throwable? = null
    ) : WebAuthnException(message, cause)
    class SecureExecutionException(
        message: String? = null,
        cause: Throwable? = null
    ) : WebAuthnException(message, cause)
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
    class DeletionException(
        message: String,
        cause: Throwable? = null,
        trigger: Throwable? = null
    ) : WebAuthnException(message, cause)
}
