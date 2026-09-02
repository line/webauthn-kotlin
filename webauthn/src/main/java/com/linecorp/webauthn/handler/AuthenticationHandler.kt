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

import android.content.Context
import androidx.fragment.app.FragmentActivity
import com.linecorp.webauthn.model.Fido2PromptInfo
import com.linecorp.webauthn.model.Fido2UserAuthResult
import java.security.Signature

/**
 * Interface for handling authentication operations in a WebAuthn context.
 * Provides methods to check support for authentication and to perform authentication.
 */
interface AuthenticationHandler {

    class AuthenticationFailedException(val errorCode: Int? = null, message: String? = null, cause: Throwable? = null) :
        Exception(message, cause)
    class AuthenticationErrorException(val errorCode: Int? = null, message: String? = null, cause: Throwable? = null) :
        Exception(message, cause)

    /**
     * Checks if the current device or environment supports the required authentication methods.
     *
     * @param context The activity context used for UI operations.
     * @return True if the authentication method is supported, false otherwise.
     */
    fun isSupported(context: Context): Boolean

    /**
     * Performs user authentication, optionally using a provided signature and prompt information.
     *
     * @param activity The activity context used for UI operations.
     * @param fido2PromptInfo The prompt information for FIDO2 authentication, if any.
     * @param signatureProvider A function that provides a signature for the authentication process.
     * @return The result of the user authentication, encapsulated in a Fido2UserAuthResult object.
     * @throws WebAuthnException If an error occurs during the authentication process.
     */
    suspend fun authenticate(
        activity: FragmentActivity,
        fido2PromptInfo: Fido2PromptInfo?,
        signatureProvider: (() -> Signature)? = null
    ): Fido2UserAuthResult
}

/**
 * Exposes the raw platform status behind [AuthenticationHandler.isSupported].
 *
 * A separate interface, not a member of [AuthenticationHandler]: adding one there would break every Java
 * implementor.
 */
internal interface AuthenticationCapability {
    fun canAuthenticateStatus(context: Context): Int
}
