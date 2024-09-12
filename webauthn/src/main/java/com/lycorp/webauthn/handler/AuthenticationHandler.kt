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

package com.lycorp.webauthn.handler

import com.lycorp.webauthn.model.Fido2PromptInfo
import com.lycorp.webauthn.model.Fido2UserAuthResult
import java.security.Signature

/**
 * Interface for handling authentication operations in a WebAuthn context.
 * Provides methods to check support for authentication and to perform authentication.
 */
interface AuthenticationHandler {

    /**
     * Checks if the current device or environment supports the required authentication methods.
     *
     * @return True if the authentication method is supported, false otherwise.
     */
    fun isSupported(): Boolean

    /**
     * Performs user authentication, optionally using a provided signature and prompt information.
     *
     * @param signatureProvider A function that provides a signature for the authentication process.
     * @param fido2PromptInfo The prompt information for FIDO2 authentication, if any.
     * @return The result of the user authentication, encapsulated in a Fido2UserAuthResult object.
     * @throws WebAuthnException If an error occurs during the authentication process.
     */
    suspend fun authenticate(signatureProvider: () -> Signature, fido2PromptInfo: Fido2PromptInfo?): Fido2UserAuthResult
}
