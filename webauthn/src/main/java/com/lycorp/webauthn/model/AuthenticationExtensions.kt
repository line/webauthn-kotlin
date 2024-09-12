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

package com.lycorp.webauthn.model

import co.nstant.`in`.cbor.builder.AbstractBuilder
import co.nstant.`in`.cbor.builder.MapBuilder

// NOTE: This file contains several dummy methods and classes.
// These are made to support authenticator extensions if they are needed in the future.
// If an authenticator extension is required, the following interfaces and methods should be properly implemented.

// AuthenticatorExtensionInput is not currently implemented. (Therefore, it is always treated as null in code now.)
interface AuthenticatorExtensionsInput : CborSerializable {
    override fun <T : AbstractBuilder<*>?> toCBOR(builder: MapBuilder<T>): T
}

class AuthenticatorExtensionsOutput : CborSerializable {
    companion object {
        fun getAuthenticatorExtensionResult(
            authenticatorExtensionsInput: AuthenticatorExtensionsInput? = null,
        ): AuthenticatorExtensionsOutput? {
            // Need to be implemented when authenticator extension is used.
            return null
        }
    }

    override fun <T : AbstractBuilder<*>?> toCBOR(builder: MapBuilder<T>): T {
        // Need to be implemented when authenticator extension is used.
        return builder.end()
    }
}

class ClientExtensionInput {

    fun processAuthenticatorExtensionsInput(): AuthenticatorExtensionsInput? {
        // Need to be implemented when authenticator extension is used.
        return null
    }

    fun processClientExtensionsOutput(): ClientExtensionsOutput {
        // Need to be implemented when client extension is used.
        return ClientExtensionsOutput()
    }
}

class ClientExtensionsOutput
