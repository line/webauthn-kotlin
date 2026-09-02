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

package com.linecorp.webauthn.authenticator.keygenerator

import com.linecorp.webauthn.model.COSEAlgorithmIdentifier
import java.security.KeyPair
import java.security.ProviderException

abstract class Fido2KeyGenerator {
    val lock = Any()

    abstract fun generateFido2Key(
        keyAlias: String,
        challenge: ByteArray?,
        publicKeyAlgorithm: COSEAlgorithmIdentifier,
        isStrongBoxBacked: Boolean,
        userAuthenticationRequired: Boolean = true
    ): KeyPair

    /**
     * Runs [generate] with StrongBox and falls back to the TEE when the platform rejects it.
     *
     * The clause is [ProviderException] rather than `StrongBoxUnavailableException`: the platform raises
     * the latter only for a hardware-type-unavailable error, while every other KeyMint rejection -
     * including the `UNIMPLEMENTED` this fallback was written for - arrives as a bare [ProviderException],
     * of which `StrongBoxUnavailableException` is itself a subclass.
     *
     * If the retry also fails, the StrongBox failure is attached to it with `addSuppressed`, which keeps
     * it in the trace and lets `Authenticator` recognise a keystore rejection that is reachable only that
     * way. When both attempts carry a keystore fault the reported error code is the retry's, because the
     * walk explores `cause` before `suppressed`.
     */
    protected fun generateWithStrongBoxFallback(
        isStrongBoxBacked: Boolean,
        generate: (strongBoxBacked: Boolean) -> KeyPair
    ): KeyPair {
        if (!isStrongBoxBacked) {
            return generate(false)
        }
        return try {
            generate(true)
        } catch (e: ProviderException) {
            // One clause covers both: StrongBoxUnavailableException is a ProviderException subclass, and
            // the fallback is identical either way.
            retryWithoutStrongBox(e, generate)
        }
    }

    private fun retryWithoutStrongBox(first: Throwable, generate: (Boolean) -> KeyPair): KeyPair = try {
        generate(false)
    } catch (second: Throwable) {
        // `addSuppressed` throws IllegalArgumentException on self-suppression, which a caller reusing one
        // exception instance for both attempts would otherwise trigger in place of the real failure.
        if (second !== first) {
            second.addSuppressed(first)
        }
        throw second
    }
}
