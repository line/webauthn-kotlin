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

package com.linecorp.webauthn.model

import co.nstant.`in`.cbor.CborBuilder
import co.nstant.`in`.cbor.CborEncoder
import co.nstant.`in`.cbor.builder.AbstractBuilder
import co.nstant.`in`.cbor.builder.MapBuilder
import com.linecorp.webauthn.exceptions.WebAuthnException
import java.io.ByteArrayOutputStream

interface CborSerializable {
    fun <T : AbstractBuilder<*>?> toCBOR(builder: MapBuilder<T>): T

    /**
     * Encodes this value as CBOR.
     *
     * @param canonical When true (the default) the map is definite-length, which WebAuthn Level 2
     * section 2.4 requires via the CTAP2 canonical CBOR encoding form. `CborEncoder` is canonical by
     * default, so it additionally sorts map keys per RFC 7049 section 3.9 — shorter encoded key first,
     * then bytewise — which is not CTAP2's rule (that also sorts a lower major type first), but the two
     * coincide for every map this SDK emits: the attestation object's keys are all text strings, and the
     * COSE labels 1, 3, -1, -2, -3 encode to 01 03 20 21 22. When false the indefinite-length form is
     * emitted; that is a diagnostic switch, not reachable from any public API.
     */
    fun toCBOR(canonical: Boolean = true): ByteArray = encodeToCborBytes {
        toCBOR(CborBuilder().let { if (canonical) it.addMap() else it.startMap() })
    }
}

/**
 * Encodes the CBOR map that [fillMap] builds, returning the encoded bytes.
 *
 * [fillMap] is invoked inside the `try` so that a failure while writing the entries is also reported as
 * [WebAuthnException.EncodingException]; that is why this takes a lambda and not a built map.
 */
internal fun encodeToCborBytes(fillMap: () -> CborBuilder): ByteArray {
    try {
        val baos = ByteArrayOutputStream()
        CborEncoder(baos).encode(fillMap().build())
        return baos.toByteArray()
    } catch (e: Exception) {
        throw WebAuthnException.EncodingException("Cannot convert Attestation Object to CBOR.", e)
    }
}
