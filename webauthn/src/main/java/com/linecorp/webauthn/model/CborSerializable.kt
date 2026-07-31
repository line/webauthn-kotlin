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
     * default, so it additionally sorts the map keys per RFC 7049 section 3.9: shorter encoded key
     * first, then bytewise. That rule is not identical to CTAP2's, which also sorts a lower major type
     * first, but the two coincide for every map this SDK emits — the attestation object's keys are all
     * text strings, and the COSE key labels 1, 3, -1, -2, -3 encode to 01 03 20 21 22, which is the
     * same order under either rule.
     *
     * When false the pre-1.2.0 indefinite-length form is emitted, so the CBOR framing — map headers, key
     * order and break bytes — is the framing released builds produced. This is a diagnostic switch for
     * identifying a relying party that cannot accept the conformant encoding, not a rollback path: it is
     * not reachable from any public API, so using it means editing the call sites and republishing the
     * artifact, and it does not restore the pre-1.2.0 EC coordinate encoding that the framing wraps.
     * Reverting the change that introduced this is both cheaper and more complete.
     *
     * [AttestationObject] overrides this, because it is the only implementation that nests a map and so
     * the only one for which [canonical] has to reach further than the top-level map.
     */
    fun toCBOR(canonical: Boolean = true): ByteArray = encodeToCborBytes {
        toCBOR(CborBuilder().let { if (canonical) it.addMap() else it.startMap() })
    }
}

/**
 * Encodes the CBOR map that [fillMap] builds, returning the encoded bytes.
 *
 * Shared by [CborSerializable.toCBOR] and by [AttestationObject]'s override of it, so that the encoder
 * setup and the failure message exist in one place rather than being kept in step by hand.
 *
 * [fillMap] is invoked inside the `try` on purpose: writing the entries has always been covered by this
 * wrapping, so a failure there is reported as an [WebAuthnException.EncodingException] rather than
 * escaping raw. That is why this takes a lambda instead of an already-filled builder as its receiver.
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
