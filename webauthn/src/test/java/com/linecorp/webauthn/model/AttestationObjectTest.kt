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

import co.nstant.`in`.cbor.CborDecoder
import co.nstant.`in`.cbor.model.ByteString
import co.nstant.`in`.cbor.model.UnicodeString
import com.google.common.truth.Truth.assertThat
import java.io.ByteArrayInputStream
import org.junit.jupiter.api.Test
import co.nstant.`in`.cbor.model.Map as CborMap

class AttestationObjectTest {

    @Test
    fun `android-key attestation object and its nested attStmt are definite-length maps`() {
        val authData = ByteArray(37) { it.toByte() }
        val attStmt = AndroidKeyAttestationStatement(
            alg = -7L,
            sig = byteArrayOf(1, 2, 3),
            x5c = listOf(byteArrayOf(4, 5, 6)),
        )
        val attestationObject = AttestationObject(authData, AttestationStatementFormat.ANDROID_KEY.value, attStmt)

        val cbor = attestationObject.toCBOR()
        val outerMap = CborDecoder(ByteArrayInputStream(cbor)).decode()[0] as CborMap

        // Indefinite-length (chunked) maps violate the CTAP2 canonical CBOR encoding form.
        assertThat(outerMap.isChunked).isFalse()
        assertThat((outerMap.get(UnicodeString("authData")) as ByteString).bytes).isEqualTo(authData)
        assertThat((outerMap.get(UnicodeString("fmt")) as UnicodeString).string)
            .isEqualTo(AttestationStatementFormat.ANDROID_KEY.value)

        val nestedAttStmt = outerMap.get(UnicodeString("attStmt")) as CborMap
        assertThat(nestedAttStmt.isChunked).isFalse()
        assertThat((nestedAttStmt.get(UnicodeString("sig")) as ByteString).bytes).isEqualTo(byteArrayOf(1, 2, 3))
    }

    @Test
    fun `none attestation object encodes an empty definite-length attStmt map`() {
        val attestationObject = AttestationObject(
            ByteArray(1),
            AttestationStatementFormat.NONE.value,
            NoneAttestationStatement(),
        )

        val cbor = attestationObject.toCBOR()
        val outerMap = CborDecoder(ByteArrayInputStream(cbor)).decode()[0] as CborMap

        assertThat(outerMap.isChunked).isFalse()

        val nestedAttStmt = outerMap.get(UnicodeString("attStmt")) as CborMap
        assertThat(nestedAttStmt.isChunked).isFalse()
        assertThat(nestedAttStmt.keys).isEmpty()
    }
}
