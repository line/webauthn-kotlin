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

import com.google.common.truth.Truth.assertThat
import org.junit.jupiter.api.Test

class CborEncodingTest {

    private fun ByteArray.hex(): String = joinToString("") { "%02x".format(it) }

    private fun noneAttestationObject() = AttestationObject(
        authData = byteArrayOf(1, 2),
        fmt = AttestationStatementFormat.NONE.value,
        attStmt = NoneAttestationStatement(),
    )

    private fun androidKeyAttestationObject() = AttestationObject(
        authData = byteArrayOf(1, 2),
        fmt = AttestationStatementFormat.ANDROID_KEY.value,
        attStmt = AndroidKeyAttestationStatement(
            alg = -7,
            sig = byteArrayOf(0x0a, 0x0b),
            x5c = listOf(byteArrayOf(0x0c), byteArrayOf(0x0d)),
        ),
    )

    private val canonicalAndroidKey =
        "a363666d746b616e64726f69642d6b65796761747453746d74a363616c672663736967420a0b" +
            "6378356382410c410d686175746844617461420102"

    private val pre120AndroidKey =
        "bf68617574684461746142010263666d746b616e64726f69642d6b65796761747453746d74bf" +
            "63616c672663736967420a0b6378356382410c410dffff"

    @Test
    fun `an attestation object encodes as a definite-length map`() {
        val attestationObject = noneAttestationObject()

        val encoded = attestationObject.toCBOR()

        // a3 = map(3 pairs). The previous startMap() form emitted bf ... ff (indefinite length),
        // which WebAuthn Level 2 section 2.4 disallows: it requires CTAP2 canonical CBOR.
        assertThat(encoded.first()).isEqualTo(0xa3.toByte())
        assertThat(encoded.last()).isNotEqualTo(0xff.toByte())
        // CborEncoder is canonical by default, so a definite-length map also gets the RFC 7049 key
        // ordering: length first, then bytewise, which puts fmt (3) before attStmt (7) before
        // authData (8). For these all-text-string keys that is also CTAP2 order.
        assertThat(encoded.hex()).isEqualTo("a363666d74646e6f6e656761747453746d74a0686175746844617461420102")
    }

    @Test
    fun `the non-canonical switch reproduces the pre-1_2_0 none attestation object`() {
        val attestationObject = noneAttestationObject()

        val encoded = attestationObject.toCBOR(canonical = false)

        assertThat(encoded.first()).isEqualTo(0xbf.toByte())
        assertThat(encoded.last()).isEqualTo(0xff.toByte())
        // Byte-for-byte what 1.1.3 emitted: indefinite outer map, keys in insertion order, and an empty
        // definite attStmt (a0), which is what the none branch has always written.
        assertThat(encoded.hex()).isEqualTo("bf68617574684461746142010263666d74646e6f6e656761747453746d74a0ff")
    }

    @Test
    fun `a COSE key map keeps its payload and key order when switched to definite length`() {
        val x = ByteArray(32) { 0xAA.toByte() }
        val y = ByteArray(32) { 0xBB.toByte() }
        val key = EC2COSEKey(kty = 2, alg = -7, crv = 1, x = x, y = y)

        val canonicalBytes = key.toCBOR()
        val canonical = canonicalBytes.hex()
        val legacy = key.toCBOR(canonical = false).hex()

        assertThat(canonical).startsWith("a5")
        assertThat(legacy).startsWith("bf")
        // Only the map header and the break byte differ; keys stay in order 1, 3, -1, -2, -3.
        assertThat(canonical.removePrefix("a5")).isEqualTo(legacy.removePrefix("bf").removeSuffix("ff"))
        // Asserted on the byte, not on the hex: "ff" in a hex string can also match across a byte pair.
        assertThat(canonicalBytes.last()).isNotEqualTo(0xff.toByte())
    }

    @Test
    fun `an android-key attestation object is definite-length at every level`() {
        val attestationObject = androidKeyAttestationObject()

        val encoded = attestationObject.toCBOR()

        assertThat(encoded.first()).isEqualTo(0xa3.toByte())
        assertThat(encoded.last()).isNotEqualTo(0xff.toByte())
        // The nested attStmt map must be definite too: "attStmt" is immediately followed by a3, not bf.
        // AttestationObject built it with startMap("attStmt") before, which left a bf ... ff inside an
        // otherwise conformant attestation object.
        assertThat(encoded.hex()).contains("6761747453746d74a3")
        assertThat(encoded.hex()).doesNotContain("6761747453746d74bf")
        // putArray already emits a definite-length array, so x5c is 82 (array of 2).
        assertThat(encoded.hex()).contains("6378356382410c410d")
        assertThat(encoded.hex()).isEqualTo(canonicalAndroidKey)
    }

    @Test
    fun `the non-canonical switch reproduces the pre-1_2_0 android-key attestation object`() {
        val attestationObject = androidKeyAttestationObject()

        val encoded = attestationObject.toCBOR(canonical = false)

        // canonical must revert every level, otherwise the diagnostic emits a byte string no released
        // build ever produced and an experiment against a relying party proves nothing. Both maps are
        // indefinite here, so the encoding ends in two break bytes.
        assertThat(encoded.first()).isEqualTo(0xbf.toByte())
        assertThat(encoded.hex()).contains("6761747453746d74bf")
        assertThat(encoded.hex()).endsWith("ffff")
        // Byte-for-byte what 1.1.3 emitted.
        assertThat(encoded.hex()).isEqualTo(pre120AndroidKey)
    }

    /**
     * `AttestationObject` overrides `toCBOR(canonical)` instead of adding a member to
     * `CborSerializable`. A default argument is resolved against the static type but the call still
     * dispatches virtually, so the override must be reached either way. Pinned rather than assumed.
     */
    @Test
    fun `the no-argument call reaches the override from either static type`() {
        val concrete = androidKeyAttestationObject()
        val asInterface: CborSerializable = androidKeyAttestationObject()

        val fromConcrete = concrete.toCBOR()
        val fromInterface = asInterface.toCBOR()

        assertThat(fromConcrete.hex()).isEqualTo(fromInterface.hex())
        assertThat(fromConcrete.hex()).isEqualTo(canonicalAndroidKey)
    }

    @Test
    fun `the non-canonical call reaches the override from either static type`() {
        val concrete = androidKeyAttestationObject()
        val asInterface: CborSerializable = androidKeyAttestationObject()

        // This is the case that would silently regress if dispatch landed in the interface default: the
        // nested attStmt map would come out definite (a3) and these would not be the 1.1.3 bytes.
        assertThat(concrete.toCBOR(canonical = false).hex()).isEqualTo(pre120AndroidKey)
        assertThat(asInterface.toCBOR(canonical = false).hex()).isEqualTo(pre120AndroidKey)
    }
}
