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
import com.google.common.truth.Truth.assertWithMessage
import com.linecorp.webauthn.exceptions.WebAuthnException
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

class EC2COSEKeyTest {

    private fun generator(curve: String) = KeyPairGenerator.getInstance("EC").apply {
        initialize(ECGenParameterSpec(curve))
    }

    @Test
    fun `every P-256 coordinate is exactly 32 bytes`() {
        val generator = generator("secp256r1")

        // BigInteger.toByteArray() is minimal-length two's-complement: roughly half of all coordinates
        // gain a 0x00 sign byte and about 1 in 256 loses a leading zero. 500 keys makes the 33-byte case
        // a certainty and the 31-byte case likely.
        repeat(500) {
            val publicKey = generator.generateKeyPair().public as ECPublicKey
            val cose = EC2COSEKey(publicKey)

            assertThat(cose.x).hasLength(32)
            assertThat(cose.y).hasLength(32)
        }
    }

    @Test
    fun `a coordinate is left-padded rather than truncated, preserving its value`() {
        val generator = generator("secp256r1")
        val publicKey = generator.generateKeyPair().public as ECPublicKey

        val cose = EC2COSEKey(publicKey)

        assertThat(BigInteger(1, cose.x)).isEqualTo(publicKey.w.affineX)
        assertThat(BigInteger(1, cose.y)).isEqualTo(publicKey.w.affineY)
    }

    /**
     * Non-vacuity guard: over a large sample the minimal-length form must actually produce the 33-byte
     * case, otherwise the sign-byte strip branch would never be exercised and the length assertions
     * above would pass on the old code too. The observed distribution is reported in the assertion
     * message so that a failure explains itself.
     */
    @Test
    fun `the minimal-length form really does emit non-32-byte coordinates`() {
        val generator = generator("secp256r1")
        val minimalLengths = mutableMapOf<Int, Int>()
        val samples = 4000

        repeat(samples) {
            val publicKey = generator.generateKeyPair().public as ECPublicKey
            val affineX = publicKey.w.affineX
            val affineY = publicKey.w.affineY
            minimalLengths.merge(affineX.toByteArray().size, 1, Int::plus)
            minimalLengths.merge(affineY.toByteArray().size, 1, Int::plus)

            val cose = EC2COSEKey(publicKey)

            assertThat(cose.x).hasLength(32)
            assertThat(cose.y).hasLength(32)
            // A truncating or sign-extending implementation cannot round-trip the numeric value.
            assertThat(BigInteger(1, cose.x)).isEqualTo(affineX)
            assertThat(BigInteger(1, cose.y)).isEqualTo(affineY)
        }

        val total = samples * 2
        val distribution = minimalLengths.toSortedMap()
            .map { (length, count) -> "$length bytes: $count (${"%.2f".format(count * 100.0 / total)}%)" }
        val message = "toByteArray() length distribution over $total P-256 coordinates: $distribution"

        // 33 bytes happens for about half of all coordinates, so it is a certainty at this sample size.
        assertWithMessage(message).that(minimalLengths.getOrDefault(33, 0)).isGreaterThan(0)
        assertWithMessage(message).that(minimalLengths.getOrDefault(32, 0)).isGreaterThan(0)
        assertWithMessage(message).that(minimalLengths.keys.max()).isAtMost(33)
    }

    /**
     * Pins the field-element length to the curve rather than to a hard-coded 32. Only the coordinate
     * length is asserted: `EC2COSEKey(ECPublicKey)` still hard-codes `alg`/`crv` to the P-256 values, and
     * the library only ever passes a P-256 key, so this is not a claim that P-384 is supported.
     */
    @Test
    fun `the coordinate length is derived from the curve field size`() {
        val publicKey = generator("secp384r1").generateKeyPair().public as ECPublicKey

        val cose = EC2COSEKey(publicKey)

        assertThat(cose.x).hasLength(48)
        assertThat(cose.y).hasLength(48)
        assertThat(BigInteger(1, cose.x)).isEqualTo(publicKey.w.affineX)
    }

    // The cases below exercise toSec1FieldElement directly. Through EC2COSEKey(ECPublicKey) the padding
    // branch is only reachable probabilistically and the rejection branches are not reachable at all,
    // because the length is derived from the very key that produced the coordinate.

    @Test
    fun `a short field element is left-padded to the curve length`() {
        val value = BigInteger(1, ByteArray(31) { 0x01 })

        val encoded = value.toSec1FieldElement(32)

        assertThat(encoded).hasLength(32)
        assertThat(encoded[0]).isEqualTo(0x00.toByte())
        assertThat(encoded[1]).isEqualTo(0x01.toByte())
        assertThat(BigInteger(1, encoded)).isEqualTo(value)
    }

    @Test
    fun `a field element that is already the curve length is unchanged`() {
        val value = BigInteger(1, ByteArray(32) { 0x01 })

        val encoded = value.toSec1FieldElement(32)

        assertThat(encoded).isEqualTo(ByteArray(32) { 0x01 })
    }

    @Test
    fun `the two's-complement sign byte is stripped`() {
        // A coordinate whose high bit is set: toByteArray() returns 33 bytes with a leading 0x00.
        val value = BigInteger(1, ByteArray(32) { 0xFF.toByte() })
        assertThat(value.toByteArray()).hasLength(33)

        val encoded = value.toSec1FieldElement(32)

        assertThat(encoded).isEqualTo(ByteArray(32) { 0xFF.toByte() })
        assertThat(BigInteger(1, encoded)).isEqualTo(value)
    }

    @Test
    fun `an oversized field element whose extra byte is not a sign byte is rejected`() {
        val value = BigInteger(1, ByteArray(33) { 0x01 })

        val exception = assertThrows<WebAuthnException.EncodingException> {
            value.toSec1FieldElement(32)
        }

        assertThat(exception).hasMessageThat().contains("does not fit a 32-byte field element")
    }

    @Test
    fun `a field element from the wrong curve is rejected rather than truncated`() {
        val value = BigInteger(1, ByteArray(48) { 0x01 })

        val exception = assertThrows<WebAuthnException.EncodingException> {
            value.toSec1FieldElement(32)
        }

        assertThat(exception).hasMessageThat().contains("48 bytes")
    }

    @Test
    fun `a negative field element is rejected rather than zero-padded`() {
        // Without the sign check this would be zero-padded into a completely different number.
        val value = BigInteger.valueOf(-1)

        val exception = assertThrows<WebAuthnException.EncodingException> {
            value.toSec1FieldElement(32)
        }

        assertThat(exception).hasMessageThat().contains("cannot be negative")
    }
}
