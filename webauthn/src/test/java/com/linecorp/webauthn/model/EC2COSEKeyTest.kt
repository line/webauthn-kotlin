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
import co.nstant.`in`.cbor.model.NegativeInteger
import com.google.common.truth.Truth.assertThat
import com.linecorp.webauthn.exceptions.WebAuthnException
import io.mockk.every
import io.mockk.mockk
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECPoint
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import co.nstant.`in`.cbor.model.Map as CborMap

class EC2COSEKeyTest {
    @Test
    fun `normalizes p256 coordinates to 32 bytes`() {
        val x = ByteArray(32) { 0x11.toByte() }
        val y = ByteArray(33) { 0x22.toByte() }.also { it[0] = 0x00 }

        val key = EC2COSEKey(
            kty = 2,
            alg = -7,
            crv = 1,
            x = x,
            y = y,
        )

        assertThat(key.x.size).isEqualTo(32)
        assertThat(key.y.size).isEqualTo(32)
        assertThat(key.y[0]).isEqualTo(0x22.toByte())
    }

    @Test
    fun `left pads short p256 coordinates with zeros`() {
        val x = ByteArray(31) { 0x11.toByte() }
        val y = byteArrayOf(0x01)

        val key = p256Key(x, y)

        assertThat(key.x).isEqualTo(ByteArray(1) + x)
        assertThat(key.y).isEqualTo(ByteArray(31) + y)
    }

    @Test
    fun `strips every redundant leading zero from p256 coordinates`() {
        val value = ByteArray(32) { 0x11.toByte() }

        val key = p256Key(ByteArray(3) + value, ByteArray(2) + value)

        assertThat(key.x).isEqualTo(value)
        assertThat(key.y).isEqualTo(value)
    }

    @Test
    fun `rejects p256 coordinates with more than 32 significant bytes`() {
        val tooLong = ByteArray(33) { 0x11.toByte() }

        assertThrows<WebAuthnException.EncodingException> { p256Key(tooLong, ByteArray(32)) }
        assertThrows<WebAuthnException.EncodingException> { p256Key(ByteArray(32), ByteArray(1) + tooLong) }
    }

    @Test
    fun `leaves coordinates of other curves unchanged`() {
        val x = ByteArray(49) { 0x11.toByte() }.also { it[0] = 0x00 }
        val y = ByteArray(47) { 0x22.toByte() }

        val key = EC2COSEKey(kty = 2, alg = -35, crv = 2, x = x, y = y)

        assertThat(key.x).isEqualTo(x)
        assertThat(key.y).isEqualTo(y)
    }

    @Test
    fun `encodes public key coordinates as 32 byte unsigned big-endian values`() {
        // BigInteger.toByteArray gives 33 bytes for affineX, whose top bit is set, and 2 bytes for affineY.
        val affineX = BigInteger.ONE.shiftLeft(255).add(BigInteger.ONE)
        val affineY = BigInteger.valueOf(0x0102)

        val key = EC2COSEKey(publicKey(affineX, affineY))

        assertThat(key.x).isEqualTo(byteArrayOf(0x80.toByte()) + ByteArray(30) + byteArrayOf(0x01))
        assertThat(key.y).isEqualTo(ByteArray(30) + byteArrayOf(0x01, 0x02))
    }

    @Test
    fun `keeps the coordinate values of generated p256 keys`() {
        val generator = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }

        repeat(256) {
            val publicKey = generator.generateKeyPair().public as ECPublicKey

            val key = EC2COSEKey(publicKey)

            assertThat(key.x).hasLength(32)
            assertThat(key.y).hasLength(32)
            assertThat(BigInteger(1, key.x)).isEqualTo(publicKey.w.affineX)
            assertThat(BigInteger(1, key.y)).isEqualTo(publicKey.w.affineY)
        }
    }

    @Test
    fun `serializes p256 coordinates as 32 byte strings`() {
        val key = EC2COSEKey(publicKey(BigInteger.ONE.shiftLeft(255), BigInteger.ONE))

        val map = CborDecoder.decode(key.toCBOR()).single() as CborMap

        assertThat((map.get(NegativeInteger(-2)) as ByteString).bytes).isEqualTo(key.x)
        assertThat((map.get(NegativeInteger(-3)) as ByteString).bytes).isEqualTo(key.y)
        assertThat(key.x).hasLength(32)
        assertThat(key.y).hasLength(32)
    }

    private fun p256Key(x: ByteArray, y: ByteArray) = EC2COSEKey(kty = 2, alg = -7, crv = 1, x = x, y = y)

    private fun publicKey(affineX: BigInteger, affineY: BigInteger) = mockk<ECPublicKey> {
        every { w } returns ECPoint(affineX, affineY)
    }
}
