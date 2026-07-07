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
import java.io.ByteArrayInputStream
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import org.junit.jupiter.api.Test
import co.nstant.`in`.cbor.model.Map as CborMap

class EC2COSEKeyTest {

    private fun fakeEcPublicKey(x: BigInteger, y: BigInteger): ECPublicKey {
        val parameterSpec = AlgorithmParameters.getInstance("EC").apply {
            init(ECGenParameterSpec("secp256r1"))
        }.getParameterSpec(ECParameterSpec::class.java)

        return object : ECPublicKey {
            override fun getAlgorithm(): String = "EC"
            override fun getFormat(): String = "X.509"
            override fun getEncoded(): ByteArray = ByteArray(0)
            override fun getParams(): ECParameterSpec = parameterSpec
            override fun getW(): ECPoint = ECPoint(x, y)
        }
    }

    private fun decodeCoordinates(cbor: ByteArray): Pair<ByteArray, ByteArray> {
        val map = CborDecoder(ByteArrayInputStream(cbor)).decode()[0] as CborMap
        val x = (map.get(NegativeInteger(-2)) as ByteString).bytes
        val y = (map.get(NegativeInteger(-3)) as ByteString).bytes
        return Pair(x, y)
    }

    @Test
    fun `coordinate with top bit set is encoded as exactly 32 bytes`() {
        // BigInteger.toByteArray() would return 33 bytes (0x00 sign byte) for this value.
        val topBitSet = BigInteger(1, ByteArray(32) { 0xFF.toByte() })
        val cbor = EC2COSEKey(fakeEcPublicKey(topBitSet, topBitSet)).toCBOR()

        val (x, y) = decodeCoordinates(cbor)
        assertThat(x).hasLength(32)
        assertThat(y).hasLength(32)
        assertThat(x).isEqualTo(ByteArray(32) { 0xFF.toByte() })
    }

    @Test
    fun `coordinate with leading zero octets is padded to exactly 32 bytes`() {
        // BigInteger.toByteArray() would return a single byte for this value.
        val small = BigInteger.ONE
        val cbor = EC2COSEKey(fakeEcPublicKey(small, small)).toCBOR()

        val (x, y) = decodeCoordinates(cbor)
        assertThat(x).hasLength(32)
        assertThat(y).hasLength(32)
        assertThat(x[31]).isEqualTo(1.toByte())
        assertThat(x.copyOfRange(0, 31)).isEqualTo(ByteArray(31))
    }

    @Test
    fun `cose key is encoded as a definite-length map`() {
        val value = BigInteger(1, ByteArray(32) { 0x42 })
        val cbor = EC2COSEKey(fakeEcPublicKey(value, value)).toCBOR()

        // A definite-length CBOR map with 5 entries starts with 0xA5.
        // The indefinite-length form (0xBF) violates the CTAP2 canonical encoding.
        assertThat(cbor[0]).isEqualTo(0xA5.toByte())
    }
}
