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
import java.security.spec.ECGenParameterSpec
import org.junit.jupiter.api.Test

class COSEAlgorithmIdentifierTest {

    @Test
    fun `values match the IANA COSE Algorithms registry`() {
        assertThat(COSEAlgorithmIdentifier.RS1.value).isEqualTo(-65535L)
        assertThat(COSEAlgorithmIdentifier.RS256.value).isEqualTo(-257L)
        assertThat(COSEAlgorithmIdentifier.RS384.value).isEqualTo(-258L)
        assertThat(COSEAlgorithmIdentifier.RS512.value).isEqualTo(-259L)
        assertThat(COSEAlgorithmIdentifier.PS256.value).isEqualTo(-37L)
        assertThat(COSEAlgorithmIdentifier.PS384.value).isEqualTo(-38L)
        assertThat(COSEAlgorithmIdentifier.PS512.value).isEqualTo(-39L)
        assertThat(COSEAlgorithmIdentifier.EdDSA.value).isEqualTo(-8L)
        assertThat(COSEAlgorithmIdentifier.ES256.value).isEqualTo(-7L)
        assertThat(COSEAlgorithmIdentifier.ES384.value).isEqualTo(-35L)
        assertThat(COSEAlgorithmIdentifier.ES512.value).isEqualTo(-36L)
        // RFC 8812. -43 is SHA-384 in the same registry, so the two are not interchangeable.
        assertThat(COSEAlgorithmIdentifier.ES256K.value).isEqualTo(-47L)
    }

    @Test
    fun `fromValue resolves every entry by its registered value`() {
        COSEAlgorithmIdentifier.entries.forEach {
            assertThat(COSEAlgorithmIdentifier.fromValue(it.value)).isEqualTo(it)
        }
    }

    @Test
    fun `every EC algorithm names the curve it is defined over`() {
        // The names are pinned as literals rather than resolved through a provider: the SDK targets
        // AndroidKeyStore, and the JVM the unit tests run on does not carry the same curve set (SunEC
        // dropped secp256k1 in JDK 16). A typo here surfaces only on-device as
        // InvalidAlgorithmParameterException at key generation, which is what happened to ES512.
        val curves = mapOf(
            COSEAlgorithmIdentifier.ES256 to "secp256r1",
            COSEAlgorithmIdentifier.ES384 to "secp384r1",
            COSEAlgorithmIdentifier.ES512 to "secp521r1",
            COSEAlgorithmIdentifier.ES256K to "secp256k1",
        )
        curves.forEach { (algorithm, expectedCurve) ->
            val spec = algorithm.getAlgorithmParameterSpec()
            assertThat(spec).isInstanceOf(ECGenParameterSpec::class.java)
            assertThat((spec as ECGenParameterSpec).name).isEqualTo(expectedCurve)
        }
    }

    @Test
    fun `only the EC algorithms carry a curve`() {
        val withoutCurve = listOf(
            COSEAlgorithmIdentifier.RS1,
            COSEAlgorithmIdentifier.RS256,
            COSEAlgorithmIdentifier.RS384,
            COSEAlgorithmIdentifier.RS512,
            COSEAlgorithmIdentifier.PS256,
            COSEAlgorithmIdentifier.PS384,
            COSEAlgorithmIdentifier.PS512,
            COSEAlgorithmIdentifier.EdDSA,
        )
        withoutCurve.forEach { assertThat(it.getAlgorithmParameterSpec()).isNull() }
    }
}
