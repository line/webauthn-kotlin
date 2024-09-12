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

import android.security.keystore.KeyProperties
import co.nstant.`in`.cbor.builder.AbstractBuilder
import co.nstant.`in`.cbor.builder.MapBuilder
import java.security.spec.AlgorithmParameterSpec
import java.security.spec.ECGenParameterSpec

data class AttestationStatement(
    val alg: Long,
    val sig: ByteArray,
    val x5c: List<ByteArray>,
) : CborSerializable {
    override fun <T : AbstractBuilder<*>?> toCBOR(builder: MapBuilder<T>): T {
        return builder
            .put("alg", alg)
            .put("sig", sig)
            .putArray("x5c").also {
                for (i in x5c) {
                    it.add(i)
                }
            }
            .end()
            .end()
    }
}

enum class AttestationStatementFormats(val value: String) {
    PACKED("packed"),
    TPM("tpm"),
    ANDROID_KEY("android-key"),
    ANDROID_SAFETYNET("android-safetynet"),
    FIDO_U2F("fido-u2f"),
}

enum class COSEAlgorithmIdentifier(val value: Long) {
    RS1(-65535), // RSASSA-PKCS1-v1_5 with SHA-1
    RS256(-257), // RSASSA-PKCS1-v1_5 with SHA-256
    RS384(-258), // RSASSA-PKCS1-v1_5 with SHA-384
    RS512(-259), // RSASSA-PKCS1-v1_5 with SHA-512
    PS256(-37), // RSASSA-PSS with SHA-256
    PS384(-38), // RSASSA-PSS with SHA-384
    PS512(-39), // RSASSA-PSS with SHA-512
    EdDSA(-8), // EdDSA
    ES256(-7), // ECDSA with SHA-256
    ES384(-35), // ECDSA with SHA-384
    ES512(-36), // ECDSA with SHA-512
    ES256K(-43), // ECDSA using P-256K and SHA-256
    ;

    companion object {
        fun fromValue(value: Long): COSEAlgorithmIdentifier? {
            return COSEAlgorithmIdentifier.values().find { it.value == value }
        }
    }
}
fun COSEAlgorithmIdentifier.getSignatureAlgorithmName(): String? {
    val correspondingSignatureAlgorithm = SignatureAlgorithms.values().find { it.name == this.name }
    return correspondingSignatureAlgorithm?.algName
}

fun COSEAlgorithmIdentifier.getDigests(): String? {
    return when (this) {
        COSEAlgorithmIdentifier.RS1 -> KeyProperties.DIGEST_SHA1
        COSEAlgorithmIdentifier.RS256 -> KeyProperties.DIGEST_SHA256
        COSEAlgorithmIdentifier.RS384 -> KeyProperties.DIGEST_SHA384
        COSEAlgorithmIdentifier.RS512 -> KeyProperties.DIGEST_SHA512
        COSEAlgorithmIdentifier.PS256 -> KeyProperties.DIGEST_SHA256
        COSEAlgorithmIdentifier.PS384 -> KeyProperties.DIGEST_SHA384
        COSEAlgorithmIdentifier.PS512 -> KeyProperties.DIGEST_SHA512
        COSEAlgorithmIdentifier.EdDSA -> KeyProperties.DIGEST_SHA512
        COSEAlgorithmIdentifier.ES256 -> KeyProperties.DIGEST_SHA256
        COSEAlgorithmIdentifier.ES384 -> KeyProperties.DIGEST_SHA384
        COSEAlgorithmIdentifier.ES512 -> KeyProperties.DIGEST_SHA512
        COSEAlgorithmIdentifier.ES256K -> KeyProperties.DIGEST_SHA256
    }
}

fun COSEAlgorithmIdentifier.getSignaturePaddings(): String? {
    return when (this) {
        COSEAlgorithmIdentifier.RS1 -> KeyProperties.SIGNATURE_PADDING_RSA_PKCS1
        COSEAlgorithmIdentifier.RS256 -> KeyProperties.SIGNATURE_PADDING_RSA_PKCS1
        COSEAlgorithmIdentifier.RS384 -> KeyProperties.SIGNATURE_PADDING_RSA_PKCS1
        COSEAlgorithmIdentifier.RS512 -> KeyProperties.SIGNATURE_PADDING_RSA_PKCS1
        COSEAlgorithmIdentifier.PS256 -> KeyProperties.SIGNATURE_PADDING_RSA_PSS
        COSEAlgorithmIdentifier.PS384 -> KeyProperties.SIGNATURE_PADDING_RSA_PSS
        COSEAlgorithmIdentifier.PS512 -> KeyProperties.SIGNATURE_PADDING_RSA_PSS
        COSEAlgorithmIdentifier.EdDSA -> null
        COSEAlgorithmIdentifier.ES256 -> null
        COSEAlgorithmIdentifier.ES384 -> null
        COSEAlgorithmIdentifier.ES512 -> null
        COSEAlgorithmIdentifier.ES256K -> null
    }
}

fun COSEAlgorithmIdentifier.getAlgorithmParameterSpec(): AlgorithmParameterSpec? {
    return when (this) {
        COSEAlgorithmIdentifier.RS1 -> null
        COSEAlgorithmIdentifier.RS256 -> null
        COSEAlgorithmIdentifier.RS384 -> null
        COSEAlgorithmIdentifier.RS512 -> null
        COSEAlgorithmIdentifier.PS256 -> null
        COSEAlgorithmIdentifier.PS384 -> null
        COSEAlgorithmIdentifier.PS512 -> null
        COSEAlgorithmIdentifier.EdDSA -> null
        COSEAlgorithmIdentifier.ES256 -> ECGenParameterSpec("secp256r1")
        COSEAlgorithmIdentifier.ES384 -> ECGenParameterSpec("secp384r1")
        COSEAlgorithmIdentifier.ES512 -> ECGenParameterSpec("secp512r1")
        COSEAlgorithmIdentifier.ES256K -> ECGenParameterSpec("secp256k1")
    }
}

fun COSEAlgorithmIdentifier.getKeyProperties(): String? {
    return when (this) {
        COSEAlgorithmIdentifier.RS1 -> KeyProperties.KEY_ALGORITHM_RSA
        COSEAlgorithmIdentifier.RS256 -> KeyProperties.KEY_ALGORITHM_RSA
        COSEAlgorithmIdentifier.RS384 -> KeyProperties.KEY_ALGORITHM_RSA
        COSEAlgorithmIdentifier.RS512 -> KeyProperties.KEY_ALGORITHM_RSA
        COSEAlgorithmIdentifier.PS256 -> KeyProperties.KEY_ALGORITHM_RSA
        COSEAlgorithmIdentifier.PS384 -> KeyProperties.KEY_ALGORITHM_RSA
        COSEAlgorithmIdentifier.PS512 -> KeyProperties.KEY_ALGORITHM_RSA
        COSEAlgorithmIdentifier.EdDSA -> KeyProperties.KEY_ALGORITHM_EC
        COSEAlgorithmIdentifier.ES256 -> KeyProperties.KEY_ALGORITHM_EC
        COSEAlgorithmIdentifier.ES384 -> KeyProperties.KEY_ALGORITHM_EC
        COSEAlgorithmIdentifier.ES512 -> KeyProperties.KEY_ALGORITHM_EC
        COSEAlgorithmIdentifier.ES256K -> KeyProperties.KEY_ALGORITHM_EC
    }
}

enum class SignatureAlgorithms(val algName: String) {
    RS1("SHA1withRSA"),
    RS256("SHA256withRSA"),
    RS384("SHA384withRSA"),
    RS512("SHA512withRSA"),
    PS256("SHA256withRSA/PSS"),
    PS384("SHA384withRSA/PSS"),
    PS512("SHA512withRSA/PSS"),
    EdDSA("EdDSA"),
    ES256("SHA256withECDSA"),
    ES384("SHA384withECDSA"),
    ES512("SHA512withECDSA"),
    ES256K("SHA256withECDSAinP256K"),
}
