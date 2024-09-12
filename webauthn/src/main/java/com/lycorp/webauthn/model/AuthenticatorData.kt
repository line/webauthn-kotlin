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

import co.nstant.`in`.cbor.builder.AbstractBuilder
import co.nstant.`in`.cbor.builder.MapBuilder
import com.lycorp.webauthn.exceptions.WebAuthnException
import java.nio.ByteBuffer
import java.security.interfaces.ECPublicKey

/**
 * Represents Authenticator Data in the WebAuthn process.
 *
 * This class corresponds to the authenticator data as defined in the Web Authentication: An API for accessing Public Key Credentials Level 2 specification.
 * For more details, see the specification: [Web Authentication: Level 2 - Authenticator Data](https://www.w3.org/TR/webauthn-2/#authenticator-data)
 *
 * AuthenticatorData:
 * | rpIdHash |  flags  | signCount | attestedCredData |  extensions   |
 * |----------|---------|-----------|------------------|---------------|
 * | 32 bytes | 1 byte  |  4 bytes  |  variable size   | variable size |
 */
data class AuthenticatorData(
    val rpIdHash: ByteArray,
    var flags: UByte,
    val signCount: UInt,
    val attestedCredData: ByteArray? = null,
    val extensions: ByteArray? = null,
) {
    fun toByteArray(): ByteArray {
        if (attestedCredData != null) {
            val atFlag = AuthenticatorDataFlags.AT.value
            flags = flags or atFlag
        }
        if (extensions != null) {
            val edFlag = AuthenticatorDataFlags.ED.value
            flags = flags or edFlag
        }

        try {
            return ByteBuffer.allocate(
                rpIdHash.size +
                    1 +
                    4 +
                    (attestedCredData?.size ?: 0) +
                    (extensions?.size ?: 0),
            ).apply {
                put(rpIdHash)
                put(flags.toByte())
                putInt(signCount.toInt())
                attestedCredData?.let { put(it) }
                extensions?.let { put(it) }
            }.array()
        } catch (e: Exception) {
            throw WebAuthnException.EncodingException("Cannot convert AuthenticatorData to ByteArray", e)
        }
    }
}

/**
 * Represents Attested Credential Data in the WebAuthn process.
 *
 * This class corresponds to the attested credential data as defined in the Web Authentication: An API for accessing Public Key Credentials Level 2 specification.
 * For more details, see the specification: [Web Authentication: Level 2 - Attested Credential Data](https://www.w3.org/TR/webauthn-2/#attested-credential-data)
 *
 * AttestedCredentialData:
 * |  aaguid  | credIdLength |     credID      |   publicKey   |
 * |----------|--------------|-----------------|---------------|
 * | 16 bytes |   2 bytes    | credID.length() | variable size |
 */
class AttestedCredData(
    val aaguid: ByteArray,
    val credId: ByteArray,
    val publicKey: ByteArray,
) {
    fun toByteArray(): ByteArray {
        try {
            return ByteBuffer.allocate(aaguid.size + 2 + credId.size + publicKey.size).apply {
                put(aaguid)
                putShort(credId.size.toShort())
                put(credId)
                put(publicKey)
            }.array()
        } catch (e: Exception) {
            throw WebAuthnException.EncodingException("Cannot convert AttestedCredData to ByteArray", e)
        }
    }
}

class EC2COSEKey(
    var kty: Int,
    var alg: Int,
    var crv: Int,
    var x: ByteArray,
    var y: ByteArray,
) : CborSerializable {
    constructor(ecPublicKey: ECPublicKey) : this(
        kty = 2,
        alg = -7,
        crv = 1,
        x = ecPublicKey.w.affineX.toByteArray(),
        y = ecPublicKey.w.affineY.toByteArray(),
    )

    override fun <T : AbstractBuilder<*>?> toCBOR(builder: MapBuilder<T>): T {
        return builder
            .put(1, kty.toLong())
            .put(3, alg.toLong())
            .put(-1, crv.toLong())
            .put(-2, x)
            .put(-3, y)
            .end()
    }
}

enum class AuthenticatorDataFlags(val value: UByte) {
    UP(0b0000_0001u),
    UV(0b0000_0100u),
    AT(0b0100_0000u),
    ED(0b1000_0000u),
    ;

    companion object {
        fun makeFlags(
            userPresent: Boolean = false,
            userVerified: Boolean = false,
            attestedCredentialDataIncluded: Boolean = false,
            extensionDataIncluded: Boolean = false,
        ): UByte {
            var flags: UByte = 0u
            if (userPresent) flags = flags or UP.value
            if (userVerified) flags = flags or UV.value
            if (attestedCredentialDataIncluded) flags = flags or AT.value
            if (extensionDataIncluded) flags = flags or ED.value
            return flags
        }
    }
}
