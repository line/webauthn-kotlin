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

package com.lycorp.webauthn.authenticator

import com.lycorp.webauthn.model.AssertionObject
import com.lycorp.webauthn.model.AttestationObject
import com.lycorp.webauthn.model.AttestationStatement
import com.lycorp.webauthn.model.AttestationStatementFormats
import com.lycorp.webauthn.model.AttestedCredData
import com.lycorp.webauthn.model.AuthenticatorData
import com.lycorp.webauthn.model.AuthenticatorDataFlags
import com.lycorp.webauthn.model.AuthenticatorExtensionsOutput
import com.lycorp.webauthn.model.COSEAlgorithmIdentifier
import com.lycorp.webauthn.model.EC2COSEKey
import com.lycorp.webauthn.util.SecureExecutionHelper
import com.lycorp.webauthn.util.base64urlToByteArray
import com.lycorp.webauthn.util.toBase64url
import java.security.MessageDigest
import java.security.Signature
import java.security.interfaces.ECPublicKey

internal class Fido2ObjectFactory {
    private val fmt = AttestationStatementFormats.ANDROID_KEY.value

    fun createAttestationObject(
        hash: ByteArray,
        rpId: String,
        aaguid: ByteArray,
        credId: String,
        signCount: UInt,
        signature: Signature,
        extensions: AuthenticatorExtensionsOutput?,
    ): AttestationObject {
        val credIdBytes = credId.base64urlToByteArray()
        val keyAlias = credId.toBase64url()
        val publicKey = SecureExecutionHelper.getPublicKey(keyAlias)
        val encodedCredPubKey = EC2COSEKey(publicKey as ECPublicKey)
            .toCBOR()
        val rpIdHash = MessageDigest.getInstance("SHA-256").digest(rpId.toByteArray())
        val attestedCredData = AttestedCredData(
            aaguid,
            credIdBytes,
            encodedCredPubKey
        )
        val authenticatorData =
            createAuthenticatorData(
                signCount = signCount,
                rpIdHash = rpIdHash,
                extensions = extensions?.toCBOR(),
                attestedCredData = attestedCredData,
            )
        val authenticatorDataBytes = authenticatorData.toByteArray()
        signature.update(authenticatorDataBytes + hash)
        val sig = signature.sign()

        val certChain = SecureExecutionHelper.getX509Certificates(keyAlias)
        val x5cBytesList = certChain.map { it.encoded }
        val x5c = x5cBytesList

        val attStmt =
            AttestationStatement(
                alg = COSEAlgorithmIdentifier.ES256.value,
                sig = sig,
                x5c = x5c,
            )
        return AttestationObject(authenticatorDataBytes, fmt, attStmt)
    }

    fun createAssertionObject(
        hash: ByteArray,
        rpId: String,
        signCount: UInt,
        signature: Signature,
        extensions: AuthenticatorExtensionsOutput?,
    ): AssertionObject {
        val rpIdHash = MessageDigest.getInstance("SHA-256").digest(rpId.toByteArray())

        val authenticatorData =
            createAuthenticatorData(
                signCount = signCount,
                rpIdHash = rpIdHash,
                extensions = extensions?.toCBOR(),
                attestedCredData = null
            )
        val authenticatorDataBytes = authenticatorData.toByteArray()
        signature.update(authenticatorDataBytes + hash)
        val sig = signature.sign()

        return AssertionObject(
            authenticatorDataBytes,
            sig,
        )
    }

    private fun createAuthenticatorData(
        signCount: UInt,
        rpIdHash: ByteArray,
        userPresent: Boolean = true,
        userVerified: Boolean = true,
        extensions: ByteArray? = null,
        attestedCredData: AttestedCredData?,
    ): AuthenticatorData {
        val attestedCredDataBytes = attestedCredData?.toByteArray()
        val flags =
            createFlags(
                userPresent,
                userVerified,
                attestedCredData != null,
                extensions,
            )
        return AuthenticatorData(
            rpIdHash,
            flags,
            signCount,
            attestedCredDataBytes,
            extensions
        )
    }

    private fun createFlags(
        userPresent: Boolean,
        userVerified: Boolean,
        attestedCredDataIncluded: Boolean,
        extensions: ByteArray?,
    ): UByte {
        val up = userPresent
        val uv = userVerified
        val at = attestedCredDataIncluded
        val ed = extensions != null
        return AuthenticatorDataFlags.makeFlags(up, uv, at, ed)
    }
}
