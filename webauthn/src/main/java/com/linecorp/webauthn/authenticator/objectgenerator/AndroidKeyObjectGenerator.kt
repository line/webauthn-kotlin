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

package com.linecorp.webauthn.authenticator.objectgenerator

import com.linecorp.webauthn.exceptions.WebAuthnException
import com.linecorp.webauthn.model.AndroidKeyAttestationStatement
import com.linecorp.webauthn.model.AttestationObject
import com.linecorp.webauthn.model.AttestationStatement
import com.linecorp.webauthn.model.AttestationStatementFormat
import com.linecorp.webauthn.model.AttestedCredData
import com.linecorp.webauthn.model.AuthenticatorExtensionsOutput
import com.linecorp.webauthn.model.COSEAlgorithmIdentifier
import com.linecorp.webauthn.model.EC2COSEKey
import com.linecorp.webauthn.util.SecureExecutionHelper
import com.linecorp.webauthn.util.base64urlToByteArray
import java.security.MessageDigest
import java.security.Signature
import java.security.interfaces.ECPublicKey

internal class AndroidKeyObjectGenerator : Fido2ObjectGenerator() {
    override val fmt: AttestationStatementFormat = AttestationStatementFormat.ANDROID_KEY

    override fun createAttestationObject(
        hash: ByteArray,
        rpId: String,
        aaguid: ByteArray,
        credId: String,
        signCount: UInt,
        extensions: AuthenticatorExtensionsOutput?,
        signature: Signature?
    ): AttestationObject {
        val credIdBytes = credId.base64urlToByteArray()
        val keyAlias = credId
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
        // An android-key statement is a signature over the authenticator data, so a null Signature here is
        // an SDK wiring error rather than anything the caller did. `!!` reported it as a bare
        // NullPointerException that the callers above flattened into "an unknown error occurred".
        val signingSignature = signature
            ?: throw WebAuthnException.UnknownException("An ANDROID_KEY attestation requires a signature.")
        signingSignature.update(authenticatorDataBytes + hash)
        val sig = signingSignature.sign()
        val certChain = SecureExecutionHelper.getX509Certificates(keyAlias)
        val x5c = certChain.map { it.encoded }
        val attStmt: AttestationStatement = AndroidKeyAttestationStatement(
            alg = COSEAlgorithmIdentifier.ES256.value,
            sig = sig,
            x5c = x5c,
        )

        return AttestationObject(authenticatorDataBytes, fmt.value, attStmt)
    }
}
