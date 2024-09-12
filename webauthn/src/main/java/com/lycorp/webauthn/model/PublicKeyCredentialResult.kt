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

import com.lycorp.webauthn.util.base64urlToByteArray

/**
 * The result of the WebAuthn registration process.
 *
 * @property id Base64url encoding of the credential ID.
 * @property authenticatorAttestationResponse The authenticator's attestation response.
 * @property clientExtensionsOutput Optional client extension outputs.
 * @property rawId ByteArray representation of the credential ID.
 * @property type The type of public key credential.
 */
class PublicKeyCredentialCreateResult(
    val id: String,
    val authenticatorAttestationResponse: AuthenticatorAttestationResponse,
    val clientExtensionsOutput: ClientExtensionsOutput? = null,
) {
    var rawId: ByteArray = id.base64urlToByteArray()
    val type: String = PublicKeyCredentialType.PUBLIC_KEY.value
}

/**
 * The result of the WebAuthn authentication process.
 *
 * @property id Base64url encoding of the credential ID.
 * @property authenticatorAssertionResponse The authenticator's assertion response.
 * @property clientExtensionsOutput Optional client extension outputs.
 * @property rawId ByteArray representation of the credential ID.
 * @property type The type of public key credential.
 */
class PublicKeyCredentialGetResult(
    val id: String,
    val authenticatorAssertionResponse: AuthenticatorAssertionResponse,
    val clientExtensionsOutput: ClientExtensionsOutput? = null,
) {
    var rawId: ByteArray = id.base64urlToByteArray()
    val type: String = PublicKeyCredentialType.PUBLIC_KEY.value
}
