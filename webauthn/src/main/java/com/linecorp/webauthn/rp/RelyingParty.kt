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

package com.linecorp.webauthn.rp

import com.linecorp.webauthn.model.AttestationConveyancePreference
import com.linecorp.webauthn.model.AuthenticatorSelectionCriteria
import com.linecorp.webauthn.model.ClientExtensionInput
import com.linecorp.webauthn.model.CredentialProtection
import com.linecorp.webauthn.model.PublicKeyCredentialCreateResult
import com.linecorp.webauthn.model.PublicKeyCredentialDescriptor
import com.linecorp.webauthn.model.PublicKeyCredentialGetResult
import com.linecorp.webauthn.model.PublicKeyCredentialParams
import com.linecorp.webauthn.model.PublicKeyCredentialRpEntity
import com.linecorp.webauthn.model.PublicKeyCredentialUserEntity
import com.linecorp.webauthn.model.UserVerificationRequirement

/**
 * Interface for Relying Party operations in WebAuthn.
 * Defines methods for registration and authentication processes.
 */
interface RelyingParty {

    /**
     * Generates and returns the data required to initiate a WebAuthn registration process.
     *
     * @param options The registration options containing parameters like attestation, authenticator selection, etc.
     * @return RegistrationData The data required to initiate the registration process.
     */
    suspend fun getRegistrationData(options: RegistrationOptions): RegistrationData

    /**
     * Verifies the result of a WebAuthn registration process.
     *
     * @param result The result of the registration process.
     */
    suspend fun verifyRegistration(result: PublicKeyCredentialCreateResult)

    /**
     * Generates and returns the data required to initiate a WebAuthn authentication process.
     *
     * @param options The authentication options containing parameters like user verification, username, etc.
     * @return AuthenticationData The data required to initiate the authentication process.
     */
    suspend fun getAuthenticationData(options: AuthenticationOptions): AuthenticationData

    /**
     * Verifies the result of a WebAuthn authentication process.
     *
     * @param result The result of the authentication process.
     */
    suspend fun verifyAuthentication(result: PublicKeyCredentialGetResult)
}

data class RegistrationOptions(
    val attestation: AttestationConveyancePreference,
    val authenticatorSelection: AuthenticatorSelectionCriteria?,
    val credProtect: CredentialProtection?,
    val displayName: String,
    val username: String
)

data class AuthenticationOptions(val userVerification: UserVerificationRequirement, val username: String)

data class RegistrationData(
    val attestation: AttestationConveyancePreference,
    val authenticatorSelection: AuthenticatorSelectionCriteria?,
    /**
     * MUST be the base64url (unpadded) encoding of the server's raw challenge bytes.
     * The value is embedded verbatim as `challenge` in clientDataJSON and compared by
     * the server during verification, so any other encoding will fail server-side.
     */
    val challenge: String,
    val excludeCredentials: List<PublicKeyCredentialDescriptor>?,
    val extensions: ClientExtensionInput?,
    val pubKeyCredParams: List<PublicKeyCredentialParams>,
    val rp: PublicKeyCredentialRpEntity,
    val user: PublicKeyCredentialUserEntity
)

data class AuthenticationData(
    val allowCredentials: List<PublicKeyCredentialDescriptor>?,
    /**
     * MUST be the base64url (unpadded) encoding of the server's raw challenge bytes.
     * See [RegistrationData.challenge].
     */
    val challenge: String,
    val extensions: ClientExtensionInput?,
    val rpId: String,
    val userVerification: UserVerificationRequirement
)
