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

package com.lycorp.webauthn.rp

import com.lycorp.webauthn.model.AttestationConveyancePreference
import com.lycorp.webauthn.model.AuthenticatorSelectionCriteria
import com.lycorp.webauthn.model.ClientExtensionInput
import com.lycorp.webauthn.model.CredentialProtection
import com.lycorp.webauthn.model.PublicKeyCredentialCreateResult
import com.lycorp.webauthn.model.PublicKeyCredentialDescriptor
import com.lycorp.webauthn.model.PublicKeyCredentialGetResult
import com.lycorp.webauthn.model.PublicKeyCredentialParams
import com.lycorp.webauthn.model.PublicKeyCredentialRpEntity
import com.lycorp.webauthn.model.PublicKeyCredentialUserEntity
import com.lycorp.webauthn.model.UserVerificationRequirement

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

class RegistrationOptions(
    val attestation: AttestationConveyancePreference,
    val authenticatorSelection: AuthenticatorSelectionCriteria?,
    val credProtect: CredentialProtection?,
    val displayName: String,
    val username: String
)

class AuthenticationOptions(
    val userVerification: UserVerificationRequirement,
    val username: String
)

class RegistrationData(
    val attestation: AttestationConveyancePreference,
    val authenticatorSelection: AuthenticatorSelectionCriteria?,
    val challenge: String,
    val excludeCredentials: List<PublicKeyCredentialDescriptor>?,
    val extensions: ClientExtensionInput?,
    val pubKeyCredParams: List<PublicKeyCredentialParams>,
    val rp: PublicKeyCredentialRpEntity,
    val user: PublicKeyCredentialUserEntity
)

class AuthenticationData(
    val allowCredentials: List<PublicKeyCredentialDescriptor>?,
    val challenge: String,
    val extensions: ClientExtensionInput?,
    val rpId: String,
    val userVerification: UserVerificationRequirement
)
