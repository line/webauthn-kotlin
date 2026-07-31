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

package com.linecorp.webauthn.util

import com.linecorp.webauthn.model.AttestationConveyancePreference
import com.linecorp.webauthn.model.AuthenticatorSelectionCriteria
import com.linecorp.webauthn.model.COSEAlgorithmIdentifier
import com.linecorp.webauthn.model.PublicKeyCredentialCreateResult
import com.linecorp.webauthn.model.PublicKeyCredentialGetResult
import com.linecorp.webauthn.model.PublicKeyCredentialParams
import com.linecorp.webauthn.model.PublicKeyCredentialRpEntity
import com.linecorp.webauthn.model.PublicKeyCredentialType
import com.linecorp.webauthn.model.PublicKeyCredentialUserEntity
import com.linecorp.webauthn.model.UserVerificationRequirement
import com.linecorp.webauthn.rp.AuthenticationData
import com.linecorp.webauthn.rp.AuthenticationOptions
import com.linecorp.webauthn.rp.RegistrationData
import com.linecorp.webauthn.rp.RegistrationOptions
import com.linecorp.webauthn.rp.RelyingParty

/**
 * A [RelyingParty] that answers from fixed data and records what the SDK hands back to it.
 *
 * There is no server: the point is to reach the real `PublicKeyCredential.create`/`get` path on a device
 * and then inspect the results a relying party would actually receive - the `clientDataJSON`, the
 * attestation object, the assertion signature. Verification of those is left to the test, which does check
 * the assertion signature the way a server would.
 *
 * [failVerifyRegistrationWith] turns `verifyRegistration` into a failure without touching the SDK, which
 * is how the registration-cleanup path is exercised through the public API.
 */
class FakeRelyingParty(
    val rp: PublicKeyCredentialRpEntity = PublicKeyCredentialRpEntity("example.com", "Example Relying Party"),
    // base64url, because the SDK reads user.id as base64url when it decodes the user handle.
    val user: PublicKeyCredentialUserEntity = PublicKeyCredentialUserEntity(
        id = "dXNlci0xMjM",
        name = "User Name",
        displayName = "Display Name",
    ),
) : RelyingParty {

    val registrationChallenge: String = Fido2Util.generateRandomByteArray(32).toBase64url()
    val authenticationChallenge: String = Fido2Util.generateRandomByteArray(32).toBase64url()

    /** When set, `verifyRegistration` records the result and then throws this. */
    var failVerifyRegistrationWith: Throwable? = null

    var lastCreateResult: PublicKeyCredentialCreateResult? = null
        private set
    var lastGetResult: PublicKeyCredentialGetResult? = null
        private set

    fun registrationOptions(): RegistrationOptions = RegistrationOptions(
        attestation = AttestationConveyancePreference.NONE,
        authenticatorSelection = AuthenticatorSelectionCriteria(null, UserVerificationRequirement.REQUIRED.value),
        credProtect = null,
        displayName = user.displayName,
        username = user.name,
    )

    fun authenticationOptions(): AuthenticationOptions = AuthenticationOptions(
        userVerification = UserVerificationRequirement.REQUIRED,
        username = user.name,
    )

    override suspend fun getRegistrationData(options: RegistrationOptions): RegistrationData = RegistrationData(
        attestation = options.attestation,
        authenticatorSelection = options.authenticatorSelection,
        challenge = registrationChallenge,
        // Empty rather than populated: a credential of this relying party's own would make every second
        // registration an InvalidStateException, which is a case
        // com.linecorp.webauthn.authenticator.AuthenticatorExceptionTest covers directly.
        excludeCredentials = null,
        // Null rather than a ClientExtensionInput: extension processing is a documented no-op, and a
        // null input is what keeps the authenticator data free of an extensions block.
        extensions = null,
        pubKeyCredParams = listOf(
            PublicKeyCredentialParams(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256)
        ),
        rp = rp,
        user = user,
    )

    override suspend fun verifyRegistration(result: PublicKeyCredentialCreateResult) {
        lastCreateResult = result
        failVerifyRegistrationWith?.let { throw it }
    }

    override suspend fun getAuthenticationData(options: AuthenticationOptions): AuthenticationData = AuthenticationData(
        // Null, so the authenticator selects by relying-party id out of its own storage rather than
        // being handed the answer.
        allowCredentials = null,
        challenge = authenticationChallenge,
        extensions = null,
        rpId = rp.id,
        userVerification = options.userVerification,
    )

    override suspend fun verifyAuthentication(result: PublicKeyCredentialGetResult) {
        lastGetResult = result
    }
}
