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

package com.linecorp.webauthn.publickeycredential

import androidx.fragment.app.FragmentActivity
import com.linecorp.webauthn.authenticator.Authenticator
import com.linecorp.webauthn.authenticator.AuthenticatorProvider
import com.linecorp.webauthn.db.CredentialSourceStorage
import com.linecorp.webauthn.exceptions.WebAuthnException
import com.linecorp.webauthn.model.AttestationStatementFormat
import com.linecorp.webauthn.model.AuthenticationMethod
import com.linecorp.webauthn.model.AuthenticatorAssertionResponse
import com.linecorp.webauthn.model.AuthenticatorAttestationResponse
import com.linecorp.webauthn.model.AuthenticatorGetAssertionResult
import com.linecorp.webauthn.model.AuthenticatorMakeCredentialResult
import com.linecorp.webauthn.model.COSEAlgorithmIdentifier
import com.linecorp.webauthn.model.CollectedClientData
import com.linecorp.webauthn.model.Fido2PromptInfo
import com.linecorp.webauthn.model.PublicKeyCredentialCreateResult
import com.linecorp.webauthn.model.PublicKeyCredentialCreationOptions
import com.linecorp.webauthn.model.PublicKeyCredentialGetResult
import com.linecorp.webauthn.model.PublicKeyCredentialParams
import com.linecorp.webauthn.model.PublicKeyCredentialRequestOptions
import com.linecorp.webauthn.model.PublicKeyCredentialSource
import com.linecorp.webauthn.model.PublicKeyCredentialType
import com.linecorp.webauthn.rp.AuthenticationData
import com.linecorp.webauthn.rp.AuthenticationOptions
import com.linecorp.webauthn.rp.RegistrationData
import com.linecorp.webauthn.rp.RegistrationOptions
import com.linecorp.webauthn.rp.RelyingParty
import com.linecorp.webauthn.util.Fido2Util
import com.linecorp.webauthn.util.toBase64url
import java.security.MessageDigest
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.encodeToString

/**
 * Abstract class representing a PublicKeyCredential for WebAuthn operations.
 * Provides methods for credential creation, authentication, and account management.
 */
class PublicKeyCredential(
    private val rpClient: RelyingParty,
    db: CredentialSourceStorage,
    private val authenticationMethod: AuthenticationMethod,
    private val attestationStatement: AttestationStatementFormat,
    private val relyingPartyDispatcher: CoroutineDispatcher = Dispatchers.IO,
    private val databaseDispatcher: CoroutineDispatcher = Dispatchers.IO,
    private val authenticationDispatcher: CoroutineDispatcher = Dispatchers.Main,
    private val authenticatorProvider: AuthenticatorProvider = AuthenticatorProvider(
        db,
        databaseDispatcher,
        authenticationDispatcher
    ),
) {
    companion object {
        /**
         * Mutex to ensure that create and get operations are thread-safe.
         */
        private val mutex = Mutex()
    }

    internal lateinit var authenticator: Authenticator

    /**
     * Initiates the registration process for a new credential.
     *
     * @param activity The activity context used for UI operations.
     * @param options The registration options provided by the relying party.
     * @param fido2PromptInfo Optional prompt information for FIDO2 authentication.
     * @return Result of the registration process.
     * @throws WebAuthnException.RpException If there is an error obtaining or verifying registration data from the relying party.
     * @throws WebAuthnException.DeletionException If there is an error deleting keys during cleanup.
     * @throws WebAuthnException If an error occurs in the authenticator during the registration process.
     */
    suspend fun create(
        activity: FragmentActivity,
        options: RegistrationOptions,
        fido2PromptInfo: Fido2PromptInfo? = null
    ): Result<Unit> = mutex.withLock {
        runCatching {
            val registrationData: RegistrationData = try {
                withContext(relyingPartyDispatcher) {
                    rpClient.getRegistrationData(options)
                }
            } catch (e: Throwable) {
                throw WebAuthnException.RpException(
                    "Error occurred while getting registration data from rp: $e",
                    e
                )
            }

            val createResult: PublicKeyCredentialCreateResult = publicKeyCredentialCreate(
                activity,
                PublicKeyCredentialCreationOptions(
                    rp = registrationData.rp,
                    user = registrationData.user,
                    challenge = registrationData.challenge,
                    publicKeyCredentialParams = registrationData.pubKeyCredParams,
                    excludeCredentials = registrationData.excludeCredentials,
                    authenticatorSelection = registrationData.authenticatorSelection,
                    attestation = registrationData.attestation,
                    extensions = registrationData.extensions,
                ),
                fido2PromptInfo
            )

            try {
                withContext(relyingPartyDispatcher) {
                    rpClient.verifyRegistration(createResult)
                }
            } catch (e: Throwable) {
                val rpException = WebAuthnException.RpException(
                    "Error occurred while verifying registration data from rp: $e",
                    e
                )

                try {
                    authenticator.retryCleanup(createResult.id, maxTries = 2, delayMillis = 1000)
                } catch (e2: Throwable) {
                    throw WebAuthnException.DeletionException(
                        "Error occurred while deleting key: $e2",
                        cause = e2,
                        trigger = rpException
                    )
                }
                throw rpException
            }
        }
    }

    /**
     * Initiates the authentication process for an existing credential.
     *
     * @param activity The activity context used for UI operations.
     * @param options The authentication options provided by the relying party.
     * @param fido2PromptInfo Optional prompt information for FIDO2 authentication.
     * @return Result of the authentication process.
     * @throws WebAuthnException.RpException If there is an error obtaining or verifying authentication data from the relying party.
     * @throws WebAuthnException If an error occurs in the authenticator during the authentication process.
     */
    suspend fun get(
        activity: FragmentActivity,
        options: AuthenticationOptions,
        fido2PromptInfo: Fido2PromptInfo? = null
    ): Result<Unit> = mutex.withLock {
        runCatching {
            val authenticationData: AuthenticationData = try {
                withContext(relyingPartyDispatcher) {
                    rpClient.getAuthenticationData(options)
                }
            } catch (e: Throwable) {
                throw WebAuthnException.RpException(
                    "Error occurred while getting authentication data from rp: $e",
                    e
                )
            }

            val getResult = publicKeyCredentialGet(
                activity,
                PublicKeyCredentialRequestOptions(
                    challenge = authenticationData.challenge,
                    rpId = authenticationData.rpId,
                    allowCredentials = authenticationData.allowCredentials,
                    userVerification = authenticationData.userVerification,
                    extensions = authenticationData.extensions,
                ),
                fido2PromptInfo
            )

            try {
                withContext(relyingPartyDispatcher) {
                    rpClient.verifyAuthentication(getResult)
                }
            } catch (e: Throwable) {
                throw WebAuthnException.RpException(
                    "Error occurred while verifying authentication data from rp: $e",
                    e
                )
            }
        }
    }

    /**
     * Retrieves all registered accounts.
     *
     * @return List of all registered PublicKeyCredentialSource.
     * @throws WebAuthnException.CredSrcStorageException If there is an error loading credentials from the database.
     */
    suspend fun getAllAccounts(): List<com.linecorp.webauthn.model.PublicKeyCredentialSource> {
        val result = mutableListOf<com.linecorp.webauthn.model.PublicKeyCredentialSource>()
        for (authMethod in AuthenticationMethod.entries) {
            for (fmt in AttestationStatementFormat.entries) {
                val authenticator = authenticatorProvider.getAuthenticator(
                    authenticationMethod = authMethod,
                    attestationStatement = fmt,
                    fido2PromptInfo = null,
                )
                val credentials: List<com.linecorp.webauthn.model.PublicKeyCredentialSource> = try {
                    withContext(databaseDispatcher) {
                        authenticator.db.loadAll()
                    }
                } catch (e: Exception) {
                    throw WebAuthnException.CredSrcStorageException(
                        "Failed to load credentials for authenticator type: ${authenticator.authType}",
                        e
                    )
                }
                result.addAll(credentials)
            }
        }

        return result
    }

    /**
     * Deletes all registered accounts.
     *
     * @throws WebAuthnException.CredSrcStorageException If there is an error loading or deleting credentials from the database.
     */
    suspend fun deleteAllAccounts() {
        for (authMethod in AuthenticationMethod.entries) {
            for (fmt in AttestationStatementFormat.entries) {
                val authenticator = authenticatorProvider.getAuthenticator(
                    authenticationMethod = authMethod,
                    attestationStatement = fmt,
                    fido2PromptInfo = null,
                )

                try {
                    withContext(databaseDispatcher) {
                        authenticator.db.loadAll().forEach { credential ->
                            authenticator.db.delete(credential.id)
                        }
                    }
                } catch (e: Exception) {
                    throw WebAuthnException.CredSrcStorageException("Failed to load and delete all credentials", e)
                }
            }
        }
    }

    /**
     * Creates a new public key credential.
     *
     * This method implements the `create` operation as defined in the Web Authentication: An API for accessing Public Key Credentials Level 2 specification.
     * For more details, see the specification: [Web Authentication: Level 2 - Create](https://www.w3.org/TR/webauthn-2/#sctn-createCredential)
     *
     * @param activity The activity context used for UI operations.
     * @param options The public key credential creation options.
     * @param fido2PromptInfo Optional prompt information for FIDO2 authentication.
     * @return The result of the credential creation process.
     * @throws WebAuthnException If there is an error during the creation process.
     */
    private suspend fun publicKeyCredentialCreate(
        activity: FragmentActivity,
        options: PublicKeyCredentialCreationOptions,
        fido2PromptInfo: Fido2PromptInfo? = null
    ): PublicKeyCredentialCreateResult {
        try {
            if (options.user.id.length !in 1..64) {
                throw WebAuthnException.CoreException.TypeException(
                    "The length of the user id must be between 1 and 64."
                )
            }

            val credTypesAndPubKeyAlgs = processCredTypesAndPubKeyAlgs(options)

            val collectedClientData =
                CollectedClientData(
                    type = "webauthn.create",
                    challenge = options.challenge,
                    origin = Fido2Util.getPackageFacetID(activity.applicationContext),
                )
            val clientDataJSON: ByteArray = Json.encodeToString(collectedClientData).toByteArray()
            val clientDataHash: ByteArray =
                MessageDigest.getInstance("SHA-256").digest(clientDataJSON)

            authenticator = authenticatorProvider.getAuthenticator(
                authenticationMethod = authenticationMethod,
                attestationStatement = attestationStatement,
                fido2PromptInfo = fido2PromptInfo
            )

            val authMakeCredResult: AuthenticatorMakeCredentialResult = authenticator.makeCredential(
                activity = activity,
                hash = clientDataHash,
                rpEntity = options.rp,
                userEntity = options.user,
                credTypesAndPubKeyAlgs = credTypesAndPubKeyAlgs,
                excludeCredDescriptorList = options.excludeCredentials,
                extensions = options.extensions?.processAuthenticatorExtensionsInput(),
            ).getOrThrow()

            return PublicKeyCredentialCreateResult(
                id = authMakeCredResult.credentialId.toBase64url(),
                authenticatorAttestationResponse =
                com.linecorp.webauthn.model.AuthenticatorAttestationResponse(
                    clientDataJSON = clientDataJSON,
                    attestationObject = authMakeCredResult.attestationObject,
                ),
                clientExtensionsOutput = options.extensions?.processClientExtensionsOutput(),
            )
        } catch (e: Exception) {
            if (e is WebAuthnException) {
                throw e
            } else {
                throw WebAuthnException.UnknownException(
                    "Error occurred while creating public key credential: $e",
                    e
                )
            }
        }
    }

    /**
     * Retrieves an existing public key credential.
     *
     * This method implements the `get` operation as defined in the Web Authentication: An API for accessing Public Key Credentials Level 2 specification.
     * For more details, see the specification: [Web Authentication: Level 2 - Get](https://www.w3.org/TR/webauthn-2/#sctn-getAssertion)
     *
     * @param activity The activity context used for UI operations.
     * @param options The public key credential request options.
     * @param fido2PromptInfo Optional prompt information for FIDO2 authentication.
     * @return The result of the credential retrieval process.
     * @throws WebAuthnException If there is an error during the retrieval process.
     */
    private suspend fun publicKeyCredentialGet(
        activity: FragmentActivity,
        options: PublicKeyCredentialRequestOptions,
        fido2PromptInfo: Fido2PromptInfo? = null
    ): PublicKeyCredentialGetResult {
        val collectedClientData = CollectedClientData(
            type = "webauthn.get",
            challenge = options.challenge,
            origin = Fido2Util.getPackageFacetID(activity.applicationContext),
        )
        val clientDataJSON: ByteArray = Json.encodeToString(collectedClientData).toByteArray()
        val clientDataHash: ByteArray =
            MessageDigest.getInstance("SHA-256").digest(clientDataJSON)

        authenticator = authenticatorProvider.getAuthenticator(
            authenticationMethod = authenticationMethod,
            attestationStatement = attestationStatement,
            fido2PromptInfo = fido2PromptInfo
        )

        val authGetAssertionResult: AuthenticatorGetAssertionResult = authenticator.getAssertion(
            activity = activity,
            rpId = options.rpId,
            hash = clientDataHash,
            allowCredDescriptorList = options.allowCredentials,
            extensions = options.extensions?.processAuthenticatorExtensionsInput(),
        ).getOrThrow()

        return PublicKeyCredentialGetResult(
            id = authGetAssertionResult.credentialId.toBase64url(),
            authenticatorAssertionResponse =
            com.linecorp.webauthn.model.AuthenticatorAssertionResponse(
                clientDataJSON = clientDataJSON,
                authenticatorData = authGetAssertionResult.authenticatorData,
                signature = authGetAssertionResult.signature,
                userHandle = authGetAssertionResult.userHandle,
            ),
            clientExtensionsOutput = options.extensions?.processClientExtensionsOutput(),
        )
    }

    /**
     * Processes the credential types and public key algorithms from the creation options.
     *
     * @param options The public key credential creation options.
     * @return The list of processed public key credential parameters.
     * @throws WebAuthnException.CoreException.NotSupportedException If no valid credential types and public key algorithms are found.
     */
    private fun processCredTypesAndPubKeyAlgs(
        options: PublicKeyCredentialCreationOptions
    ): List<PublicKeyCredentialParams> {
        val credTypesAndPubKeyAlgs = mutableListOf<PublicKeyCredentialParams>()
        if (options.publicKeyCredentialParams.isEmpty()) {
            credTypesAndPubKeyAlgs.add(
                PublicKeyCredentialParams(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256)
            )
        } else {
            for (pubKeyParam in options.publicKeyCredentialParams) {
                if (pubKeyParam.type == PublicKeyCredentialType.PUBLIC_KEY) {
                    credTypesAndPubKeyAlgs.add(PublicKeyCredentialParams(pubKeyParam.type, pubKeyParam.alg))
                }
            }
        }
        if (credTypesAndPubKeyAlgs.isEmpty()) {
            throw WebAuthnException.CoreException.NotSupportedException(
                "credTypesAndPubKeyAlgs is empty."
            )
        }
        return credTypesAndPubKeyAlgs
    }
}
