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

import android.content.Context
import androidx.fragment.app.FragmentActivity
import com.linecorp.webauthn.authenticator.Authenticator
import com.linecorp.webauthn.authenticator.AuthenticatorProvider
import com.linecorp.webauthn.db.CredentialSourceStorage
import com.linecorp.webauthn.exceptions.WebAuthnException
import com.linecorp.webauthn.handler.BiometricAuthenticationHandler
import com.linecorp.webauthn.handler.DeviceCredentialAuthenticationHandler
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
import com.linecorp.webauthn.util.SecureExecutionHelper
import com.linecorp.webauthn.util.base64urlToByteArray
import com.linecorp.webauthn.util.toBase64url
import java.security.MessageDigest
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

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
     * Returns the raw androidx BiometricManager.canAuthenticate() status code for the
     * authentication method this instance was configured with, without starting any UI.
     *
     * Call this BEFORE offering FIDO registration/authentication so unsupported devices can
     * be routed to an alternative instead of failing mid-flow with a ConstraintException:
     * - BiometricManager.BIOMETRIC_SUCCESS (0): authentication is available.
     * - BIOMETRIC_ERROR_NONE_ENROLLED (11): no (strong) biometric or credential enrolled -
     *   guide the user to enrollment.
     * - BIOMETRIC_ERROR_NO_HARDWARE (12): the device has no capable hardware - hide the
     *   FIDO entry point or fall back per policy.
     * - BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED (15): a security update is required first.
     *
     * @param context The application context.
     * @return A BiometricManager status code.
     */
    fun canAuthenticate(context: Context): Int = when (authenticationMethod) {
        AuthenticationMethod.Biometric ->
            BiometricAuthenticationHandler(authenticationDispatcher).capabilityStatus(context)
        AuthenticationMethod.DeviceCredential ->
            DeviceCredentialAuthenticationHandler(authenticationDispatcher).capabilityStatus(context)
    }

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
            } catch (e: CancellationException) {
                throw e
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
            } catch (e: CancellationException) {
                // Roll back the locally stored credential (cleanup itself is
                // NonCancellable), then let cancellation propagate.
                runCatching { authenticator.cleanup(createResult.id) }
                throw e
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
        }.onFailure { if (it is CancellationException) throw it }
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
            } catch (e: CancellationException) {
                throw e
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
            } catch (e: CancellationException) {
                throw e
            } catch (e: Throwable) {
                throw WebAuthnException.RpException(
                    "Error occurred while verifying authentication data from rp: $e",
                    e
                )
            }
        }.onFailure { if (it is CancellationException) throw it }
    }

    /**
     * Retrieves all registered accounts.
     *
     * @return List of all registered PublicKeyCredentialSource.
     * @throws WebAuthnException.CredSrcStorageException If there is an error loading credentials from the database.
     */
    suspend fun getAllAccounts(): List<com.linecorp.webauthn.model.PublicKeyCredentialSource> {
        // loadAll() without an aaguid filter already returns every stored credential, so a
        // single call is enough. Iterating authenticator types here would return each
        // credential once per type (4x duplicates).
        val authenticator = authenticatorProvider.getAuthenticator(
            authenticationMethod = authenticationMethod,
            attestationStatement = attestationStatement,
            fido2PromptInfo = null,
        )
        return try {
            withContext(databaseDispatcher) {
                authenticator.db.loadAll()
            }
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            throw WebAuthnException.CredSrcStorageException("Failed to load all credentials", e)
        }
    }

    /**
     * Deletes all registered accounts.
     *
     * @throws WebAuthnException.CredSrcStorageException If there is an error loading or deleting credentials from the database.
     */
    suspend fun deleteAllAccounts() {
        val authenticator = authenticatorProvider.getAuthenticator(
            authenticationMethod = authenticationMethod,
            attestationStatement = attestationStatement,
            fido2PromptInfo = null,
        )

        try {
            withContext(databaseDispatcher) {
                authenticator.db.loadAll().forEach { credential ->
                    // Delete the hardware-backed private key together with the DB row;
                    // removing only the row would leave orphaned keys in the KeyStore.
                    // The credential id is the KeyStore alias (see Authenticator).
                    SecureExecutionHelper.deleteKey(credential.id)
                    authenticator.db.delete(credential.id)
                }
            }
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            throw WebAuthnException.CredSrcStorageException("Failed to load and delete all credentials", e)
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
            // WebAuthn requires user.id to be 1..64 BYTES. The field carries the
            // base64url encoding of those bytes (it is decoded as base64url at assertion
            // time), so validate by decoding instead of counting string characters:
            // a spec-valid 64-byte id encodes to ~86 characters and was wrongly rejected
            // before, while a non-decodable id would only crash later during get().
            val userIdBytes = try {
                options.user.id.base64urlToByteArray()
            } catch (e: WebAuthnException) {
                throw WebAuthnException.CoreException.TypeException(
                    "user.id must be a base64url-encoded byte sequence.",
                    e
                )
            }
            if (userIdBytes.size !in 1..64) {
                throw WebAuthnException.CoreException.TypeException(
                    "The length of the user id must be between 1 and 64 bytes."
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
        } catch (e: CancellationException) {
            throw e
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
        try {
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
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            // Mirror publicKeyCredentialCreate: normalize everything to WebAuthnException
            // so get() never surfaces raw platform exceptions.
            if (e is WebAuthnException) {
                throw e
            } else {
                throw WebAuthnException.UnknownException(
                    "Error occurred while getting public key credential: $e",
                    e
                )
            }
        }
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
