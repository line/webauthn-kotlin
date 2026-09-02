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
import com.linecorp.webauthn.handler.AuthenticationCapability
import com.linecorp.webauthn.handler.BiometricAuthenticationHandler
import com.linecorp.webauthn.handler.DeviceCredentialAuthenticationHandler
import com.linecorp.webauthn.model.AttestationStatementFormat
import com.linecorp.webauthn.model.AuthenticationAvailability
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

        /**
         * Reports whether [authenticationMethod] can be used on this device right now.
         *
         * Call this before [create] to gate your UI. `create()` throws
         * [WebAuthnException.CoreException.ConstraintException] when authentication is unavailable,
         * which is an expected device state rather than an error worth reporting.
         *
         * It answers whether the user can authenticate at all, not whether an already registered
         * credential is still usable: re-enrolling a biometric invalidates the credential's key while
         * leaving this result [AuthenticationAvailability.Reason.AVAILABLE], so [get] can still fail with
         * [WebAuthnException.AuthenticationException.KeyPermanentlyInvalidatedException].
         *
         * This function does not throw. If the platform query itself fails, the result is
         * [AuthenticationAvailability.Reason.UNKNOWN] with a null
         * [AuthenticationAvailability.status]. It queries the platform synchronously, so treat it as a
         * cheap-but-not-free binder call rather than something to poll.
         */
        @JvmStatic
        fun checkAuthenticationAvailability(
            context: Context,
            authenticationMethod: AuthenticationMethod
        ): AuthenticationAvailability {
            val handler: AuthenticationCapability = when (authenticationMethod) {
                AuthenticationMethod.Biometric -> BiometricAuthenticationHandler()
                AuthenticationMethod.DeviceCredential -> DeviceCredentialAuthenticationHandler()
            }
            return try {
                AuthenticationAvailability.fromStatus(handler.canAuthenticateStatus(context))
            } catch (e: Exception) {
                // Below API 30 the device-credential path reaches KeyguardManager through an unchecked
                // cast, so a device with no keyguard service throws here. UNKNOWN rather than NO_HARDWARE:
                // an arbitrary failure is not an observation about the device's hardware.
                AuthenticationAvailability(
                    isAvailable = false,
                    status = null,
                    reason = AuthenticationAvailability.Reason.UNKNOWN
                )
            }
        }
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
     * Every stored credential is returned exactly once, whichever authenticator type registered it.
     *
     * @return List of all registered PublicKeyCredentialSource.
     * @throws WebAuthnException.CredSrcStorageException If there is an error loading credentials from the database.
     */
    suspend fun getAllAccounts(): List<PublicKeyCredentialSource> {
        val storage = anyAuthenticator().db
        return try {
            withContext(databaseDispatcher) { storage.loadAll() }
        } catch (e: Exception) {
            throw WebAuthnException.CredSrcStorageException("Failed to load credentials", e)
        }
    }

    /**
     * Deletes all registered accounts, including their hardware-backed key material.
     *
     * This is irreversible: the private keys cannot be recovered, and a credential that is still
     * registered at the relying party has to be deregistered there separately. Do not call this while a
     * [create] or [get] ceremony is in flight; the account APIs deliberately stay outside the mutex those
     * two hold, so a concurrent call can destroy the key the ceremony is using.
     *
     * Deletion is best effort: every credential is attempted even when an earlier one fails, and the first
     * failure is rethrown with any later ones attached to it as suppressed exceptions.
     *
     * A credential whose key could not be deleted keeps its database row, since that row is the only record
     * of the KeyStore alias, so it stays listed by [getAllAccounts] and fails here again on every later
     * call. See [deleteAccount] for how to abandon such a key.
     *
     * @throws WebAuthnException.CredSrcStorageException If the credentials could not be loaded, or a row
     * could not be deleted.
     * @throws WebAuthnException.SecureExecutionException If key material could not be deleted.
     */
    suspend fun deleteAllAccounts() {
        val authenticator = anyAuthenticator()
        val failures = mutableListOf<Throwable>()
        for (credential in getAllAccounts()) {
            try {
                // Called directly: `cleanup` dispatches its own work and runs both deletions to
                // completion, so wrapping it would only put a cancellation checkpoint in front of the
                // keystore delete.
                authenticator.cleanup(credential.id)
            } catch (e: CancellationException) {
                // Collecting this would keep the loop running over every remaining credential doing
                // nothing, and attach the cancellations to an unrelated failure as suppressed exceptions.
                throw e
            } catch (e: Throwable) {
                failures.add(e)
            }
        }
        failures.firstOrNull()?.let { firstFailure ->
            // addSuppressed throws IllegalArgumentException on self-suppression, and one exception instance
            // can come back for several credentials (a cached or stubbed throwable from the storage layer).
            failures.drop(1).forEach { if (it !== firstFailure) firstFailure.addSuppressed(it) }
            throw firstFailure
        }
    }

    /**
     * Deletes one registered account: its hardware-backed key material, and then its database row.
     *
     * The key deletion is idempotent: AndroidKeyStore reports a missing alias as success. Whether an
     * unknown [credId] is an error overall therefore depends on your
     * [com.linecorp.webauthn.db.CredentialSourceStorage], which this SDK does not require to tolerate one
     * - an implementation that throws for an id it does not hold makes a repeated call fail with
     * [WebAuthnException.CredSrcStorageException].
     *
     * @param credId The credential id as returned by [getAllAccounts], which is also the KeyStore alias of
     * the credential's private key.
     * @throws WebAuthnException.SecureExecutionException If the key material could not be deleted. The
     * database row is kept in that case, since it is the only record of the KeyStore alias, so every later
     * call for this [credId] fails the same way until the key deletion succeeds. To abandon the key instead,
     * delete the row through your own [com.linecorp.webauthn.db.CredentialSourceStorage].
     * @throws WebAuthnException.CredSrcStorageException If the database row could not be deleted.
     */
    suspend fun deleteAccount(credId: String) {
        anyAuthenticator().cleanup(credId)
    }

    /**
     * An [Authenticator] used only to reach shared state, with no prompt attached.
     *
     * The credential storage is one consumer-supplied instance shared by every authenticator type, so any
     * authenticator reaches every stored credential, and one instance is enough for the account APIs above.
     *
     * `loadAll()` stays unfiltered: passing `authType.aaguid` would hide rows whose aaguid is not one of the
     * [com.linecorp.webauthn.model.AuthenticatorType] values.
     */
    private fun anyAuthenticator(): Authenticator = authenticatorProvider.getAuthenticator(
        authenticationMethod = authenticationMethod,
        attestationStatement = attestationStatement,
        fido2PromptInfo = null,
    )

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
