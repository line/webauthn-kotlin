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

        /**
         * Reports whether [authenticationMethod] can be used on this device right now.
         *
         * Call this before [create] to gate your UI. `create()` throws
         * [WebAuthnException.CoreException.ConstraintException] when authentication is unavailable,
         * which is an expected device state rather than an error worth reporting.
         *
         * This function does not throw. If the platform query itself fails, the result is
         * [AuthenticationAvailability.Reason.UNKNOWN] with a null
         * [AuthenticationAvailability.status].
         */
        @JvmStatic
        fun checkAuthenticationAvailability(
            context: Context,
            authenticationMethod: AuthenticationMethod
        ): AuthenticationAvailability {
            // Typed explicitly: the least upper bound of the two concrete handlers is not
            // AuthenticationCapability, so inference would not find canAuthenticateStatus.
            val handler: AuthenticationCapability = when (authenticationMethod) {
                AuthenticationMethod.Biometric -> BiometricAuthenticationHandler()
                AuthenticationMethod.DeviceCredential -> DeviceCredentialAuthenticationHandler()
            }
            return try {
                AuthenticationAvailability.fromStatus(handler.canAuthenticateStatus(context))
            } catch (e: Exception) {
                // The whole point of this API is to answer instead of failing, so a platform query that
                // throws must not surface as an exception to a caller who is trying to avoid one. Below
                // API 30 the device-credential path reaches `KeyguardManager` through an unchecked cast,
                // so a device with no keyguard service would otherwise propagate a raw platform throwable.
                // UNKNOWN rather than NO_HARDWARE: we caught an arbitrary failure, so we genuinely could
                // not determine availability, and NO_HARDWARE would name a device capability we never
                // observed. This is also the only case in which `status` is null.
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
     * Cancellation is not a result. If the calling coroutine's scope is cancelled - a back press, a
     * destroyed host, a timeout - this function completes with a [CancellationException] rather than a
     * `Result.failure`, so the cancellation stays a cancellation instead of arriving at your error handling
     * as a relying-party or deletion failure.
     *
     * Key material that an interrupted registration had already created is deleted before this function
     * returns. A credential that was already registered on the device when the cancellation arrived is kept
     * instead, since it is complete and [getAllAccounts] lists it; whether the relying party accepted it is
     * unknown, and [deleteAccount] removes it.
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
        runCatchingCancellable {
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
                // Deliberately no cleanup: the credential is fully registered on the device at this point,
                // so its row names the key and deleteAccount can still remove it. Deleting it here would
                // also be a guess about a verification whose outcome the caller never learned.
                throw e
            } catch (e: Throwable) {
                val rpException = WebAuthnException.RpException(
                    "Error occurred while verifying registration data from rp: $e",
                    e
                )

                try {
                    authenticator.retryCleanup(createResult.id, maxTries = 2, delayMillis = 1000)
                } catch (e2: CancellationException) {
                    // Only the cancellable wait between cleanup attempts can land here, so the key deletion
                    // has already run once. The relying-party failure that triggered it rides along, so it
                    // still appears in a printed stack trace instead of being replaced by a DeletionException
                    // that blames the SDK for the caller's teardown.
                    e2.addSuppressed(rpException)
                    throw e2
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
     * As with [create], a cancelled scope completes this function with a [CancellationException] rather than
     * with a `Result.failure`.
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
        runCatchingCancellable {
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
        }
    }

    /**
     * Runs [block] and captures its failure in a [Result], except cancellation.
     *
     * `runCatching` catches [Throwable], so it swallows the [CancellationException] that a cancelled scope
     * raises at the next suspension point and hands the caller a `Result.failure` instead. That breaks
     * structured concurrency twice over: the caller's coroutine is already dead, and the SDK reports a
     * business error - in practice `RpException`, because the innermost `catch` around the relying-party
     * call rewrote it - for what is a back press or a destroyed host. Consuming apps then log and count that
     * as a relying-party fault.
     */
    private inline fun <T> runCatchingCancellable(block: () -> T): Result<T> = try {
        Result.success(block())
    } catch (e: CancellationException) {
        throw e
    } catch (e: Throwable) {
        Result.failure(e)
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
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            throw WebAuthnException.CredSrcStorageException("Failed to load credentials", e)
        }
    }

    /**
     * Deletes all registered accounts, including their hardware-backed key material.
     *
     * This is irreversible: the private keys cannot be recovered, and a credential that is still
     * registered at the relying party has to be deregistered there separately.
     *
     * Deletion is best effort. Every credential is attempted even when an earlier one fails, so a single
     * unusable credential cannot strand the rest of the batch; the first failure is then rethrown with any
     * later ones attached to it as suppressed exceptions.
     *
     * A credential whose key could not be deleted deliberately **keeps its database row**, because that
     * row is the only record of the KeyStore alias: dropping it would leave behind a private key that can
     * never be named, and so never deleted, again. The consequence is that such a credential is still
     * listed by [getAllAccounts] and that every later call to this function fails on it again. Nothing this
     * API offers can remove it while the key deletion keeps failing — but the
     * [com.linecorp.webauthn.db.CredentialSourceStorage] implementation belongs to you, so if you decide to
     * abandon the key you can delete the row through it directly.
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
                withContext(databaseDispatcher) { authenticator.cleanup(credential.id) }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Throwable) {
                failures.add(e)
            }
        }
        failures.firstOrNull()?.let { firstFailure ->
            // Identity-checked: addSuppressed throws IllegalArgumentException for self-suppression, which
            // would replace the documented failure with an undocumented one. Two credentials can genuinely
            // fail with one instance - a stubbed or cached exception, or a singleton from a storage layer.
            failures.drop(1).forEach { if (it !== firstFailure) firstFailure.addSuppressed(it) }
            throw firstFailure
        }
    }

    /**
     * Deletes one registered account: its hardware-backed key material, and then its database row.
     *
     * Idempotent. An unknown [credId] is not an error, because a missing KeyStore alias and a missing row
     * are indistinguishable from a deletion that already succeeded.
     *
     * @param credId The credential id as returned by [getAllAccounts], which is also the KeyStore alias of
     * the credential's private key.
     * @throws WebAuthnException.SecureExecutionException If the key material could not be deleted. The
     * database row is deliberately kept in that case, since it is the only record of the KeyStore alias, so
     * the credential stays nameable and every later call for this [credId] fails the same way until the key
     * deletion succeeds. The [com.linecorp.webauthn.db.CredentialSourceStorage] implementation is yours: if
     * you decide to abandon the key, delete the row through it directly.
     * @throws WebAuthnException.CredSrcStorageException If the database row could not be deleted.
     */
    suspend fun deleteAccount(credId: String) {
        val authenticator = anyAuthenticator()
        withContext(databaseDispatcher) { authenticator.cleanup(credId) }
    }

    /**
     * An [Authenticator] used only to reach shared state, with no prompt attached.
     *
     * The credential storage is a single consumer-supplied instance shared by every authenticator type, so
     * any authenticator reaches every stored credential. The account-management APIs above used to loop
     * over all four [AuthenticationMethod] x [AttestationStatementFormat] combinations and call the
     * unfiltered `loadAll()` once per combination, which returned every credential four times and ran
     * every deletion four times.
     *
     * `loadAll()` stays unfiltered rather than passing `authType.aaguid`: filtering would silently hide
     * rows whose aaguid is not one of the four [com.linecorp.webauthn.model.AuthenticatorType] values, and
     * a storage implementation that ignores the parameter would still return every row per iteration.
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
            validateUserHandle(options.user.id)

            val credTypesAndPubKeyAlgs = processCredTypesAndPubKeyAlgs(options)

            // Off the caller's dispatcher for the reason spelled out in [publicKeyCredentialGet]; the string
            // itself is unchanged.
            val origin = withContext(Dispatchers.IO) {
                Fido2Util.getPackageFacetID(activity.applicationContext)
            }
            val collectedClientData =
                CollectedClientData(
                    type = "webauthn.create",
                    challenge = options.challenge,
                    origin = origin,
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
                // `$e` renders as "java.lang.IllegalStateException: no signing info" only when the message is
                // non-null; a message-less throwable printed as its class name alone with no indication that
                // that was all there was. Naming the class and the message separately keeps both halves
                // legible, and matches the sibling in `publicKeyCredentialGet`.
                throw WebAuthnException.UnknownException(
                    "Unhandled ${e::class.java.name} while creating public key credential: ${e.message}",
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
            // Off the caller's dispatcher: a PackageManager binder round trip, an X.509 parse and a SHA-256,
            // on every single operation. `create` does the same, and the string is unchanged - it is the
            // `origin` inside the signed clientDataJSON that the relying party verifies byte for byte.
            val origin = withContext(Dispatchers.IO) {
                Fido2Util.getPackageFacetID(activity.applicationContext)
            }
            val collectedClientData = CollectedClientData(
                type = "webauthn.get",
                challenge = options.challenge,
                origin = origin,
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
            // The `create` sibling has always normalised here; this one did not, so anything the platform
            // raised outside the authenticator - a PackageManager.NameNotFoundException, a package with no
            // signers - reached the caller as a raw non-WebAuthnException in Result.failure, contradicting
            // the @throws contract above and falling through consumer `when (e)` blocks to a generic error.
            if (e is WebAuthnException) {
                throw e
            }
            throw WebAuthnException.UnknownException(
                "Unhandled ${e::class.java.name} while getting public key credential: ${e.message}",
                e
            )
        }
    }

    /**
     * The user handle must be 1..64 **bytes** per WebAuthn Level 2. `user.id` carries it as base64url,
     * so counting characters capped it at 48 bytes and rejected spec-legal 49..64-byte handles.
     *
     * A value that is not valid base64url falls back to the previous character-count check rather than
     * failing: rejecting it outright would turn a working integration into 100% registration failure on
     * upgrade. Passing a non-base64url id is unsupported and will be rejected in a future release.
     */
    private fun validateUserHandle(userId: String) {
        val decodedSize = try {
            userId.base64urlToByteArray().size
        } catch (e: WebAuthnException.UtilityException) {
            userId.length
        }
        if (decodedSize !in 1..64) {
            throw WebAuthnException.CoreException.TypeException(
                "The length of the user id must be between 1 and 64 bytes, but was $decodedSize."
            )
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
