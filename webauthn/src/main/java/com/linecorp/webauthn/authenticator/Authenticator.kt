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

package com.linecorp.webauthn.authenticator

import android.annotation.SuppressLint
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity
import com.linecorp.webauthn.authenticator.keygenerator.Fido2KeyGenerator
import com.linecorp.webauthn.authenticator.objectgenerator.Fido2ObjectGenerator
import com.linecorp.webauthn.db.CredentialSourceStorage
import com.linecorp.webauthn.exceptions.WebAuthnException
import com.linecorp.webauthn.handler.AuthenticationCapability
import com.linecorp.webauthn.handler.AuthenticationHandler
import com.linecorp.webauthn.model.AssertionObject
import com.linecorp.webauthn.model.AttestationObject
import com.linecorp.webauthn.model.AttestationStatementFormat
import com.linecorp.webauthn.model.AuthenticatorExtensionsInput
import com.linecorp.webauthn.model.AuthenticatorExtensionsOutput
import com.linecorp.webauthn.model.AuthenticatorGetAssertionResult
import com.linecorp.webauthn.model.AuthenticatorMakeCredentialResult
import com.linecorp.webauthn.model.AuthenticatorType
import com.linecorp.webauthn.model.COSEAlgorithmIdentifier
import com.linecorp.webauthn.model.Fido2PromptInfo
import com.linecorp.webauthn.model.Fido2UserAuthResult
import com.linecorp.webauthn.model.PublicKeyCredentialDescriptor
import com.linecorp.webauthn.model.PublicKeyCredentialParams
import com.linecorp.webauthn.model.PublicKeyCredentialRpEntity
import com.linecorp.webauthn.model.PublicKeyCredentialSource
import com.linecorp.webauthn.model.PublicKeyCredentialType
import com.linecorp.webauthn.model.PublicKeyCredentialUserEntity
import com.linecorp.webauthn.model.getSignatureAlgorithmName
import com.linecorp.webauthn.util.CRED_ID_SIZE
import com.linecorp.webauthn.util.Fido2Util
import com.linecorp.webauthn.util.SecureExecutionHelper
import com.linecorp.webauthn.util.base64urlToByteArray
import com.linecorp.webauthn.util.toBase64url
import java.security.PrivateKey
import java.security.Signature
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext

internal class Authenticator(
    val db: CredentialSourceStorage,
    val authenticationHandler: AuthenticationHandler,
    val fido2KeyGenerator: Fido2KeyGenerator,
    val fido2ObjectGenerator: Fido2ObjectGenerator,
    val authType: AuthenticatorType,
    var fido2PromptInfo: Fido2PromptInfo? = null,
    val databaseDispatcher: CoroutineDispatcher = Dispatchers.IO,
    /**
     * Where AndroidKeyStore and KeyMint work runs.
     *
     * Key generation, alias lookups, key and certificate reads, and signing are all synchronous binder
     * round trips into keystore2 and from there into the TEE or StrongBox; hardware attestation and
     * StrongBox key generation are the slowest of them by an order of magnitude. Nothing in this class used
     * to shift them, so they ran on whichever dispatcher the consumer called from — in practice
     * `Dispatchers.Main`, which is what the production ANR reports show.
     *
     * Added last, and defaulted, so that adding it cannot change the descriptor of any existing call.
     */
    val keystoreDispatcher: CoroutineDispatcher = Dispatchers.IO,
) {

    /**
     * The list of supported public key credential parameters.
     */
    private val supportedCredParamsList: List<PublicKeyCredentialParams> =
        listOf(
            PublicKeyCredentialParams(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256),
        )

    /**
     * Runs [block] on [keystoreDispatcher], carrying a failure back as a value instead of throwing it across
     * the dispatcher hop.
     *
     * That indirection is not decoration. kotlinx.coroutines' stack-trace recovery *copies* an exception
     * that is thrown across a coroutine boundary whenever its class declares no fields of its own — which is
     * true of every platform keystore failure, `java.security.ProviderException` and
     * `android.security.KeyStoreException` included. The caller would then get a different instance with the
     * original pushed one level down onto `cause`, and `WebAuthnException.KeyGenerationException.cause` is
     * read by consumers to reach the platform failure, so its identity is part of this SDK's contract.
     * Handing the failure back as a `Result` and unwrapping it on this side of the hop rethrows the original
     * instance, with its own fields and stack trace intact.
     *
     * `runCatching` is safe here because [block] is synchronous keystore work with no suspension point of
     * its own: it cannot observe cancellation, and a cancellation of the surrounding scope is still raised
     * by `withContext` before the result is unwrapped.
     */
    private suspend fun <T> withKeystore(block: () -> T): T =
        withContext(keystoreDispatcher) { runCatching(block) }.getOrThrow()

    /**
     * Creates a new credential.
     *
     * This method implements the `authenticatorMakeCredential` operation as defined in the Web Authentication: An API for accessing Public Key Credentials Level 2 specification.
     * For more details, see the specification: [Web Authentication: Level 2 - Create](https://www.w3.org/TR/webauthn-2/#authenticatormakecredential)
     *
     * @param activity The activity context used for UI operations.
     * @param hash The hash to sign.
     * @param rpEntity The relying party entity information.
     * @param userEntity The user entity information.
     * @param credTypesAndPubKeyAlgs The list of credential types and public key algorithms.
     * @param excludeCredDescriptorList The list of credentials to exclude.
     * @param extensions The authenticator extensions input.
     * @return The result of the credential creation process.
     * @throws WebAuthnException If an error occurs during the creation process.
     */
    suspend fun makeCredential(
        activity: FragmentActivity,
        hash: ByteArray,
        rpEntity: PublicKeyCredentialRpEntity,
        userEntity: PublicKeyCredentialUserEntity,
        credTypesAndPubKeyAlgs: List<PublicKeyCredentialParams>,
        excludeCredDescriptorList: List<PublicKeyCredentialDescriptor>?,
        extensions: AuthenticatorExtensionsInput?,
    ): Result<AuthenticatorMakeCredentialResult> {
        val (credIdBytes: ByteArray, credId: String) = generateUniqueCredId()
        var strongBoxRequested = false
        var keyCommitted = false
        try {
            val credTypeAndPubKeyAlg: PublicKeyCredentialParams = fetchCredTypeAndPubKeyAlg(credTypesAndPubKeyAlgs)
            checkCredentialWasNotRegistered(rpEntity.id, excludeCredDescriptorList)
            checkAuthenticationSupport(activity.applicationContext)
            val keyAlias: String = credId

            val credentialSource = com.linecorp.webauthn.model.PublicKeyCredentialSource(
                type = credTypeAndPubKeyAlg.type.value,
                id = credId,
                rpId = rpEntity.id,
                userHandle = userEntity.id,
                aaguid = authType.aaguid,
            )

            val fmt = authType.getAttestationStatementFormat()
            val challenge = if (fmt != AttestationStatementFormat.NONE) hash else null
            strongBoxRequested = isStrongBoxSupported(activity.applicationContext)
            // The slowest keystore call in the SDK: an attested, possibly StrongBox-backed key pair. The
            // flag is set inside the block rather than from its result, because `withContext` discards a
            // value computed after the job was cancelled - and the key exists on the device either way.
            val keyPair = withKeystore {
                fido2KeyGenerator.generateFido2Key(
                    keyAlias = keyAlias,
                    challenge = challenge,
                    publicKeyAlgorithm = credTypeAndPubKeyAlg.alg,
                    isStrongBoxBacked = strongBoxRequested,
                ).also { keyCommitted = true }
            }

            val fido2UserAuthResult = if (fmt != AttestationStatementFormat.NONE) {
                val signatureAlgorithm = credTypeAndPubKeyAlg.alg.getSignatureAlgorithmName()
                authenticate(activity, authenticationHandler, fido2PromptInfo) {
                    Signature.getInstance(signatureAlgorithm).apply { initSign(keyPair.private) }
                }
            } else {
                authenticate(activity, authenticationHandler, fido2PromptInfo)
            }

            // Reads the public key and, for the android-key format, the whole attestation certificate chain
            // out of the keystore, then signs with the already-initialised Signature. The signing operation
            // was authorised by `initSign` on the main thread above; finishing it here only moves the
            // keystore round trips off the caller's dispatcher, and KeyMint operations are not
            // thread-confined.
            val attestationObject: AttestationObject = withKeystore {
                fido2ObjectGenerator.createAttestationObject(
                    hash = hash,
                    rpId = rpEntity.id,
                    aaguid = authType.aaguidBytes(),
                    credId = credId,
                    signCount = 0u,
                    extensions = AuthenticatorExtensionsOutput.getAuthenticatorExtensionResult(extensions),
                    signature = fido2UserAuthResult.signature,
                )
            }

            storeCredentialSourceIntoDB(credentialSource)

            return Result.success(
                AuthenticatorMakeCredentialResult(
                    credentialId = credIdBytes,
                    attestationObject = attestationObject.toCBOR(),
                )
            )
        } catch (e: CancellationException) {
            // The caller's scope is gone, so no result can be delivered - but a key that reached the
            // keystore still has to go with it. `credId` is the alias and nothing outside this frame knows
            // it yet: no database row names it (the row is written last, and is dropped here as well if it
            // was), so a key left behind could never be named, and so never deleted, again.
            //
            // `cleanup` rather than `retryCleanup`: its two terminal operations are uncancellable and run to
            // completion here, whereas a retry's `delay` would keep the FragmentActivity and the
            // process-wide create/get mutex held for another second after the caller had given up.
            if (keyCommitted) {
                try {
                    cleanup(credId)
                } catch (cleanupFailure: Throwable) {
                    // Carried on the cancellation rather than replacing it: a cancelled coroutine has to
                    // complete with a CancellationException, or the caller's scope reports a business
                    // failure for its own teardown - which is the defect this whole path exists to remove.
                    e.addSuppressed(cleanupFailure)
                }
            }
            throw e
        } catch (e: Throwable) {
            return handleMakeCredentialException(e, credId, strongBoxRequested, keyCommitted)
        }
    }

    /**
     * Gets an assertion for authentication.
     *
     * This method implements the `authenticatorGetAssertion` operation as defined in the Web Authentication: An API for accessing Public Key Credentials Level 2 specification.
     * For more details, see the specification: [Web Authentication: Level 2 - Get](https://www.w3.org/TR/webauthn-2/#sctn-op-get-assertion)
     *
     * @param activity The activity context used for UI operations.
     * @param rpId The relying party ID.
     * @param hash The hash to sign.
     * @param allowCredDescriptorList The list of allowed credentials.
     * @param extensions The authenticator extensions input.
     * @return The result of the assertion process.
     * @throws WebAuthnException If an error occurs during the assertion process.
     */
    suspend fun getAssertion(
        activity: FragmentActivity,
        rpId: String,
        hash: ByteArray,
        allowCredDescriptorList: List<PublicKeyCredentialDescriptor>?,
        extensions: AuthenticatorExtensionsInput?,
    ): Result<AuthenticatorGetAssertionResult> {
        try {
            val credOptions: List<com.linecorp.webauthn.model.PublicKeyCredentialSource> =
                checkCredentialWasRegistered(rpId, allowCredDescriptorList)
            val selectedCred: com.linecorp.webauthn.model.PublicKeyCredentialSource = credOptions[0]
            val credId: String = selectedCred.id
            val keyAlias: String = credId

            checkAuthenticationSupport(activity.applicationContext)

            // Two keystore round trips, taken together so the pair costs one dispatch rather than two. The
            // `Signature` is still created and initialised inside the handler on the main dispatcher below:
            // `initSign` is what consumes the user's authentication, and on API < 30 the device-credential
            // key is time-authorised for five seconds, so an extra hop between the keyguard result and
            // `initSign` can turn a successful ceremony into a UserNotAuthenticatedException.
            val (key, signatureAlgorithm) = withKeystore {
                val storedKey = SecureExecutionHelper.getKey(keyAlias)
                    ?: throw WebAuthnException.KeyNotFoundException(
                        message = "Cannot get a key from device. credId=$credId, " +
                            "candidates=${credOptions.size}, authType=$authType"
                    )
                storedKey to SecureExecutionHelper.getX509Certificate(keyAlias).sigAlgName
            }
            val fido2UserAuthResult = authenticate(activity, authenticationHandler, fido2PromptInfo) {
                Signature.getInstance(signatureAlgorithm).apply { initSign(key as PrivateKey) }
            }
            // Checked here rather than at the point of use: an assertion cannot be produced without it, and
            // failing before the signature counter is advanced keeps the counter a record of assertions the
            // relying party can actually have seen. `!!` used to raise a bare NullPointerException that
            // `getAssertion`'s terminal catch turned into "An unknown error occurred", naming neither the
            // handler nor the authenticator type.
            val signature = fido2UserAuthResult.signature
                ?: throw WebAuthnException.UnknownException(
                    message = "The authenticator returned no signature. authType=$authType, " +
                        "handler=${authenticationHandler::class.java.name}"
                )

            val processedExtensions = AuthenticatorExtensionsOutput.getAuthenticatorExtensionResult(extensions)

            try {
                withContext(databaseDispatcher) {
                    db.increaseSignatureCounter(credId)
                }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                throw WebAuthnException.CredSrcStorageException(
                    "Failed to increase signature counter for credId: $credId",
                    e
                )
            }

            val signCount: UInt = try {
                withContext(databaseDispatcher) {
                    db.getSignatureCounter(credId)
                }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                throw WebAuthnException.CredSrcStorageException(
                    "Failed to get signature counter for credId: $credId",
                    e
                )
            }

            // Signs, so it is a KeyMint round trip like the reads above. The operation was already
            // authorised by `initSign` inside the prompt; only `update`/`sign` happen here.
            val assertionObject: AssertionObject = withKeystore {
                fido2ObjectGenerator.createAssertionObject(
                    hash = hash,
                    rpId = rpId,
                    signCount = signCount,
                    signature = signature,
                    extensions = processedExtensions
                )
            }

            return Result.success(
                AuthenticatorGetAssertionResult(
                    credentialId = credId.base64urlToByteArray(),
                    authenticatorData = assertionObject.authenticatorData,
                    signature = assertionObject.signature,
                    userHandle = selectedCred.userHandle?.base64urlToByteArray(),
                )
            )
        } catch (e: CancellationException) {
            // Never a Result.failure: cancellation is the caller's own scope ending, and reporting it as an
            // assertion failure is what made a back-press look like an SDK fault. Nothing to clean up here -
            // getAssertion creates no key material.
            throw e
        } catch (e: Exception) {
            val authenticatorException = if (e is WebAuthnException) {
                e
            } else {
                // Named, like the makeCredential path: "An unknown error occurred" identified neither the
                // failure nor where it came from, and a consumer only ever sees the message string.
                WebAuthnException.UnknownException(
                    message = "Unhandled ${e::class.java.name}: ${e.message}",
                    cause = e
                )
            }
            return Result.failure(authenticatorException)
        }
    }

    /**
     * Fetches the supported credential type and public key algorithm from the provided list.
     *
     * @param credTypesAndPubKeyAlgs The list of credential types and public key algorithms to check.
     * @return The supported credential type and public key algorithm.
     * @throws WebAuthnException.CoreException.NotSupportedException If none of the provided types and algorithms are supported.
     */
    private fun fetchCredTypeAndPubKeyAlg(
        credTypesAndPubKeyAlgs: List<PublicKeyCredentialParams>
    ): PublicKeyCredentialParams {
        var chosenPubKeyAlgAndCredType: PublicKeyCredentialParams? = null
        for (pubKeyAlgAndCredType in credTypesAndPubKeyAlgs) {
            for (supportedPubKeyAlgAndCredType in supportedCredParamsList) {
                if (pubKeyAlgAndCredType == supportedPubKeyAlgAndCredType) {
                    chosenPubKeyAlgAndCredType = pubKeyAlgAndCredType
                    break
                }
            }
            if (chosenPubKeyAlgAndCredType != null) {
                break
            }
        }
        if (chosenPubKeyAlgAndCredType == null) {
            throw WebAuthnException.CoreException.NotSupportedException(
                message = "The credential type and public key algorithm are not supported."
            )
        }
        return chosenPubKeyAlgAndCredType
    }

    /**
     * Generates a unique credential ID.
     *
     * This method generates a random byte array and checks if it is already used as a credential ID.
     * If it is already used, it repeats the process until a unique ID is found.
     *
     * Every iteration asks the keystore whether the alias exists, which is a binder round trip, so the loop
     * runs on [keystoreDispatcher] rather than on the caller's dispatcher.
     *
     * @return A pair containing the byte array and the base64url-encoded string of the credential ID.
     */
    private suspend fun generateUniqueCredId(): Pair<ByteArray, String> = withKeystore {
        var credIdBytes: ByteArray
        var credId: String
        do {
            credIdBytes = Fido2Util.generateRandomByteArray(CRED_ID_SIZE)
            credId = credIdBytes.toBase64url()
        } while (SecureExecutionHelper.containAlias(credId))
        Pair(credIdBytes, credId)
    }

    /**
     * Checks if authentication is supported by the device.
     *
     * @throws WebAuthnException.CoreException.ConstraintException If authentication is not supported by the device.
     */
    private fun checkAuthenticationSupport(context: Context) {
        if (authenticationHandler.isSupported(context)) {
            return
        }
        val status = (authenticationHandler as? AuthenticationCapability)?.canAuthenticateStatus(context)
        throw WebAuthnException.CoreException.ConstraintException(
            message = "Authentication is not supported by a device. " +
                "canAuthenticateStatus=$status, authType=$authType, " +
                "model=${Build.MODEL}, sdk=${Build.VERSION.SDK_INT}"
        ).apply { canAuthenticateStatus = status }
    }

    /**
     * Checks if a credential is not registered.
     *
     * @param rpId The relying party ID.
     * @param excludeCredDescriptorList The list of credentials to exclude.
     * @return True if the credential is not registered, false otherwise.
     */
    private suspend fun checkCredentialWasNotRegistered(
        rpId: String,
        excludeCredDescriptorList: List<PublicKeyCredentialDescriptor>?,
    ) {
        if (excludeCredDescriptorList.isNullOrEmpty()) {
            return
        }
        for (descriptor in excludeCredDescriptorList) {
            val credentialSource = try {
                withContext(databaseDispatcher) {
                    db.load(credId = descriptor.id)
                }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                throw WebAuthnException.CredSrcStorageException(
                    "Failed to load credential source for credId: ${descriptor.id}",
                    e
                )
            }

            if (credentialSource != null &&
                credentialSource.rpId == rpId &&
                credentialSource.type == descriptor.type
            ) {
                throw WebAuthnException.CoreException.InvalidStateException(
                    message = "The credential is already registered."
                )
            }
        }
        return
    }

    /**
     * Checks if a credential is registered.
     *
     * @param rpId The relying party ID.
     * @param allowCredDescriptorList The list of allowed credentials.
     * @return The list of registered public key credential sources.
     */
    private suspend fun checkCredentialWasRegistered(
        rpId: String,
        allowCredDescriptorList: List<PublicKeyCredentialDescriptor>?,
    ): List<com.linecorp.webauthn.model.PublicKeyCredentialSource> {
        val credOptions: MutableList<com.linecorp.webauthn.model.PublicKeyCredentialSource> = mutableListOf()
        if (!allowCredDescriptorList.isNullOrEmpty()) {
            for (descriptor in allowCredDescriptorList) {
                val credId = descriptor.id
                val credSource = try {
                    withContext(databaseDispatcher) {
                        db.load(credId = credId)
                    }
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    throw WebAuthnException.CredSrcStorageException(
                        "Failed to load credential source for credId: $credId",
                        e
                    )
                }
                if (credSource != null && credSource.rpId == rpId) {
                    credOptions.add(credSource)
                }
            }
        } else {
            val credSourceList = try {
                withContext(databaseDispatcher) {
                    db.loadAll(authType.aaguid)
                }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                throw WebAuthnException.CredSrcStorageException("Failed to load all credential sources", e)
            }

            for (credSource in credSourceList) {
                if (credSource.rpId == rpId) {
                    credOptions.add(credSource)
                }
            }
        }
        if (credOptions.isEmpty()) {
            throw WebAuthnException.CoreException.NotAllowedException(
                message = "No credential found for the given RP ID."
            )
        }
        return credOptions
    }

    /**
     * Authenticates the user, enabling the use of keys for signing.
     *
     * This method performs user authentication using the provided authentication handler.
     * The process includes handling initial signatures and displaying prompt information for FIDO2 authentication.
     *
     * @param activity The activity context used for UI operations.
     * @param authenticationHandler The handler for authentication.
     * @param fido2PromptInfo The prompt information for FIDO2 authentication.
     * @param signatureProvider The provider for the signature.
     * @return The result of the user authentication.
     * @throws WebAuthnException.CoreException.NotAllowedException If authentication fails or if an authentication error occurs.
     * @throws WebAuthnException.CoreException.UserCancelledException If the user deliberately dismissed the prompt.
     */
    private suspend fun authenticate(
        activity: FragmentActivity,
        authenticationHandler: AuthenticationHandler,
        fido2PromptInfo: Fido2PromptInfo?,
        signatureProvider: (() -> Signature)? = null,
    ): Fido2UserAuthResult {
        try {
            return authenticationHandler.authenticate(activity, fido2PromptInfo, signatureProvider)
        } catch (e: AuthenticationHandler.AuthenticationFailedException) {
            throw WebAuthnException.CoreException.NotAllowedException(
                message = "Authentication failed",
                cause = e
            ).apply { errorCode = e.errorCode }
        } catch (e: AuthenticationHandler.AuthenticationErrorException) {
            val errorCode = e.errorCode
            val exception = if (errorCode != null && errorCode in USER_CANCELLED_ERROR_CODES) {
                WebAuthnException.CoreException.UserCancelledException(
                    message = "The user cancelled the authentication prompt. errorCode=$errorCode",
                    cause = e
                )
            } else {
                WebAuthnException.CoreException.NotAllowedException(
                    message = "Authentication error is occurred. errorCode=$errorCode",
                    cause = e
                )
            }
            throw exception.apply { this.errorCode = errorCode }
        } catch (e: android.security.keystore.KeyPermanentlyInvalidatedException) {
            throw WebAuthnException.AuthenticationException.KeyPermanentlyInvalidatedException(
                cause = e
            )
        }
    }

    /**
     * Cleans up by deleting a unnecessary credential: both its key material and its database row.
     *
     * [credId] **is** the KeyStore alias, used verbatim. It is already base64url — `generateUniqueCredId`
     * produces it with `ByteArray.toBase64url` — and [makeCredential] passes it straight to
     * `generateFido2Key` as the alias, as do [getAssertion] and the object generators when reading the key
     * back. Encoding it again with `String.toBase64url` names an alias no key was ever stored under, and
     * `KeyStore.deleteEntry` is a silent no-op for an alias that does not exist, so cleanup would report
     * success while leaving the private key behind for the lifetime of the app's keystore.
     *
     * A missing alias is treated as success ([SecureExecutionHelper.deleteKeyIfPresent]) so that cleanup
     * stays idempotent — [retryCleanup]'s second attempt legitimately finds the key already gone — and so
     * that a failure of its own cannot replace the error that triggered it.
     *
     * Both deletions are [NonCancellable]. They are the terminal operations of the failure path, and they
     * are exactly the pair that must not be interrupted half-done: the key deletion runs on a dispatcher and
     * the row deletion runs on another, so on a cancelled scope every `withContext` here would otherwise
     * throw before doing anything, leaving a private key on the device whose only name — [credId] — the
     * failed registration was about to forget. [retryCleanup]'s delay is deliberately left cancellable,
     * because waiting a second on a dead scope would keep the `FragmentActivity` and the process-wide
     * create/get mutex held for no benefit.
     *
     * The window this opens is that both calls are consumer- or platform-bound, so `cleanup` blocks for as
     * long as they do and can no longer be interrupted. It is deliberately not wrapped in a `withTimeout`:
     * cancelling a coroutine cannot interrupt a blocking call, and `withTimeout` does not complete while a
     * child is still inside one, so the timeout would fire without bounding anything — measured at 2.0 s for
     * a 300 ms timeout over a 2 s blocking child — while under a virtual clock (`runTest`, in this SDK's
     * tests or a consumer's) it can fire as soon as the caller's dispatcher goes idle, intermittently
     * aborting the very deletion it was supposed to protect. Worse, a storage implementation that *is*
     * cooperatively cancellable is the one case where the timeout would succeed in aborting the deletion —
     * reopening the orphan window [NonCancellable] is here to close. Bounding it for real needs either a
     * detached coroutine whose work is abandoned, or thread interruption inside a consumer's storage write;
     * both are worse than a slow deletion.
     *
     * @param credId The credential ID, which is also the KeyStore alias of the credential's private key.
     * @throws WebAuthnException.CredSrcStorageException If there is an error deleting the credential from the database.
     */
    suspend fun cleanup(credId: String) {
        withContext(NonCancellable) {
            withKeystore {
                SecureExecutionHelper.deleteKeyIfPresent(credId)
            }
            try {
                withContext(databaseDispatcher) {
                    db.delete(credId = credId)
                }
            } catch (e: Exception) {
                throw WebAuthnException.CredSrcStorageException("Failed to delete credential for credId: $credId", e)
            }
        }
    }

    /**
     * Retries cleanup in case of failure.
     *
     * The wait between attempts stays cancellable: [cleanup] itself cannot be interrupted, so a cancelled
     * scope loses at most a retry of an operation that already ran once, rather than holding the caller's
     * `FragmentActivity` and the process-wide create/get mutex for another [delayMillis].
     *
     * @param credId The credential ID.
     * @param maxTries The maximum number of attempts.
     * @param delayMillis The delay between retries in milliseconds.
     */
    suspend fun retryCleanup(credId: String, maxTries: Int, delayMillis: Long) {
        repeat(maxTries) { attempt ->
            try {
                cleanup(credId)
                return
            } catch (e: CancellationException) {
                throw e
            } catch (e: Throwable) {
                if (attempt == maxTries - 1) throw e
                delay(delayMillis)
            }
        }
    }

    /**
     * Stores the given credential source into the database.
     *
     * @param credentialSource The credential source to store.
     * @throws WebAuthnException.CredSrcStorageException If there is an error storing the credential.
     */
    private suspend fun storeCredentialSourceIntoDB(
        credentialSource: com.linecorp.webauthn.model.PublicKeyCredentialSource
    ) {
        try {
            withContext(databaseDispatcher) {
                db.store(credentialSource)
            }
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            throw WebAuthnException.CredSrcStorageException(
                "Failed to store new credential for credId: ${credentialSource.id}",
                e
            )
        }
    }

    /**
     * Handles exceptions that occur during the credential creation process.
     *
     * This method attempts to clean up the credential and returns a failure result with the appropriate exception.
     *
     * @param e The exception that occurred.
     * @param credId The credential ID related to the exception.
     * @param strongBoxRequested Whether the key was requested StrongBox-backed, for diagnostics.
     * @param keyCommitted Whether key generation for [credId] returned. Cleanup runs either way; when key
     * generation did not return, a cleanup failure is carried on the original exception instead of
     * replacing it.
     * @return A failure result containing the exception.
     */
    private suspend fun handleMakeCredentialException(
        e: Throwable,
        credId: String,
        strongBoxRequested: Boolean,
        keyCommitted: Boolean,
    ): Result<AuthenticatorMakeCredentialResult> {
        val authenticatorException = when {
            e is WebAuthnException -> e
            // The operation is deliberately not named. `isKeystoreRejection` matches a ProviderException
            // anywhere in the block above, which includes `Signature.sign()` and the attestation
            // certificate-chain read inside `createAttestationObject`, so claiming key generation would
            // misattribute those. The throwable's own class is the closest thing to an operation this frame
            // can state truthfully.
            e.isKeystoreRejection() -> WebAuthnException.KeyGenerationException(
                message = "The platform keystore rejected an operation during credential creation: " +
                    "${e::class.java.name}. authType=$authType, strongBoxRequested=$strongBoxRequested, " +
                    "model=${Build.MODEL}, sdk=${Build.VERSION.SDK_INT}: ${e.message}",
                cause = e
            ).apply { keyStoreErrorCode = e.numericKeyStoreErrorCode() }
            else -> WebAuthnException.UnknownException(
                message = "Unhandled ${e::class.java.name}: ${e.message}",
                cause = e
            )
        }

        return try {
            retryCleanup(credId, maxTries = 2, delayMillis = 1000)
            Result.failure(authenticatorException)
        } catch (e2: CancellationException) {
            // Only reachable from the cancellable wait between attempts, so the first cleanup has already
            // run. Reporting it as a DeletionException is precisely the misattribution that made a
            // back-press arrive at the consumer as "Error occurred while deleting key:
            // JobCancellationException".
            //
            // The failure that triggered the cleanup rides along, as it does on the relying-party path in
            // `PublicKeyCredential.create`, so it still appears in a printed stack trace instead of being
            // dropped - a KeyGenerationException carries the KeyMint error code and is the only record of it.
            // The identity guard is required because `addSuppressed` throws IllegalArgumentException when
            // handed the same instance.
            if (authenticatorException !== e2) {
                e2.addSuppressed(authenticatorException)
            }
            throw e2
        } catch (e2: Throwable) {
            if (keyCommitted) {
                Result.failure(
                    WebAuthnException.DeletionException(
                        "Error occurred while deleting key: $e2",
                        cause = e2,
                        trigger = authenticatorException
                    )
                )
            } else {
                // The cleanup here is defensive: no key generation ever returned for this credId, and the
                // database row is written after it, so on every pre-flight failure - unsupported
                // algorithm, exclude-list match, no usable authentication method - it deletes state that
                // was never created. `CredentialSourceStorage.delete` is not required to be idempotent, so
                // a consumer that throws for an unknown id would otherwise turn a ConstraintException -
                // which the caller routes to biometric enrolment - into a DeletionException. Cleanup still
                // runs, because `keyCommitted` is only set once `generateFido2Key` has returned: a
                // generator that reached the keystore and then threw would leave a key under an alias
                // nothing outside this frame knows. Only the reported failure changes.
                if (authenticatorException !== e2) {
                    authenticatorException.addSuppressed(e2)
                }
                Result.failure(authenticatorException)
            }
        }
    }

    /**
     * Checks if the device supports StrongBox.
     *
     * @param context The application context.
     * @return True if StrongBox is supported, false otherwise.
     */
    private fun isStrongBoxSupported(context: Context): Boolean =
        context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)

    /**
     * Every throwable reachable from [this], depth first, following `cause` before `suppressed` and
     * never revisiting a node.
     *
     * Both are walked because the StrongBox attempt's failure is carried on `suppressed` by
     * [com.linecorp.webauthn.authenticator.keygenerator.Fido2KeyGenerator], so a cause-only walk would
     * miss the KeyMint code of the attempt that actually named it. Node identity is compared with `===`
     * so an exception overriding `equals` cannot collapse distinct links, and cyclic `cause` chains
     * terminate.
     */
    private fun Throwable.selfAndNested(): List<Throwable> {
        val visited = mutableListOf<Throwable>()
        val pending = ArrayDeque<Throwable>()
        pending.addLast(this)
        while (pending.isNotEmpty()) {
            val current = pending.removeLast()
            if (visited.any { it === current }) {
                continue
            }
            visited.add(current)
            // Pushed first, so they are popped last: the cause chain is explored ahead of suppressed.
            current.suppressed.forEach { pending.addLast(it) }
            current.cause?.let { pending.addLast(it) }
        }
        return visited
    }

    /** True when [this] is a platform keystore rejection rather than an SDK-level failure. */
    private fun Throwable.isKeystoreRejection(): Boolean = selfAndNested().any { it.isKeystoreFailureType() }

    /**
     * The bare type test that needs the lint suppression, and nothing else.
     *
     * `android.security.KeyStoreException` entered the public SDK in API 33, so lint rejects naming it
     * against this module's minSdk of 28. The check is still safe on 28-32: the class is present in the
     * platform there as a non-SDK class rather than absent - it is what the AndroidKeyStore provider
     * wraps its KeyMint failures in - and ART's hidden-API enforcement is per-member, so resolving the
     * type for an `is` test succeeds. Only `getNumericErrorCode` is genuinely new, and it is guarded on
     * `SDK_INT` in [numericKeyStoreErrorCode].
     *
     * Kept as its own function so the suppression covers three `is` expressions instead of a whole
     * function body: an API-gated call added to [isKeystoreRejection] later would otherwise be
     * unchecked too.
     */
    @SuppressLint("NewApi")
    private fun Throwable.isKeystoreFailureType(): Boolean = this is java.security.ProviderException ||
        this is android.security.KeyStoreException ||
        this is java.security.KeyStoreException

    /**
     * Walks the cause and suppressed chains for the KeyMint error code.
     *
     * `android.security.KeyStoreException.getNumericErrorCode()` was added in API 33, so it is read only
     * where it exists; the exception itself is present on older releases.
     */
    private fun Throwable.numericKeyStoreErrorCode(): Int? {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) {
            return null
        }
        for (current in selfAndNested()) {
            if (current is android.security.KeyStoreException) {
                return current.numericErrorCode
            }
        }
        return null
    }

    private companion object {
        /**
         * `BiometricPrompt` error codes that mean the ceremony ended without the user completing it.
         *
         * ERROR_USER_CANCELED and ERROR_NEGATIVE_BUTTON are unambiguous user dismissals.
         *
         * ERROR_CANCELED is included deliberately, and it is broader than a deliberate dismissal:
         * androidx documents it as the sensor being unavailable because the user was switched, the
         * device was locked, or another biometric operation is pending. On this library's minSdk,
         * androidx's own `BiometricFragment.onStop()` cancels the prompt and forwards ERROR_CANCELED to
         * the client, so **the host activity being stopped or the device locking is reported through
         * this code too.** It is kept in the set because production data shows real cancellations
         * arriving with it: of the observed cancellation samples, 15 were ERROR_USER_CANCELED, 7 were
         * ERROR_NEGATIVE_BUTTON and 2 were ERROR_CANCELED (the framework `fingerprint_error_canceled`
         * message), so excluding it would misreport those as SDK failures.
         *
         * The trade-off: a lifecycle-driven ERROR_CANCELED is now surfaced as user intent. That overlaps
         * with — and can mask — the case where the prompt never reached the user at all, which is why
         * that case carries its own distinct sentinel
         * ([com.linecorp.webauthn.handler.AuthenticationHandler.ERROR_HOST_STATE_SAVED]) instead of
         * being folded into ERROR_CANCELED.
         */
        private val USER_CANCELLED_ERROR_CODES = setOf(
            BiometricPrompt.ERROR_CANCELED,
            BiometricPrompt.ERROR_USER_CANCELED,
            BiometricPrompt.ERROR_NEGATIVE_BUTTON
        )
    }
}
