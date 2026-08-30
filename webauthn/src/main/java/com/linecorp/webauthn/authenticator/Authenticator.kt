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
     * Where AndroidKeyStore and KeyMint work runs. Key generation, alias lookups, key and certificate
     * reads, and signing are all synchronous binder round trips into keystore2 and from there into the TEE
     * or StrongBox, so they must never run on the caller's dispatcher.
     */
    val keystoreDispatcher: CoroutineDispatcher = Dispatchers.IO,
) {

    private val supportedCredParamsList: List<PublicKeyCredentialParams> =
        listOf(
            PublicKeyCredentialParams(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256),
        )

    /**
     * Runs [block] on [keystoreDispatcher], carrying a failure back as a value instead of throwing it across
     * the dispatcher hop.
     *
     * kotlinx.coroutines' stack-trace recovery *copies* an exception thrown across a coroutine boundary when
     * its class declares no fields of its own, which is true of `java.security.ProviderException` and
     * `android.security.KeyStoreException`. Consumers read `WebAuthnException.KeyGenerationException.cause`
     * to reach the platform failure, so unwrapping a [Result] on this side of the hop is what keeps the
     * original instance, with its own fields and stack trace.
     *
     * `runCatching` cannot swallow cancellation here: [block] is synchronous keystore work with no
     * suspension point, and `withContext` raises a cancellation of the surrounding scope before the result
     * is unwrapped.
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
            // `keyCommitted` is set inside the block rather than from its result: `withContext` discards a
            // value computed after the job was cancelled, and the key exists on the device either way.
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

            // Reads the public key and, for the android-key format, the attestation certificate chain out of
            // the keystore, then signs. The signing operation was authorised by `initSign` on the main
            // thread above; finishing it on another dispatcher is safe because KeyMint operations are not
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
            // A key that reached the keystore has to go with the cancelled scope: `credId` is its alias and
            // nothing outside this frame knows it, so a key left behind could never be named, or deleted,
            // again.
            //
            // `cleanup` rather than `retryCleanup`: cleanup's terminal operations are uncancellable and run
            // to completion here, whereas a retry's `delay` would hold the FragmentActivity and the
            // process-wide create/get mutex for another second after the caller gave up.
            if (keyCommitted) {
                try {
                    cleanup(credId)
                } catch (cleanupFailure: Throwable) {
                    // Suppressed rather than thrown: a cancelled coroutine has to complete with a
                    // CancellationException.
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

            // `initSign` stays inside the handler on the main dispatcher below: it is what consumes the
            // user's authentication, and on API < 30 the device-credential key is time-authorised for five
            // seconds, so an extra hop between the keyguard result and `initSign` can turn a successful
            // ceremony into a UserNotAuthenticatedException.
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
            // Checked before the signature counter is advanced, so the counter stays a record of assertions
            // the relying party can actually have seen.
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
            // Rethrown, never a Result.failure: cancellation is the caller's own scope ending, not an
            // assertion failure. Nothing to clean up - getAssertion creates no key material.
            throw e
        } catch (e: Exception) {
            val authenticatorException = if (e is WebAuthnException) {
                e
            } else {
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
     * @param activity The activity context used for UI operations.
     * @param authenticationHandler The handler for authentication.
     * @param fido2PromptInfo The prompt information for FIDO2 authentication.
     * @param signatureProvider The provider for the signature.
     * @return The result of the user authentication.
     * @throws WebAuthnException.CoreException.NotAllowedException If authentication fails or if an authentication error occurs.
     * @throws WebAuthnException.CoreException.UserCancelledException If the user dismissed the prompt.
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
     * Deletes a credential's key material and its database row.
     *
     * [credId] **is** the KeyStore alias, used verbatim; it is already base64url. Encoding it again names
     * an alias no key was stored under, and `KeyStore.deleteEntry` is a silent no-op for an unknown alias,
     * so cleanup would report success and leave the private key behind.
     *
     * A missing alias counts as success ([SecureExecutionHelper.deleteKeyIfPresent]), so [retryCleanup]'s
     * second attempt - which legitimately finds the key already gone - cannot replace the error that
     * triggered it.
     *
     * Both deletions run [NonCancellable]: on a cancelled scope each `withContext` would otherwise throw
     * before doing anything, stranding a private key whose only name is [credId]. They are not wrapped in a
     * `withTimeout`, because cancellation cannot interrupt a blocking call, so the timeout would bound
     * nothing - and against a storage implementation that *is* cancellable it would abort the very deletion
     * [NonCancellable] exists to protect.
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
            // run. The triggering failure rides along so it still appears in a printed stack trace - a
            // KeyGenerationException carries the KeyMint error code and is the only record of it. The
            // identity guard is required because `addSuppressed` throws IllegalArgumentException when handed
            // the same instance.
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
                // `keyCommitted` is only set once `generateFido2Key` returned, so cleanup still runs here: a
                // generator that reached the keystore and then threw would leave a key under an alias
                // nothing outside this frame knows. Only the reported failure changes -
                // `CredentialSourceStorage.delete` is not required to be idempotent, and a consumer that
                // throws for an unknown id must not turn a pre-flight ConstraintException, which the caller
                // routes to biometric enrolment, into a DeletionException.
                if (authenticatorException !== e2) {
                    authenticatorException.addSuppressed(e2)
                }
                Result.failure(authenticatorException)
            }
        }
    }

    private fun isStrongBoxSupported(context: Context): Boolean =
        context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)

    /**
     * Every throwable reachable from [this], following `cause` before `suppressed`, never revisiting a node.
     *
     * `suppressed` is walked because [com.linecorp.webauthn.authenticator.keygenerator.Fido2KeyGenerator]
     * carries the StrongBox attempt's failure there, so a cause-only walk would miss the KeyMint code of the
     * attempt that actually named it. Node identity is compared with `===` so an exception overriding
     * `equals` cannot collapse distinct links, and cyclic `cause` chains terminate.
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

    private fun Throwable.isKeystoreRejection(): Boolean = selfAndNested().any { it.isKeystoreFailureType() }

    /**
     * `android.security.KeyStoreException` entered the public SDK in API 33, so lint rejects naming it
     * against this module's minSdk of 28. The `is` test is still safe on 28-32: the class is present in the
     * platform there as a non-SDK class rather than absent - it is what the AndroidKeyStore provider wraps
     * its KeyMint failures in - and ART's hidden-API enforcement is per-member, so resolving the type for an
     * `is` test succeeds. Only `getNumericErrorCode` is genuinely new, and it is guarded on `SDK_INT` in
     * [numericKeyStoreErrorCode].
     *
     * Kept as its own function so the suppression covers these type tests and nothing else.
     */
    @SuppressLint("NewApi")
    private fun Throwable.isKeystoreFailureType(): Boolean = this is java.security.ProviderException ||
        this is android.security.KeyStoreException ||
        this is java.security.KeyStoreException

    /** `android.security.KeyStoreException.getNumericErrorCode()` was added in API 33, hence the guard. */
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
         * ERROR_CANCELED is broader than a deliberate dismissal: androidx documents it as the sensor being
         * unavailable, and its own `BiometricFragment.onStop()` forwards it when the host activity stops or
         * the device locks. It is kept in the set because real user cancellations arrive with it, at the
         * cost of surfacing a lifecycle cancellation as user intent - a prompt that never reached the user
         * carries its own sentinel
         * ([com.linecorp.webauthn.handler.AuthenticationHandler.ERROR_HOST_STATE_SAVED]) instead.
         */
        private val USER_CANCELLED_ERROR_CODES = setOf(
            BiometricPrompt.ERROR_CANCELED,
            BiometricPrompt.ERROR_USER_CANCELED,
            BiometricPrompt.ERROR_NEGATIVE_BUTTON
        )
    }
}
