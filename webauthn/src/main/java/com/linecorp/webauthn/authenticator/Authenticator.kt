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

import android.content.Context
import android.content.pm.PackageManager
import androidx.fragment.app.FragmentActivity
import com.linecorp.webauthn.authenticator.keygenerator.Fido2KeyGenerator
import com.linecorp.webauthn.authenticator.objectgenerator.Fido2ObjectGenerator
import com.linecorp.webauthn.db.CredentialSourceStorage
import com.linecorp.webauthn.exceptions.WebAuthnException
import com.linecorp.webauthn.exceptions.biometricManagerStatusName
import com.linecorp.webauthn.exceptions.biometricPromptErrorName
import com.linecorp.webauthn.handler.AuthenticationHandler
import com.linecorp.webauthn.handler.BiometricAuthenticationHandler
import com.linecorp.webauthn.handler.DeviceCredentialAuthenticationHandler
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
    val cryptoDispatcher: CoroutineDispatcher = Dispatchers.Default,
) {

    /**
     * The list of supported public key credential parameters.
     */
    private val supportedCredParamsList: List<PublicKeyCredentialParams> =
        listOf(
            PublicKeyCredentialParams(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256),
        )

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
        // KeyStore access and key generation are blocking binder/crypto calls; keep them
        // off the caller's dispatcher (typically Main) to avoid ANRs.
        val (credIdBytes: ByteArray, credId: String) = withContext(cryptoDispatcher) { generateUniqueCredId() }
        var keyCreated = false
        try {
            val credTypeAndPubKeyAlg: PublicKeyCredentialParams = fetchCredTypeAndPubKeyAlg(credTypesAndPubKeyAlgs)
            checkAuthenticationSupport(activity.applicationContext)
            if (findExcludedCredential(rpEntity.id, excludeCredDescriptorList) != null) {
                // WebAuthn L2 6.3.2 step 3: collect an authorization gesture BEFORE
                // returning InvalidStateError, so a relying party cannot silently probe
                // whether a given credential exists on this device. If the user declines,
                // authenticate() maps the refusal to NotAllowedException as the spec
                // requires.
                authenticate(activity, authenticationHandler, fido2PromptInfo)
                throw WebAuthnException.CoreException.InvalidStateException(
                    message = "The credential is already registered."
                )
            }
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
            val keyPair = withContext(cryptoDispatcher) {
                fido2KeyGenerator.generateFido2Key(
                    keyAlias = keyAlias,
                    challenge = challenge,
                    publicKeyAlgorithm = credTypeAndPubKeyAlg.alg,
                    isStrongBoxBacked = isStrongBoxSupported(activity.applicationContext),
                )
            }
            keyCreated = true

            val fido2UserAuthResult = if (fmt != AttestationStatementFormat.NONE) {
                val signatureAlgorithm = credTypeAndPubKeyAlg.alg.getSignatureAlgorithmName()
                authenticate(activity, authenticationHandler, fido2PromptInfo) {
                    Signature.getInstance(signatureAlgorithm).apply { initSign(keyPair.private) }
                }
            } else {
                authenticate(activity, authenticationHandler, fido2PromptInfo)
            }

            val attestationObject: AttestationObject = withContext(cryptoDispatcher) {
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
            // Roll back the half-created credential, then let cancellation propagate
            // instead of being wrapped into a WebAuthnException, so structured
            // concurrency keeps working for the caller.
            if (keyCreated) {
                runCatching { cleanup(credId) }
            }
            throw e
        } catch (e: Throwable) {
            return handleMakeCredentialException(e, credId, keyCreated)
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

            // KeyStore access is a blocking binder call; keep it off the caller's dispatcher.
            val key = withContext(cryptoDispatcher) {
                SecureExecutionHelper.getKey(keyAlias)
            } ?: throw WebAuthnException.KeyNotFoundException(
                message = "Cannot get a key from device."
            )
            val signatureAlgorithm = withContext(cryptoDispatcher) {
                SecureExecutionHelper.getX509Certificate(keyAlias).sigAlgName
            }
            val fido2UserAuthResult = authenticate(activity, authenticationHandler, fido2PromptInfo) {
                Signature.getInstance(signatureAlgorithm).apply { initSign(key as PrivateKey) }
            }

            val processedExtensions = AuthenticatorExtensionsOutput.getAuthenticatorExtensionResult(extensions)

            try {
                withContext(databaseDispatcher) {
                    db.increaseSignatureCounter(credId)
                }
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
            } catch (e: Exception) {
                throw WebAuthnException.CredSrcStorageException(
                    "Failed to get signature counter for credId: $credId",
                    e
                )
            }

            val assertionObject: AssertionObject = withContext(cryptoDispatcher) {
                fido2ObjectGenerator.createAssertionObject(
                    hash = hash,
                    rpId = rpId,
                    signCount = signCount,
                    signature = fido2UserAuthResult.signature!!,
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
            // Let cancellation propagate for structured concurrency instead of
            // converting it into a WebAuthnException failure result.
            throw e
        } catch (e: Exception) {
            val authenticatorException = if (e is WebAuthnException) {
                e
            } else {
                WebAuthnException.UnknownException(
                    message = "An unknown error occurred.",
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
     * @return A pair containing the byte array and the base64url-encoded string of the credential ID.
     */
    private fun generateUniqueCredId(): Pair<ByteArray, String> {
        var credIdBytes: ByteArray
        var credId: String
        do {
            credIdBytes = Fido2Util.generateRandomByteArray(CRED_ID_SIZE)
            credId = credIdBytes.toBase64url()
        } while (SecureExecutionHelper.containAlias(credId))
        return Pair(credIdBytes, credId)
    }

    /**
     * Checks if authentication is supported by the device.
     *
     * @throws WebAuthnException.CoreException.ConstraintException If authentication is not supported by the device.
     */
    private fun checkAuthenticationSupport(context: Context) {
        if (!authenticationHandler.isSupported(context)) {
            // Preserve the raw BiometricManager.canAuthenticate() status so callers can
            // distinguish "nothing enrolled" from "no capable hardware" without a repro.
            // Diagnostic lookup must never change the primary failure, hence runCatching.
            val status: Int? = runCatching {
                when (val handler = authenticationHandler) {
                    is BiometricAuthenticationHandler -> handler.capabilityStatus(context)
                    is DeviceCredentialAuthenticationHandler -> handler.capabilityStatus(context)
                    else -> null
                }
            }.getOrNull()
            val detail = status?.let { " (capabilityStatus=$it ${biometricManagerStatusName(it)})" } ?: ""
            throw WebAuthnException.CoreException.ConstraintException(
                message = "Authentication is not supported by a device.$detail"
            ).apply { capabilityStatus = status }
        }
    }

    /**
     * Finds a credential from the exclude list that is already registered on this device.
     *
     * @param rpId The relying party ID.
     * @param excludeCredDescriptorList The list of credentials to exclude.
     * @return The first matching registered credential, or null when none of the excluded
     * credentials exist.
     */
    private suspend fun findExcludedCredential(
        rpId: String,
        excludeCredDescriptorList: List<PublicKeyCredentialDescriptor>?,
    ): PublicKeyCredentialSource? {
        if (excludeCredDescriptorList.isNullOrEmpty()) {
            return null
        }
        for (descriptor in excludeCredDescriptorList) {
            val credentialSource = try {
                withContext(databaseDispatcher) {
                    db.load(credId = descriptor.id)
                }
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
                return credentialSource
            }
        }
        return null
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
                } catch (e: Exception) {
                    throw WebAuthnException.CredSrcStorageException(
                        "Failed to load credential source for credId: $credId",
                        e
                    )
                }
                // Match type as well as rpId, mirroring the exclude-list check
                // (WebAuthn L2: allowCredentials entries are matched by type and id).
                if (credSource != null && credSource.rpId == rpId && credSource.type == descriptor.type) {
                    credOptions.add(credSource)
                }
            }
        } else {
            val credSourceList = try {
                withContext(databaseDispatcher) {
                    db.loadAll(authType.aaguid)
                }
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
            // Keep the base message stable for log grouping; append code + constant name
            // so services can act on the exact reason without a lookup table.
            val detail = e.errorCode?.let { " (errorCode=$it ${biometricPromptErrorName(it)})" } ?: ""
            throw WebAuthnException.CoreException.NotAllowedException(
                message = "Authentication failed$detail",
                cause = e
            ).apply { errorCode = e.errorCode }
        } catch (e: AuthenticationHandler.AuthenticationErrorException) {
            val detail = e.errorCode?.let { " (errorCode=$it ${biometricPromptErrorName(it)})" } ?: ""
            throw WebAuthnException.CoreException.NotAllowedException(
                message = "Authentication error is occurred.$detail",
                cause = e
            ).apply { errorCode = e.errorCode }
        } catch (e: android.security.keystore.KeyPermanentlyInvalidatedException) {
            throw WebAuthnException.AuthenticationException.KeyPermanentlyInvalidatedException(
                cause = e
            )
        }
    }

    /**
     * Cleans up by deleting a unnecessary credential.
     *
     * @param credId The credential ID.
     * @throws WebAuthnException.CredSrcStorageException If there is an error deleting the credential from the database.
     */
    suspend fun cleanup(credId: String) {
        // NonCancellable: this rollback must run to completion even when the calling
        // coroutine is already cancelled, otherwise the key and the DB row can get out
        // of sync (key deleted but row left behind, or vice versa).
        withContext(NonCancellable) {
            // The credId is already a base64url string and is used as the KeyStore alias
            // as-is (see makeCredential/getAssertion: keyAlias = credId). Re-encoding it
            // here would produce a different alias and silently skip deleting the key.
            val keyAlias = credId
            withContext(cryptoDispatcher) {
                SecureExecutionHelper.deleteKey(keyAlias)
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
     * @param credId The credential ID.
     * @param maxTries The maximum number of attempts.
     * @param delayMillis The delay between retries in milliseconds.
     */
    suspend fun retryCleanup(credId: String, maxTries: Int, delayMillis: Long) {
        repeat(maxTries) { attempt ->
            try {
                cleanup(credId)
                return
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
     * @param keyCreated True when a key pair was already generated for this credential.
     * @return A failure result containing the exception.
     */
    private suspend fun handleMakeCredentialException(
        e: Throwable,
        credId: String,
        keyCreated: Boolean,
    ): Result<AuthenticatorMakeCredentialResult> {
        val authenticatorException = if (e is WebAuthnException) {
            e
        } else {
            WebAuthnException.UnknownException(
                message = "An unknown error occurred.",
                cause = e
            )
        }

        if (!keyCreated) {
            // Nothing was persisted yet: skip cleanup so a pre-flight failure (unsupported
            // device, duplicate credential, ...) is not masked by a DeletionException from
            // deleting state that never existed.
            return Result.failure(authenticatorException)
        }

        return try {
            retryCleanup(credId, maxTries = 2, delayMillis = 1000)
            Result.failure(authenticatorException)
        } catch (e2: Throwable) {
            Result.failure(
                WebAuthnException.DeletionException(
                    "Error occurred while deleting key: $e2",
                    cause = e2,
                    trigger = authenticatorException
                )
            )
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
}
