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

package com.lycorp.webauthn.authenticator

import android.content.pm.PackageManager
import androidx.fragment.app.FragmentActivity
import com.lycorp.webauthn.db.CredentialSourceStorage
import com.lycorp.webauthn.exceptions.WebAuthnException
import com.lycorp.webauthn.handler.AuthenticationHandler
import com.lycorp.webauthn.handler.BiometricAuthenticationHandler
import com.lycorp.webauthn.model.AuthenticatorExtensionsInput
import com.lycorp.webauthn.model.AuthenticatorExtensionsOutput
import com.lycorp.webauthn.model.AuthenticatorGetAssertionResult
import com.lycorp.webauthn.model.AuthenticatorMakeCredentialResult
import com.lycorp.webauthn.model.AuthenticatorType
import com.lycorp.webauthn.model.COSEAlgorithmIdentifier
import com.lycorp.webauthn.model.Fido2PromptInfo
import com.lycorp.webauthn.model.Fido2UserAuthResult
import com.lycorp.webauthn.model.PublicKeyCredentialDescriptor
import com.lycorp.webauthn.model.PublicKeyCredentialParams
import com.lycorp.webauthn.model.PublicKeyCredentialRpEntity
import com.lycorp.webauthn.model.PublicKeyCredentialSource
import com.lycorp.webauthn.model.PublicKeyCredentialType
import com.lycorp.webauthn.model.PublicKeyCredentialUserEntity
import com.lycorp.webauthn.model.getSignatureAlgorithmName
import com.lycorp.webauthn.util.CRED_ID_SIZE
import com.lycorp.webauthn.util.Fido2Util
import com.lycorp.webauthn.util.SecureExecutionHelper
import com.lycorp.webauthn.util.base64urlToByteArray
import com.lycorp.webauthn.util.toBase64url
import java.security.KeyPair
import java.security.PrivateKey
import java.security.Signature
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext

/**
 * Abstract class representing a FIDO2 authenticator.
 * Provides methods for credential creation and assertion.
 */
internal abstract class Authenticator(
    protected open val activity: FragmentActivity,
    open val db: CredentialSourceStorage,
    protected open var fido2PromptInfo: Fido2PromptInfo? = null,
    protected open val databaseDispatcher: CoroutineDispatcher = Dispatchers.IO,
    protected open val fido2ObjectFactory: Fido2ObjectFactory = Fido2ObjectFactory(),
    protected open val authenticationHandler: AuthenticationHandler,
) {
    /**
     * The type of the authenticator.
     */
    abstract val authType: AuthenticatorType

    /**
     * The list of supported public key credential parameters.
     */
    protected open var supportedCredParamsList: List<PublicKeyCredentialParams> =
        listOf(
            PublicKeyCredentialParams(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256),
        )

    /**
     * Creates a new credential.
     *
     * This method implements the `authenticatorMakeCredential` operation as defined in the Web Authentication: An API for accessing Public Key Credentials Level 2 specification.
     * For more details, see the specification: [Web Authentication: Level 2 - Create](https://www.w3.org/TR/webauthn-2/#authenticatormakecredential)
     *
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
        hash: ByteArray,
        rpEntity: PublicKeyCredentialRpEntity,
        userEntity: PublicKeyCredentialUserEntity,
        credTypesAndPubKeyAlgs: List<PublicKeyCredentialParams>,
        excludeCredDescriptorList: List<PublicKeyCredentialDescriptor>?,
        extensions: AuthenticatorExtensionsInput?,
    ): Result<AuthenticatorMakeCredentialResult> {
        val pubKeyAlgAndCredType: PublicKeyCredentialParams =
            credTypesAndPubKeyAlgs.firstOrNull { it in supportedCredParamsList }
                ?: throw WebAuthnException.CoreException.NotSupportedException(
                    message = "The credential type and public key algorithm are not supported."
                )

        val wasNotRegistered = checkCredentialWasNotRegistered(rpEntity.id, excludeCredDescriptorList)
        if (!wasNotRegistered) {
            throw WebAuthnException.CoreException.InvalidStateException(
                message = "The credential is already registered."
            )
        }

        if (!authenticationHandler.isSupported()) {
            throw WebAuthnException.CoreException.ConstraintException(
                message = "Authentication is not supported by a device."
            )
        }

        // Generate a unique credential ID
        var credIdBytes: ByteArray
        var keyAlias: String
        var credId: String
        do {
            credIdBytes = Fido2Util.generateRandomByteArray(CRED_ID_SIZE)
            credId = credIdBytes.toBase64url()
            keyAlias = credId.toBase64url()
        } while (SecureExecutionHelper.containAlias(keyAlias))

        try {
            val isStrongBoxBacked = activity.applicationContext.packageManager.hasSystemFeature(
                PackageManager.FEATURE_STRONGBOX_KEYSTORE
            )

            val keyPair = generateFido2Key(
                keyAlias = keyAlias,
                challenge = hash,
                pubKeyAlg = pubKeyAlgAndCredType.alg,
                isStrongBoxBacked = isStrongBoxBacked,
            )

            val signatureAlgorithm = pubKeyAlgAndCredType.alg.getSignatureAlgorithmName()

            val fido2UserAuthResult = authenticateUser(
                authenticationHandler,
                { Signature.getInstance(signatureAlgorithm).apply { initSign(keyPair.private) } },
                fido2PromptInfo,
            )

            val newCredential = PublicKeyCredentialSource(
                type = pubKeyAlgAndCredType.type.value,
                id = credId,
                rpId = rpEntity.id,
                userHandle = userEntity.id,
                aaguid = authType.aaguid,
            )

            val processedExtensions = AuthenticatorExtensionsOutput.getAuthenticatorExtensionResult(extensions)

            val attestationObject = fido2ObjectFactory.createAttestationObject(
                hash = hash,
                rpId = rpEntity.id,
                aaguid = authType.aaguidBytes(),
                credId = credId,
                signCount = 0u,
                signature = fido2UserAuthResult.signature ?: throw WebAuthnException.AuthenticationException(
                    message = "CryptoObject does not include signature.",
                ),
                extensions = processedExtensions,
            )

            try {
                withContext(databaseDispatcher) {
                    db.store(newCredential)
                }
            } catch (e: Exception) {
                throw WebAuthnException.CredSrcStorageException("Failed to store new credential for credId: $credId", e)
            }

            return Result.success(
                AuthenticatorMakeCredentialResult(
                    credentialId = credIdBytes,
                    attestationObject = attestationObject.toCBOR(),
                )
            )
        } catch (e: Throwable) {
            val authenticatorException = if (e is WebAuthnException) {
                e
            } else {
                WebAuthnException.UnknownException(
                    message = "An unknown error occurred.",
                    cause = e
                )
            }

            try {
                retryCleanup(credId, maxTries = 2, delayMillis = 1000)
            } catch (e2: Throwable) {
                return Result.failure(
                    WebAuthnException.DeletionException(
                        "Error occurred while deleting key: $e2",
                        cause = e2,
                        trigger = authenticatorException
                    )
                )
            }

            return Result.failure(authenticatorException)
        }
    }

    /**
     * Gets an assertion for authentication.
     *
     * This method implements the `authenticatorGetAssertion` operation as defined in the Web Authentication: An API for accessing Public Key Credentials Level 2 specification.
     * For more details, see the specification: [Web Authentication: Level 2 - Get](https://www.w3.org/TR/webauthn-2/#sctn-op-get-assertion)
     *
     * @param rpId The relying party ID.
     * @param hash The hash to sign.
     * @param allowCredDescriptorList The list of allowed credentials.
     * @param extensions The authenticator extensions input.
     * @return The result of the assertion process.
     * @throws WebAuthnException If an error occurs during the assertion process.
     */
    suspend fun getAssertion(
        rpId: String,
        hash: ByteArray,
        allowCredDescriptorList: List<PublicKeyCredentialDescriptor>?,
        extensions: AuthenticatorExtensionsInput?,
    ): Result<AuthenticatorGetAssertionResult> {
        val credOptions: List<PublicKeyCredentialSource> = checkCredentialWasRegistered(rpId, allowCredDescriptorList)
        if (credOptions.isEmpty()) {
            throw WebAuthnException.CoreException.NotAllowedException(
                message = "No credential found for the given RP ID."
            )
        }
        val selectedCred: PublicKeyCredentialSource = credOptions[0]
        val credId: String = selectedCred.id
        val keyAlias: String = credId.toBase64url()

        if (!authenticationHandler.isSupported()) {
            throw WebAuthnException.CoreException.ConstraintException(
                message = "Authentication is not supported by a device."
            )
        }
        val key = SecureExecutionHelper.getKey(keyAlias) ?: throw WebAuthnException.KeyNotFoundException(
            message = "Cannot get a key from device."
        )
        val signatureAlgorithm = SecureExecutionHelper.getX509Certificate(keyAlias).sigAlgName
        val fido2UserAuthResult = authenticateUser(
            authenticationHandler,
            { Signature.getInstance(signatureAlgorithm).apply { initSign(key as PrivateKey) } },
            fido2PromptInfo,
        )

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
            throw WebAuthnException.CredSrcStorageException("Failed to get signature counter for credId: $credId", e)
        }

        val assertionObject =
            fido2ObjectFactory.createAssertionObject(
                hash = hash,
                rpId = rpId,
                signCount = signCount,
                signature = fido2UserAuthResult.signature ?: throw WebAuthnException.AuthenticationException(
                    message = "CryptoObject does not include signature.",
                ),
                extensions = processedExtensions
            )

        return Result.success(
            AuthenticatorGetAssertionResult(
                credentialId = credId.base64urlToByteArray(),
                authenticatorData = assertionObject.authenticatorData,
                signature = assertionObject.signature,
                userHandle = selectedCred.userHandle?.base64urlToByteArray(),
            )
        )
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
    ): Boolean {
        if (excludeCredDescriptorList.isNullOrEmpty()) {
            return true
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
                return false
            }
        }
        return true
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
    ): List<PublicKeyCredentialSource> {
        val credOptions: MutableList<PublicKeyCredentialSource> = mutableListOf()
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
                if (credSource != null && credSource.rpId == rpId) {
                    credOptions.add(credSource)
                }
            }
        } else {
            val credSourceList = try {
                withContext(databaseDispatcher) {
                    db.loadAll()
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
        return credOptions
    }

    protected abstract fun generateFido2Key(
        keyAlias: String,
        challenge: ByteArray,
        pubKeyAlg: COSEAlgorithmIdentifier,
        isStrongBoxBacked: Boolean,
    ): KeyPair

    /**
     * Authenticates the user, enabling the use of keys for signing.
     *
     * This method performs user authentication using the provided authentication handler.
     * The process includes handling initial signatures and displaying prompt information for FIDO2 authentication.
     *
     * @param authenticationHandler The handler for authentication.
     * @param signatureProvider The provider for the signature.
     * @param fido2PromptInfo The prompt information for FIDO2 authentication.
     * @return The result of the user authentication.
     * @throws WebAuthnException.CoreException.NotAllowedException If authentication fails or if an authentication error occurs.
     */
    protected suspend fun authenticateUser(
        authenticationHandler: AuthenticationHandler,
        signatureProvider: () -> Signature,
        fido2PromptInfo: Fido2PromptInfo?,
    ): Fido2UserAuthResult {
        try {
            return authenticationHandler.authenticate(signatureProvider, fido2PromptInfo)
        } catch (e: BiometricAuthenticationHandler.AuthenticationFailedException) {
            throw WebAuthnException.CoreException.NotAllowedException(
                message = "Authentication failed"
            )
        } catch (e: BiometricAuthenticationHandler.AuthenticationErrorException) {
            throw WebAuthnException.CoreException.NotAllowedException(
                message = "Authentication error is occurred."
            )
        }
    }

    /**
     * Cleans up by deleting a unnecessary credential.
     *
     * @param credId The credential ID.
     * @throws WebAuthnException.CredSrcStorageException If there is an error deleting the credential from the database.
     */
    private suspend fun cleanup(credId: String) {
        val keyAlias = credId.toBase64url()
        SecureExecutionHelper.deleteKey(keyAlias)
        try {
            withContext(databaseDispatcher) {
                db.delete(credId = credId)
            }
        } catch (e: Exception) {
            throw WebAuthnException.CredSrcStorageException("Failed to delete credential for credId: $credId", e)
        }
    }

    /**
     * Retries cleanup in case of failure.
     *
     * @param credId The credential ID.
     * @param maxTries The maximum number of attempts.
     * @param delayMillis The delay between retries in milliseconds.
     */
    private suspend fun retryCleanup(credId: String, maxTries: Int, delayMillis: Long) {
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
}
