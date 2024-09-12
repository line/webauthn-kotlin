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

package com.lycorp.webauthn.util

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import com.lycorp.webauthn.exceptions.WebAuthnException
import com.lycorp.webauthn.model.COSEAlgorithmIdentifier
import com.lycorp.webauthn.model.getAlgorithmParameterSpec
import com.lycorp.webauthn.model.getDigests
import com.lycorp.webauthn.model.getKeyProperties
import com.lycorp.webauthn.model.getSignaturePaddings
import java.security.Key
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.KeyStoreException
import java.security.PublicKey
import java.security.cert.X509Certificate

/**
 * Helper class for secure execution
 */
internal object SecureExecutionHelper {
    private val lock = Any()

    fun generateKey(
        keyAlias: String,
        challenge: ByteArray,
        publicKeyAlgorithm: COSEAlgorithmIdentifier,
        useBiometricOnly: Boolean,
        userAuthenticationValidityDurationSeconds: Int = 0,
        userAuthenticationRequired: Boolean = true,
        isStrongBoxBacked: Boolean = false,
        purpose: Int = KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
    ): KeyPair {
        return if (isStrongBoxBacked && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            return try {
                generateKeyWithOption(
                    keyAlias,
                    challenge,
                    publicKeyAlgorithm,
                    useBiometricOnly,
                    userAuthenticationValidityDurationSeconds,
                    userAuthenticationRequired,
                    purpose,
                    true
                )
            } catch (e: StrongBoxUnavailableException) {
                generateKeyWithOption(
                    keyAlias,
                    challenge,
                    publicKeyAlgorithm,
                    useBiometricOnly,
                    userAuthenticationValidityDurationSeconds,
                    userAuthenticationRequired,
                    purpose,
                    false
                )
            }
        } else {
            generateKeyWithOption(
                keyAlias,
                challenge,
                publicKeyAlgorithm,
                useBiometricOnly,
                userAuthenticationValidityDurationSeconds,
                userAuthenticationRequired,
                purpose,
                false
            )
        }
    }

    private fun generateKeyWithOption(
        keyAlias: String,
        challenge: ByteArray,
        publicKeyAlgorithm: COSEAlgorithmIdentifier,
        useBiometricOnly: Boolean,
        userAuthenticationValidityDurationSeconds: Int = 0,
        userAuthenticationRequired: Boolean = true,
        purpose: Int = KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
        isStrongBoxBacked: Boolean = false,
    ): KeyPair {
        synchronized(lock) {
            val keyProperties = publicKeyAlgorithm.getKeyProperties()
                ?: throw IllegalArgumentException("Unsupported algorithm")
            val kpg: KeyPairGenerator =
                KeyPairGenerator.getInstance(
                    keyProperties,
                    "AndroidKeyStore",
                )
            val parameterSpec: KeyGenParameterSpec =
                KeyGenParameterSpec.Builder(
                    keyAlias,
                    purpose,
                ).run {
                    if (isStrongBoxBacked && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                        setIsStrongBoxBacked(true)
                    }
                    publicKeyAlgorithm.getSignaturePaddings()?.let {
                        setSignaturePaddings(it)
                    }
                    publicKeyAlgorithm.getAlgorithmParameterSpec()?.let {
                        setAlgorithmParameterSpec(it)
                    }
                    publicKeyAlgorithm.getDigests()?.let {
                        setDigests(it)
                    }
                    setUserAuthenticationRequired(userAuthenticationRequired)
                    setInvalidatedByBiometricEnrollment(true)
                    if (!useBiometricOnly) {
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                            setUserAuthenticationParameters(
                                0,
                                KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL
                            )
                        } else {
                            setUserAuthenticationValidityDurationSeconds(userAuthenticationValidityDurationSeconds)
                        }
                    }
                    setAttestationChallenge(challenge)
                    build()
                }
            kpg.initialize(parameterSpec)
            return kpg.generateKeyPair()
        }
    }

    fun deleteKey(keyAlias: String) {
        synchronized(lock) {
            try {
                KeyStore.getInstance("AndroidKeyStore").also {
                    it.load(null)
                    it.deleteEntry(keyAlias)
                }
            } catch (e: Throwable) {
                throw WebAuthnException.SecureExecutionException("Cannot delete key from KeyStore.", e)
            }
        }
    }

    fun getKey(keyAlias: String): Key? {
        synchronized(lock) {
            try {
                val keyStore =
                    KeyStore.getInstance("AndroidKeyStore").also {
                        it.load(null, null)
                    }
                return keyStore.getKey(keyAlias, null)
            } catch (e: Throwable) {
                throw WebAuthnException.SecureExecutionException("Cannot fetch key from KeyStore.", e)
            }
        }
    }

    fun getX509Certificates(keyAlias: String): List<X509Certificate> {
        synchronized(lock) {
            try {
                val keyStore =
                    KeyStore.getInstance("AndroidKeyStore").also {
                        it.load(null, null)
                    }
                val certChain = keyStore.getCertificateChain(keyAlias)
                    ?: throw KeyStoreException("Cannot find certificate chain")
                val certChainList = certChain.toList()
                return certChainList.map { it as X509Certificate }
            } catch (e: Throwable) {
                throw WebAuthnException.SecureExecutionException("Cannot fetch X509 certificate from KeyStore.", e)
            }
        }
    }

    fun getX509Certificate(keyAlias: String): X509Certificate {
        synchronized(lock) {
            try {
                val keyStore =
                    KeyStore.getInstance("AndroidKeyStore").also {
                        it.load(null, null)
                    }
                val certificate = keyStore.getCertificate(keyAlias)
                    ?: throw KeyStoreException("Cannot find certificate")
                return certificate as X509Certificate
            } catch (e: Throwable) {
                throw WebAuthnException.SecureExecutionException("Cannot fetch X509 certificate from KeyStore.", e)
            }
        }
    }

    fun containAlias(keyAlias: String): Boolean {
        synchronized(lock) {
            try {
                val keyStore =
                    KeyStore.getInstance("AndroidKeyStore").also {
                        it.load(null, null)
                    }
                return keyStore.containsAlias(keyAlias)
            } catch (e: Throwable) {
                throw WebAuthnException.SecureExecutionException("Cannot check key alias from KeyStore.", e)
            }
        }
    }

    fun getPublicKey(keyAlias: String): PublicKey {
        try {
            val x509CertificateChain = getX509Certificates(keyAlias)
            return x509CertificateChain[0].publicKey
        } catch (e: Throwable) {
            throw WebAuthnException.SecureExecutionException("Cannot fetch public key from KeyStore.", e)
        }
    }
}
