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

import com.linecorp.webauthn.exceptions.WebAuthnException
import java.security.Key
import java.security.KeyStore
import java.security.KeyStoreException
import java.security.PublicKey
import java.security.cert.X509Certificate

/**
 * Helper class for secure execution
 */
internal object SecureExecutionHelper {
    private val lock = Any()

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

    /** Deletes [keyAlias] if it exists. Unlike [deleteKey] this never throws for a missing alias. */
    fun deleteKeyIfPresent(keyAlias: String) {
        if (containAlias(keyAlias)) {
            deleteKey(keyAlias)
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
