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

package com.linecorp.webauthn.authenticator.keygenerator

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import com.linecorp.webauthn.model.COSEAlgorithmIdentifier
import com.linecorp.webauthn.model.getAlgorithmParameterSpec
import com.linecorp.webauthn.model.getDigests
import com.linecorp.webauthn.model.getKeyProperties
import com.linecorp.webauthn.model.getSignaturePaddings
import java.security.KeyPair
import java.security.KeyPairGenerator

class BiometricKeyGenerator : Fido2KeyGenerator() {

    override fun generateFido2Key(
        keyAlias: String,
        challenge: ByteArray?,
        publicKeyAlgorithm: COSEAlgorithmIdentifier,
        isStrongBoxBacked: Boolean,
        userAuthenticationRequired: Boolean
    ): KeyPair = generateWithStrongBoxFallback(isStrongBoxBacked) { strongBox ->
        generateBiometricFido2Key(keyAlias, challenge, publicKeyAlgorithm, strongBox, userAuthenticationRequired)
    }

    private fun generateBiometricFido2Key(
        keyAlias: String,
        challenge: ByteArray?,
        publicKeyAlgorithm: COSEAlgorithmIdentifier,
        isStrongBoxBacked: Boolean,
        userAuthenticationRequired: Boolean
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
                    KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
                ).run {
                    setIsStrongBoxBacked(isStrongBoxBacked)
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
                    if (challenge != null) {
                        setAttestationChallenge(challenge)
                    }
                    build()
                }
            kpg.initialize(parameterSpec)
            return kpg.generateKeyPair()
        }
    }
}
