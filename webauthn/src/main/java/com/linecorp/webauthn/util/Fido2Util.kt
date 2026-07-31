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

import android.content.Context
import android.content.pm.PackageManager
import android.content.pm.SigningInfo
import android.os.Build
import android.util.Base64
import com.linecorp.webauthn.exceptions.WebAuthnException
import java.io.ByteArrayInputStream
import java.io.InputStream
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

class Fido2Util {
    companion object {
        /**
         * The calling package's facet ID, as used for the `origin` of the collected client data.
         *
         * The returned string is part of the signed `clientDataJSON` that the relying party verifies, so
         * neither the hash nor the encoding may change. Only the failure behaviour did: the signing
         * information used to be dereferenced with `!!`, which surfaced a missing or unsigned package as a
         * raw `NullPointerException` — or, for an empty signer array, an
         * `ArrayIndexOutOfBoundsException` — from a function documented to throw
         * [WebAuthnException.UtilityException].
         *
         * This does a PackageManager binder round trip, an X.509 parse and a SHA-256, so callers run it off
         * the main thread.
         *
         * @throws WebAuthnException.UtilityException If the calling package has no usable signing certificate.
         */
        fun getPackageFacetID(context: Context): String {
            val cert: ByteArray = if (Build.VERSION.SDK_INT >= 33) {
                firstApkContentsSigner(
                    context.packageManager.getPackageInfo(
                        context.packageName,
                        PackageManager.PackageInfoFlags.of(PackageManager.GET_SIGNING_CERTIFICATES.toLong())
                    ).signingInfo
                )
            } else {
                firstApkContentsSigner(
                    context.packageManager.getPackageInfo(
                        context.packageName,
                        PackageManager.GET_SIGNING_CERTIFICATES
                    ).signingInfo
                )
            }
            val input: InputStream = ByteArrayInputStream(cert)
            val cf = CertificateFactory.getInstance("X509")
            val certificate: X509Certificate = cf.generateCertificate(input) as X509Certificate
            val md = MessageDigest.getInstance("SHA256")
            val hash = md.digest(certificate.encoded)

            // According to the "FIDO AppID and Facet Specification" v2.0 specification draft
            // Supposed to be default (non URL safe) encoding
            return "android:apk-key-hash-sha256:" +
                Base64.encodeToString(hash, Base64.DEFAULT or Base64.NO_WRAP or Base64.NO_PADDING)
        }

        /**
         * The first APK contents signer of [signingInfo], which is the certificate the facet ID hashes.
         *
         * Shared by both API branches of [getPackageFacetID] so that they cannot drift apart; the value
         * returned is the same one the two `!!` dereferences used to produce.
         */
        private fun firstApkContentsSigner(signingInfo: SigningInfo?): ByteArray {
            if (signingInfo == null) {
                throw WebAuthnException.UtilityException("No signing info available for the calling package.")
            }
            val signers = signingInfo.apkContentsSigners
            if (signers.isNullOrEmpty()) {
                throw WebAuthnException.UtilityException("The calling package has no APK content signers.")
            }
            return signers[0].toByteArray()
        }

        fun generateRandomByteArray(numByte: Int): ByteArray {
            try {
                return ByteArray(numByte).also { SecureRandom().nextBytes(it) }
            } catch (e: Throwable) {
                throw WebAuthnException.UtilityException("Cannot generate random byte array.", e)
            }
        }
    }
}
