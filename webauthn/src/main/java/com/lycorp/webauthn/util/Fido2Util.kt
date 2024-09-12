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

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.util.Base64
import com.lycorp.webauthn.exceptions.WebAuthnException
import java.io.ByteArrayInputStream
import java.io.InputStream
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

class Fido2Util {
    companion object {
        fun getPackageFacetID(context: Context): String {
            val cert: ByteArray = if (Build.VERSION.SDK_INT >= 33) {
                context.packageManager.getPackageInfo(
                    context.packageName,
                    PackageManager.PackageInfoFlags.of(PackageManager.GET_SIGNING_CERTIFICATES.toLong())
                ).signingInfo.apkContentsSigners[0].toByteArray()
            } else if (Build.VERSION.SDK_INT >= 28) {
                context.packageManager.getPackageInfo(
                    context.packageName,
                    PackageManager.GET_SIGNING_CERTIFICATES
                ).signingInfo.apkContentsSigners[0].toByteArray()
            } else {
                context.packageManager.getPackageInfo(
                    context.packageName,
                    PackageManager.GET_SIGNATURES
                ).signatures[0].toByteArray()
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

        fun generateRandomByteArray(numByte: Int): ByteArray {
            try {
                return ByteArray(numByte).also { SecureRandom().nextBytes(it) }
            } catch (e: Throwable) {
                throw WebAuthnException.UtilityException("Cannot generate random byte array.", e)
            }
        }
    }
}
