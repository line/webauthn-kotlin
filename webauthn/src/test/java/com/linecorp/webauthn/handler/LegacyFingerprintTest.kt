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

@file:Suppress("DEPRECATION")

package com.linecorp.webauthn.handler

import android.app.KeyguardManager
import android.content.Context
import android.content.pm.PackageManager
import android.content.res.Resources
import android.hardware.fingerprint.FingerprintManager
import com.google.common.truth.Truth.assertThat
import io.mockk.every
import io.mockk.mockk
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class LegacyFingerprintTest {

    private val context = mockk<Context>()
    private val packageManager = mockk<PackageManager>()
    private val keyguardManager = mockk<KeyguardManager>()
    private val fingerprintManager = mockk<FingerprintManager>()
    private val resources = mockk<Resources>()

    @BeforeEach
    fun setUp() {
        every { context.packageManager } returns packageManager
        every { packageManager.hasSystemFeature(PackageManager.FEATURE_FINGERPRINT) } returns true
        every { context.getSystemService(KeyguardManager::class.java) } returns keyguardManager
        every { keyguardManager.isDeviceSecure } returns true
        every { context.getSystemService(FingerprintManager::class.java) } returns fingerprintManager
        every { fingerprintManager.isHardwareDetected } returns true
        every { fingerprintManager.hasEnrolledFingerprints() } returns true
        every { context.resources } returns resources
        every {
            resources.getStringArray(androidx.biometric.R.array.crypto_fingerprint_fallback_vendors)
        } returns arrayOf("samsung")
        every {
            resources.getStringArray(androidx.biometric.R.array.crypto_fingerprint_fallback_prefixes)
        } returns emptyArray()
        every {
            resources.getStringArray(androidx.biometric.R.array.hide_fingerprint_instantly_prefixes)
        } returns arrayOf("SM-G973", "SM-G975")
    }

    @Test
    fun `isAvailable is true with a secure lock screen and an enrolled fingerprint`() {
        assertThat(LegacyFingerprint.isAvailable(context)).isTrue()
    }

    @Test
    fun `isAvailable is false without the fingerprint feature`() {
        every { packageManager.hasSystemFeature(PackageManager.FEATURE_FINGERPRINT) } returns false
        assertThat(LegacyFingerprint.isAvailable(context)).isFalse()
    }

    @Test
    fun `isAvailable is false without a secure lock screen`() {
        every { keyguardManager.isDeviceSecure } returns false
        assertThat(LegacyFingerprint.isAvailable(context)).isFalse()
    }

    @Test
    fun `isAvailable is false when the fingerprint hardware is not detected`() {
        every { fingerprintManager.isHardwareDetected } returns false
        assertThat(LegacyFingerprint.isAvailable(context)).isFalse()
    }

    @Test
    fun `isAvailable is false when no fingerprint is enrolled`() {
        every { fingerprintManager.hasEnrolledFingerprints() } returns false
        assertThat(LegacyFingerprint.isAvailable(context)).isFalse()
    }

    @Test
    fun `isAvailable is false when the fingerprint service is missing`() {
        every { context.getSystemService(FingerprintManager::class.java) } returns null
        assertThat(LegacyFingerprint.isAvailable(context)).isFalse()
    }

    @Test
    fun `fingerprint is required for crypto only on listed vendors running API 28`() {
        assertThat(LegacyFingerprint.requiresFingerprintForCrypto(context, 28, "samsung", "SM-G960F")).isTrue()
        assertThat(LegacyFingerprint.requiresFingerprintForCrypto(context, 28, "SAMSUNG", "SM-G960F")).isTrue()
        assertThat(LegacyFingerprint.requiresFingerprintForCrypto(context, 29, "samsung", "SM-G960F")).isFalse()
        assertThat(LegacyFingerprint.requiresFingerprintForCrypto(context, 30, "samsung", "SM-G960F")).isFalse()
        assertThat(LegacyFingerprint.requiresFingerprintForCrypto(context, 28, "Google", "Pixel 3")).isFalse()
        assertThat(LegacyFingerprint.requiresFingerprintForCrypto(context, 28, null, null)).isFalse()
    }

    @Test
    fun `fingerprint is required for crypto on listed model prefixes running API 28`() {
        every {
            resources.getStringArray(androidx.biometric.R.array.crypto_fingerprint_fallback_prefixes)
        } returns arrayOf("ABC-")
        assertThat(LegacyFingerprint.requiresFingerprintForCrypto(context, 28, "vendor", "ABC-100")).isTrue()
        assertThat(LegacyFingerprint.requiresFingerprintForCrypto(context, 28, "vendor", "XYZ-100")).isFalse()
        assertThat(LegacyFingerprint.requiresFingerprintForCrypto(context, 29, "vendor", "ABC-100")).isFalse()
    }

    @Test
    fun `the dialog is hidden only on listed model prefixes running API 28`() {
        assertThat(LegacyFingerprint.hidesDialog(context, 28, "SM-G975F")).isTrue()
        assertThat(LegacyFingerprint.hidesDialog(context, 28, "SM-G960F")).isFalse()
        assertThat(LegacyFingerprint.hidesDialog(context, 29, "SM-G975F")).isFalse()
        assertThat(LegacyFingerprint.hidesDialog(context, 28, null)).isFalse()
    }
}
