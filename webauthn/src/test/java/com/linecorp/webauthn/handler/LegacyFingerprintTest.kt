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
import androidx.biometric.BiometricPrompt
import com.google.common.truth.Truth.assertThat
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
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
    }

    @Test
    fun `isAvailable is true with a secure lock screen and an enrolled fingerprint`() {
        assertThat(LegacyFingerprint.isAvailable(context)).isTrue()
    }

    @Test
    fun `isAvailable is false without a secure lock screen`() {
        every { keyguardManager.isDeviceSecure } returns false
        assertThat(LegacyFingerprint.isAvailable(context)).isFalse()
    }

    @Test
    fun `isAvailable is false when no fingerprint is enrolled`() {
        every { fingerprintManager.hasEnrolledFingerprints() } returns false
        assertThat(LegacyFingerprint.isAvailable(context)).isFalse()
    }

    @Test
    fun `fingerprint is required for crypto only on listed vendors running API 28`() {
        assertThat(LegacyFingerprint.requiresFingerprintForCrypto(context, 28, "samsung", "SM-G960F")).isTrue()
        assertThat(LegacyFingerprint.requiresFingerprintForCrypto(context, 29, "samsung", "SM-G960F")).isFalse()
        assertThat(LegacyFingerprint.requiresFingerprintForCrypto(context, 28, "Google", "Pixel 3")).isFalse()
    }

    @Test
    fun `error codes BiometricPrompt does not define are reported as ERROR_VENDOR`() {
        assertThat(LegacyFingerprint.toBiometricPromptError(BiometricPrompt.ERROR_LOCKOUT))
            .isEqualTo(BiometricPrompt.ERROR_LOCKOUT)
        listOf(1000, 1003, 6).forEach {
            assertThat(LegacyFingerprint.toBiometricPromptError(it)).isEqualTo(BiometricPrompt.ERROR_VENDOR)
        }
    }

    @Test
    fun `the callback relay forwards to its target until the target is cleared`() {
        val target = mockk<FingerprintManager.AuthenticationCallback>(relaxed = true)
        val relay = LegacyFingerprint.CallbackRelay(target)

        relay.onAuthenticationError(BiometricPrompt.ERROR_CANCELED, "canceled")
        relay.target = null
        relay.onAuthenticationError(BiometricPrompt.ERROR_CANCELED, "canceled")

        verify(exactly = 1) { target.onAuthenticationError(BiometricPrompt.ERROR_CANCELED, "canceled") }
    }
}
