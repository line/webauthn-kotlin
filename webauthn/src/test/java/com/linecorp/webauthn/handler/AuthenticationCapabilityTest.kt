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

package com.linecorp.webauthn.handler

import android.content.Context
import androidx.biometric.BiometricManager
import com.google.common.truth.Truth.assertThat
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mockk.spyk
import io.mockk.unmockkStatic
import kotlinx.coroutines.Dispatchers
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Test

/**
 * Covers what the two concrete handlers report through [AuthenticationCapability], and the invariant that
 * `isSupported` accepts nothing but `BIOMETRIC_SUCCESS`.
 *
 * `Build.VERSION.SDK_INT` reads 0 under a local JVM unit test, so [DeviceCredentialAuthenticationHandler]
 * takes its pre-API-30 `KeyguardManager` branch here. That is the Android 9/10 population this diff exists
 * for, and it is only reachable because the handler accepts an injected [KeyguardManagerWrapper].
 */
class AuthenticationCapabilityTest {

    private val mockContext: Context = mockk()

    @AfterEach
    fun tearDown() {
        unmockkStatic(BiometricManager::class)
    }

    @Test
    fun `below API 30 device credential reports SUCCESS when the keyguard is secure`() {
        val wrapper: KeyguardManagerWrapper = mockk()
        every { wrapper.isSupported(mockContext) } returns true
        val handler = DeviceCredentialAuthenticationHandler(Dispatchers.Unconfined, wrapper)

        assertThat(handler.canAuthenticateStatus(mockContext)).isEqualTo(BiometricManager.BIOMETRIC_SUCCESS)
        assertThat(handler.isSupported(mockContext)).isTrue()
    }

    @Test
    fun `below API 30 device credential reports NONE_ENROLLED when the keyguard is not secure`() {
        val wrapper: KeyguardManagerWrapper = mockk()
        every { wrapper.isSupported(mockContext) } returns false
        val handler = DeviceCredentialAuthenticationHandler(Dispatchers.Unconfined, wrapper)

        // Synthesised, because KeyguardManager has no status code: NONE_ENROLLED is the user-fixable
        // classification, which is what an absent screen lock is.
        assertThat(handler.canAuthenticateStatus(mockContext))
            .isEqualTo(BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED)
        assertThat(handler.isSupported(mockContext)).isFalse()
    }

    @Test
    fun `biometric isSupported is true for BIOMETRIC_SUCCESS and false for every other status`() {
        val biometricManager: BiometricManager = mockk()
        mockkStatic(BiometricManager::class)
        every { BiometricManager.from(mockContext) } returns biometricManager
        val handler = BiometricAuthenticationHandler(Dispatchers.Unconfined)

        val statuses = listOf(
            BiometricManager.BIOMETRIC_SUCCESS,
            BiometricManager.BIOMETRIC_STATUS_UNKNOWN,
            BiometricManager.BIOMETRIC_ERROR_UNSUPPORTED,
            BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE,
            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED,
            BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE,
            BiometricManager.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED
        )

        statuses.forEach { status ->
            every { biometricManager.canAuthenticate(any()) } returns status

            assertThat(handler.canAuthenticateStatus(mockContext)).isEqualTo(status)
            assertThat(handler.isSupported(mockContext))
                .isEqualTo(status == BiometricManager.BIOMETRIC_SUCCESS)
        }
    }

    @Test
    fun `an undetermined status never counts as supported`() {
        // BIOMETRIC_STATUS_UNKNOWN means the platform could not answer. Treating it as supported would turn
        // a clean pre-flight ConstraintException into a late key-generation failure, so isSupported must
        // keep comparing strictly against BIOMETRIC_SUCCESS on both handlers.
        val biometric = spyk(BiometricAuthenticationHandler(Dispatchers.Unconfined))
        every { biometric.canAuthenticateStatus(mockContext) } returns BiometricManager.BIOMETRIC_STATUS_UNKNOWN

        val deviceCredential = spyk(DeviceCredentialAuthenticationHandler(Dispatchers.Unconfined, mockk()))
        every {
            deviceCredential.canAuthenticateStatus(mockContext)
        } returns BiometricManager.BIOMETRIC_STATUS_UNKNOWN

        assertThat(biometric.isSupported(mockContext)).isFalse()
        assertThat(deviceCredential.isSupported(mockContext)).isFalse()
    }
}
