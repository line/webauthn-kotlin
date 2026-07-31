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

import androidx.biometric.BiometricManager
import com.google.common.truth.Truth.assertThat
import com.linecorp.webauthn.model.AuthenticationAvailability
import org.junit.jupiter.api.Test

class AuthenticationAvailabilityTest {

    @Test
    fun `success maps to AVAILABLE`() {
        val a = AuthenticationAvailability.fromStatus(BiometricManager.BIOMETRIC_SUCCESS)

        assertThat(a.isAvailable).isTrue()
        assertThat(a.reason).isEqualTo(AuthenticationAvailability.Reason.AVAILABLE)
        assertThat(a.status).isEqualTo(BiometricManager.BIOMETRIC_SUCCESS)
    }

    @Test
    fun `every documented failure status maps to its own reason and is not available`() {
        val expected = mapOf(
            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED to AuthenticationAvailability.Reason.NONE_ENROLLED,
            BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE to AuthenticationAvailability.Reason.NO_HARDWARE,
            BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE to AuthenticationAvailability.Reason.HW_UNAVAILABLE,
            BiometricManager.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED to
                AuthenticationAvailability.Reason.SECURITY_UPDATE_REQUIRED,
            BiometricManager.BIOMETRIC_ERROR_UNSUPPORTED to AuthenticationAvailability.Reason.UNSUPPORTED,
            BiometricManager.BIOMETRIC_STATUS_UNKNOWN to AuthenticationAvailability.Reason.UNKNOWN
        )

        expected.forEach { (status, reason) ->
            val a = AuthenticationAvailability.fromStatus(status)
            assertThat(a.reason).isEqualTo(reason)
            assertThat(a.isAvailable).isFalse()
            assertThat(a.status).isEqualTo(status)
        }
    }

    @Test
    fun `an unrecognised status maps to UNKNOWN but keeps the raw value`() {
        val a = AuthenticationAvailability.fromStatus(9999)

        assertThat(a.reason).isEqualTo(AuthenticationAvailability.Reason.UNKNOWN)
        assertThat(a.isAvailable).isFalse()
        assertThat(a.status).isEqualTo(9999)
    }
}
