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

package com.linecorp.webauthn.model

import androidx.biometric.BiometricManager

/**
 * Whether the device can currently perform the SDK's user authentication, and why not if it cannot.
 *
 * Obtain one from [com.linecorp.webauthn.publickeycredential.PublicKeyCredential.checkAuthenticationAvailability]
 * and use it to gate your UI before calling `create()`, which otherwise throws
 * [com.linecorp.webauthn.exceptions.WebAuthnException.CoreException.ConstraintException].
 *
 * @property isAvailable True when authentication can proceed right now.
 * @property status The `BiometricManager.canAuthenticate()` status where the platform provides one. On API
 * levels below 30 with [AuthenticationMethod.DeviceCredential] there is no such call, so the SDK derives one
 * from `KeyguardManager.isDeviceSecure` (`BIOMETRIC_SUCCESS` or `BIOMETRIC_ERROR_NONE_ENROLLED`) to match
 * what androidx reports for that combination on API 30 and above. Null only when the availability query
 * itself failed, in which case [reason] is [Reason.UNKNOWN].
 * @property reason A stable classification of [status].
 */
@ConsistentCopyVisibility
data class AuthenticationAvailability internal constructor(
    val isAvailable: Boolean,
    val status: Int?,
    val reason: Reason
) {

    enum class Reason {
        /** Authentication can proceed. */
        AVAILABLE,

        /** No credential is enrolled. The user can fix this in system settings. */
        NONE_ENROLLED,

        /**
         * The platform reports no authenticator of the required class.
         *
         * Do **not** cache this as permanently unsupported: androidx also returns it on API 28 for a
         * device whose only biometric is face - Class 3 is not queryable there - and whenever
         * `KeyguardManager` is unavailable. Re-query before each ceremony.
         */
        NO_HARDWARE,

        /** The hardware exists but is busy or temporarily disabled. Retry later. */
        HW_UNAVAILABLE,

        /** A required security update has not been applied. */
        SECURITY_UPDATE_REQUIRED,

        /** The requested authenticator class is not supported on this API level. */
        UNSUPPORTED,

        /** The platform could not determine availability. */
        UNKNOWN
    }

    companion object {
        internal fun fromStatus(status: Int): AuthenticationAvailability {
            val reason = when (status) {
                BiometricManager.BIOMETRIC_SUCCESS -> Reason.AVAILABLE
                BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> Reason.NONE_ENROLLED
                BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> Reason.NO_HARDWARE
                BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> Reason.HW_UNAVAILABLE
                BiometricManager.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED -> Reason.SECURITY_UPDATE_REQUIRED
                BiometricManager.BIOMETRIC_ERROR_UNSUPPORTED -> Reason.UNSUPPORTED
                else -> Reason.UNKNOWN
            }
            return AuthenticationAvailability(
                isAvailable = reason == Reason.AVAILABLE,
                status = status,
                reason = reason
            )
        }
    }
}
