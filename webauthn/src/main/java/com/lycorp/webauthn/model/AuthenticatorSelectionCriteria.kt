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

package com.lycorp.webauthn.model

data class AuthenticatorSelectionCriteria(
    val authenticatorAttachment: String?,
    val userVerification: String = UserVerificationRequirement.PREFERRED.value,
)

enum class UserVerificationRequirement(val value: String) {
    REQUIRED("required"),
    PREFERRED("preferred"),
    ;

    companion object {
        fun fromValue(value: String): UserVerificationRequirement? {
            return UserVerificationRequirement.values().find { it.value == value }
        }
    }
}
