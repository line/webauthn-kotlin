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

import java.util.UUID

data class PublicKeyCredentialSource(
    val type: String = PublicKeyCredentialType.PUBLIC_KEY.value,
    var id: String,
    val rpId: String,
    val userHandle: String?, // base64url encoding of the user handle
    val aaguid: UUID,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as PublicKeyCredentialSource

        if (type != other.type) return false
        if (!id.contentEquals(other.id)) return false
        if (rpId != other.rpId) return false
        if (userHandle != null) {
            if (other.userHandle == null) return false
            if (!userHandle.contentEquals(other.userHandle)) return false
        } else if (other.userHandle != null) {
            return false
        }
        return aaguid == other.aaguid
    }

    override fun hashCode(): Int {
        var result = type.hashCode()
        result = 31 * result + id.hashCode()
        result = 31 * result + rpId.hashCode()
        result = 31 * result + (userHandle?.hashCode() ?: 0)
        result = 31 * result + aaguid.hashCode()
        return result
    }
}
