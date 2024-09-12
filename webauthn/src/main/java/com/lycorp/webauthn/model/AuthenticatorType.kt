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

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.UUID

enum class AuthenticatorType(val authenticatorName: String, val aaguid: UUID) {
    Biometric("Biometric", UUID.fromString("8c120a4d-52b3-99ef-eaf6-7cfb2a3e3f89")),
    Device("Device", UUID.fromString("2b7a96a3-f571-ee4c-632c-c5458dfadfe3")),
    ;

    fun aaguidBytes(): ByteArray {
        return ByteBuffer.wrap(ByteArray(16)).apply {
            order(ByteOrder.BIG_ENDIAN)
            putLong(aaguid.mostSignificantBits)
            putLong(aaguid.leastSignificantBits)
        }.array()
    }
}
