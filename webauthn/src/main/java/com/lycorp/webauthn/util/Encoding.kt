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

import com.lycorp.webauthn.exceptions.WebAuthnException
import java.util.Base64

fun String.toBase64url(): String {
    try {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(this.encodeToByteArray())
    } catch (e: Exception) {
        throw WebAuthnException.UtilityException("Failed to encode String to base64url String", e)
    }
}

fun String.base64urlToString(): String {
    try {
        return Base64.getUrlDecoder().decode(this).decodeToString()
    } catch (e: Exception) {
        throw WebAuthnException.UtilityException("Failed to decode base64url String to String", e)
    }
}

fun String.base64urlToByteArray(): ByteArray {
    try {
        return Base64.getUrlDecoder().decode(this)
    } catch (e: Exception) {
        throw WebAuthnException.UtilityException("Failed to decode base64url String to ByteArray", e)
    }
}

fun ByteArray.toBase64url(): String {
    try {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(this)
    } catch (e: Exception) {
        throw WebAuthnException.UtilityException("Failed to encode ByteArray to base64url String", e)
    }
}
