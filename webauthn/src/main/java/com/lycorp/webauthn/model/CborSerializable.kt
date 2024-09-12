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

import co.nstant.`in`.cbor.CborBuilder
import co.nstant.`in`.cbor.CborEncoder
import co.nstant.`in`.cbor.builder.AbstractBuilder
import co.nstant.`in`.cbor.builder.MapBuilder
import com.lycorp.webauthn.exceptions.WebAuthnException
import java.io.ByteArrayOutputStream

interface CborSerializable {
    fun <T : AbstractBuilder<*>?> toCBOR(builder: MapBuilder<T>): T

    fun toCBOR(canonical: Boolean = true): ByteArray {
        try {
            val baos = ByteArrayOutputStream()
            CborEncoder(baos).encode(toCBOR(CborBuilder().startMap()).build())
            return baos.toByteArray()
        } catch (e: Exception) {
            throw WebAuthnException.EncodingException("Cannot convert Attestation Object to CBOR.", e)
        }
    }
}
