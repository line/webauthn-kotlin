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

import co.nstant.`in`.cbor.builder.AbstractBuilder
import co.nstant.`in`.cbor.builder.MapBuilder

/**
 * Represents an Attestation Object in the WebAuthn process.
 *
 * This class corresponds to the attestation object as defined in the Web Authentication: An API for accessing Public Key Credentials Level 2 specification.
 * For more details, see the specification: [Web Authentication: Level 2 - Attestation Object](https://www.w3.org/TR/webauthn-2/#attestation-object)
 *
 * AttestationObject:
 * |   authData   | fmt  |  attStmt  |
 * |--------------|------|-----------|
 * | variable size| text | map-based |
 */
data class AttestationObject(
    val authData: ByteArray,
    val fmt: String,
    val attStmt: AttestationStatement,
) : CborSerializable {
    override fun <T : AbstractBuilder<*>?> toCBOR(builder: MapBuilder<T>): T {
        builder.put("fmt", fmt)
        attStmt.toCBOR(builder.startMap("attStmt"))
        builder.put("authData", authData)
        return builder.end()
    }
}
