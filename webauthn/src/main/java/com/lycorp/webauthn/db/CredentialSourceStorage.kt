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

package com.lycorp.webauthn.db

import com.lycorp.webauthn.model.PublicKeyCredentialSource

/**
 * Interface for storing and managing credential sources.
 */
interface CredentialSourceStorage {
    /**
     * Stores the given credential source.
     *
     * @param credSource The credential source to store.
     */
    fun store(credSource: PublicKeyCredentialSource)

    /**
     * Loads the credential source corresponding to the given credential ID.
     *
     * @param credId The ID of the credential source to load.
     * @return The loaded credential source, or null if not found.
     */
    fun load(credId: String): PublicKeyCredentialSource?

    /**
     * Loads all stored credential sources.
     *
     * @return A list of all stored credential sources.
     */
    fun loadAll(): List<PublicKeyCredentialSource>

    /**
     * Deletes the credential source corresponding to the given credential ID.
     *
     * @param credId The ID of the credential source to delete.
     */
    fun delete(credId: String)

    /**
     * Gets the signature counter for the given credential ID.
     *
     * @param credId The ID of the credential source whose signature counter is to be retrieved.
     * @return The current value of the signature counter.
     */
    fun getSignatureCounter(credId: String): UInt

    /**
     * Increases the signature counter for the given credential ID.
     *
     * @param credId The ID of the credential source whose signature counter is to be increased.
     */
    fun increaseSignatureCounter(credId: String)
}
