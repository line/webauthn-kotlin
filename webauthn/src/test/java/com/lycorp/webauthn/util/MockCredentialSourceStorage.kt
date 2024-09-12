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

import com.lycorp.webauthn.db.CredentialSourceStorage
import com.lycorp.webauthn.model.PublicKeyCredentialSource
import com.lycorp.webauthn.model.PublicKeyCredentialType
import java.util.UUID

class MockCredentialSourceStorage : CredentialSourceStorage {
    private var credSourceTable: MutableList<TestPubKeyCredSourceEntity> = mutableListOf()

    override fun store(credSource: PublicKeyCredentialSource) {
        val credSourceEntity = TestPubKeyCredSourceEntity(
            credType = PublicKeyCredentialType.PUBLIC_KEY.value,
            aaguid = credSource.aaguid,
            credId = credSource.id,
            rpId = credSource.rpId,
            userHandle = credSource.userHandle,
            signatureCounter = 0L,
        )
        credSourceTable.add(credSourceEntity)
    }
    override fun load(credId: String): PublicKeyCredentialSource? {
        val credSourceEntity = credSourceTable.firstOrNull { it.credId.contentEquals(credId) }
        return credSourceEntity?.let {
            PublicKeyCredentialSource(
                type = it.credType,
                id = it.credId,
                rpId = it.rpId,
                userHandle = it.userHandle,
                aaguid = it.aaguid,
            )
        }
    }

    override fun loadAll(): List<PublicKeyCredentialSource> {
        return credSourceTable.map { entity ->
            PublicKeyCredentialSource(
                type = entity.credType,
                id = entity.credId,
                rpId = entity.rpId,
                userHandle = entity.userHandle,
                aaguid = entity.aaguid,
            )
        }
    }

    override fun delete(credId: String) {
        credSourceTable = credSourceTable.filter { it.credId != credId }.toMutableList()
    }

    override fun increaseSignatureCounter(credId: String) {
        val credSourceEntity = credSourceTable.firstOrNull { it.credId.contentEquals(credId) }
        credSourceEntity?.let {
            it.signatureCounter += 1
        }
    }
    override fun getSignatureCounter(credId: String): UInt = 0u

    fun removeAllData() {
        credSourceTable = mutableListOf()
    }
}

data class TestPubKeyCredSourceEntity(
    val credType: String,
    var credId: String,
    val rpId: String,
    val userHandle: String?,
    val aaguid: UUID,
    var signatureCounter: Long,
)
