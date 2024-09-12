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

import com.lycorp.webauthn.model.AuthenticatorGetAssertionResult
import com.lycorp.webauthn.model.AuthenticatorMakeCredentialResult
import com.lycorp.webauthn.model.AuthenticatorType
import com.lycorp.webauthn.model.COSEAlgorithmIdentifier
import com.lycorp.webauthn.model.PublicKeyCredentialDescriptor
import com.lycorp.webauthn.model.PublicKeyCredentialParams
import com.lycorp.webauthn.model.PublicKeyCredentialRpEntity
import com.lycorp.webauthn.model.PublicKeyCredentialSource
import com.lycorp.webauthn.model.PublicKeyCredentialType
import com.lycorp.webauthn.model.PublicKeyCredentialUserEntity
import java.security.KeyPairGenerator

class DataFactory {
    companion object {
        val RP_NAME = "test_rp"
        val USER_NAME = "test_user_name"
        val USER_DISPLAY_NAME = "test_user_display_name"

        val newRpId = "https://new-rp.com"
        val newUserId = "new-user-id"
        val newRpEntity =
            PublicKeyCredentialRpEntity(newRpId, RP_NAME)
        val newUserEntity = PublicKeyCredentialUserEntity(newUserId, USER_NAME, USER_DISPLAY_NAME)

        val registeredRpId = "https://registered-rp.com"
        val registeredUserId = "registered-user-id"
        val registeredCredId = Fido2Util.generateRandomByteArray(32).toBase64url()

        val registeredCredSource = PublicKeyCredentialSource(
            id = registeredCredId,
            rpId = registeredRpId,
            userHandle = registeredUserId,
            aaguid = AuthenticatorType.Biometric.aaguid,
        )
        val registeredCredDescriptor = PublicKeyCredentialDescriptor(
            type = PublicKeyCredentialType.PUBLIC_KEY.value,
            id = registeredCredSource.id.toBase64url(),
            transports = null,
        )

        val DUMMY_BYTEARRAY = ByteArray(32) { 0 }
        val ES256_CRED_PARAMS =
            PublicKeyCredentialParams(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256)
        val keyPair = KeyPairGenerator.getInstance("EC").apply { initialize(256) }
            .generateKeyPair()

        fun getMakeCredentialResult() = AuthenticatorMakeCredentialResult(
            DUMMY_BYTEARRAY,
            DUMMY_BYTEARRAY,
        )

        fun getGetAssertionResult() = AuthenticatorGetAssertionResult(
            DUMMY_BYTEARRAY,
            DUMMY_BYTEARRAY,
            DUMMY_BYTEARRAY,
            DUMMY_BYTEARRAY,
        )
    }
}
