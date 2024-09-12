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

package com.lycorp.webauthn.authenticator

import android.os.Build
import androidx.fragment.app.FragmentActivity
import com.lycorp.webauthn.db.CredentialSourceStorage
import com.lycorp.webauthn.handler.AuthenticationHandler
import com.lycorp.webauthn.handler.DeviceCredentialAuthenticationHandler
import com.lycorp.webauthn.model.AuthenticatorType
import com.lycorp.webauthn.model.COSEAlgorithmIdentifier
import com.lycorp.webauthn.model.Fido2PromptInfo
import com.lycorp.webauthn.util.SecureExecutionHelper
import java.security.KeyPair
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers

internal class DeviceCredentialAuthenticator(
    override val activity: FragmentActivity,
    override val db: CredentialSourceStorage,
    public override var fido2PromptInfo: Fido2PromptInfo? = null,
    override val databaseDispatcher: CoroutineDispatcher = Dispatchers.IO,
    override val fido2ObjectFactory: Fido2ObjectFactory = Fido2ObjectFactory(),
    private val authenticationDispatcher: CoroutineDispatcher = Dispatchers.Main,
    override val authenticationHandler: AuthenticationHandler =
        DeviceCredentialAuthenticationHandler(activity, authenticationDispatcher)
) : Authenticator(
    activity,
    db,
    fido2PromptInfo,
    databaseDispatcher,
    fido2ObjectFactory,
    authenticationHandler
) {
    override val authType: AuthenticatorType = AuthenticatorType.Device

    override fun generateFido2Key(
        keyAlias: String,
        challenge: ByteArray,
        pubKeyAlg: COSEAlgorithmIdentifier,
        isStrongBoxBacked: Boolean,
    ): KeyPair {
        val userAuthenticationValidityDurationSeconds = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            0
        } else {
            5
        }

        return SecureExecutionHelper.generateKey(
            keyAlias = keyAlias,
            challenge = challenge,
            publicKeyAlgorithm = pubKeyAlg,
            useBiometricOnly = false,
            userAuthenticationValidityDurationSeconds = userAuthenticationValidityDurationSeconds,
            isStrongBoxBacked = isStrongBoxBacked
        )
    }
}
