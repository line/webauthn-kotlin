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

import androidx.fragment.app.FragmentActivity
import com.lycorp.webauthn.db.CredentialSourceStorage
import com.lycorp.webauthn.model.AuthenticatorType
import com.lycorp.webauthn.model.Fido2PromptInfo
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers

class AuthenticatorProvider(
    private val activity: FragmentActivity,
    private val db: CredentialSourceStorage,
    private val databaseDispatcher: CoroutineDispatcher = Dispatchers.IO,
    private val authenticationDispatcher: CoroutineDispatcher = Dispatchers.Main,
) {

    private var deviceCredentialAuthenticator: DeviceCredentialAuthenticator =
        DeviceCredentialAuthenticator(
            activity = activity,
            db = db,
            databaseDispatcher = databaseDispatcher,
            authenticationDispatcher = authenticationDispatcher
        )

    internal fun getAuthenticator(
        authType: AuthenticatorType,
        fido2PromptInfo: Fido2PromptInfo? = null,
    ): Authenticator {
        return when (authType) {
            AuthenticatorType.Biometric -> {
                BiometricAuthenticator(
                    activity = activity,
                    db = db,
                    fido2PromptInfo = fido2PromptInfo,
                    databaseDispatcher = databaseDispatcher,
                    authenticationDispatcher = authenticationDispatcher,
                )
            }

            AuthenticatorType.Device -> {
                deviceCredentialAuthenticator.apply {
                    this.fido2PromptInfo = fido2PromptInfo
                }
            }
        }
    }
}
