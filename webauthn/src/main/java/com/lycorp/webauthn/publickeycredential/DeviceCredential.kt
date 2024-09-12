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

package com.lycorp.webauthn.publickeycredential

import androidx.fragment.app.FragmentActivity
import com.lycorp.webauthn.authenticator.AuthenticatorProvider
import com.lycorp.webauthn.db.CredentialSourceStorage
import com.lycorp.webauthn.model.AuthenticatorType
import com.lycorp.webauthn.rp.RelyingParty
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers

class DeviceCredential(
    rpClient: RelyingParty,
    private val activity: FragmentActivity,
    db: CredentialSourceStorage,
    authType: AuthenticatorType = AuthenticatorType.Device,
    relyingPartyDispatcher: CoroutineDispatcher = Dispatchers.IO,
    private val databaseDispatcher: CoroutineDispatcher = Dispatchers.IO,
    private val authenticationDispatcher: CoroutineDispatcher = Dispatchers.Main,
    authenticatorProvider: AuthenticatorProvider = AuthenticatorProvider(
        activity,
        db,
        databaseDispatcher,
        authenticationDispatcher
    ),
) : PublicKeyCredential(
    rpClient,
    activity,
    db,
    authType,
    relyingPartyDispatcher,
    databaseDispatcher,
    authenticationDispatcher,
    authenticatorProvider
)
