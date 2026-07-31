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

package com.linecorp.webauthn.authenticator

import com.linecorp.webauthn.authenticator.keygenerator.BiometricKeyGenerator
import com.linecorp.webauthn.authenticator.keygenerator.DeviceCredentialKeyGenerator
import com.linecorp.webauthn.authenticator.objectgenerator.AndroidKeyObjectGenerator
import com.linecorp.webauthn.authenticator.objectgenerator.NoneObjectGenerator
import com.linecorp.webauthn.db.CredentialSourceStorage
import com.linecorp.webauthn.handler.BiometricAuthenticationHandler
import com.linecorp.webauthn.handler.DeviceCredentialAuthenticationHandler
import com.linecorp.webauthn.model.AttestationStatementFormat
import com.linecorp.webauthn.model.AuthenticationMethod
import com.linecorp.webauthn.model.AuthenticatorType
import com.linecorp.webauthn.model.Fido2PromptInfo
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers

class AuthenticatorProvider(
    private val db: CredentialSourceStorage,
    private val databaseDispatcher: CoroutineDispatcher = Dispatchers.IO,
    private val authenticationDispatcher: CoroutineDispatcher = Dispatchers.Main,
) {
    internal fun getAuthenticator(
        authenticationMethod: AuthenticationMethod,
        attestationStatement: AttestationStatementFormat,
        fido2PromptInfo: Fido2PromptInfo? = null,
    ): Authenticator {
        val authenticationHandler = when (authenticationMethod) {
            AuthenticationMethod.Biometric -> BiometricAuthenticationHandler(
                authenticationDispatcher
            )
            AuthenticationMethod.DeviceCredential -> DeviceCredentialAuthenticationHandler(
                authenticationDispatcher
            )
        }
        val fido2KeyGenerator = when (authenticationMethod) {
            AuthenticationMethod.Biometric -> BiometricKeyGenerator()
            AuthenticationMethod.DeviceCredential -> DeviceCredentialKeyGenerator()
        }
        val fido2ObjectGenerator = when (attestationStatement) {
            AttestationStatementFormat.NONE -> NoneObjectGenerator()
            AttestationStatementFormat.ANDROID_KEY -> AndroidKeyObjectGenerator()
            else -> AndroidKeyObjectGenerator()
        }
        val authType: AuthenticatorType = AuthenticatorType.getAuthenticatorType(
            authenticationMethod,
            attestationStatement
        )

        return Authenticator(
            db = db,
            authenticationHandler = authenticationHandler,
            fido2KeyGenerator = fido2KeyGenerator,
            fido2ObjectGenerator = fido2ObjectGenerator,
            authType = authType,
            fido2PromptInfo = fido2PromptInfo,
            databaseDispatcher = databaseDispatcher,
            // Passed explicitly rather than left to the default, and not exposed as a constructor parameter
            // of this class: AuthenticatorProvider is public API, so adding a defaulted parameter here would
            // change the synthetic constructor descriptor and break already-compiled consumers with a
            // NoSuchMethodError. Keystore work is blocking I/O into keystore2 either way.
            keystoreDispatcher = Dispatchers.IO,
        )
    }
}
