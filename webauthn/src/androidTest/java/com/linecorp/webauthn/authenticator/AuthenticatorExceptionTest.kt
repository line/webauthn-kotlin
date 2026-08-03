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

import androidx.fragment.app.FragmentActivity
import androidx.test.core.app.ActivityScenario
import com.google.common.truth.Truth.assertThat
import com.google.common.truth.Truth.assertWithMessage
import com.linecorp.webauthn.exceptions.WebAuthnException
import com.linecorp.webauthn.model.AuthenticatorType
import com.linecorp.webauthn.model.COSEAlgorithmIdentifier
import com.linecorp.webauthn.model.PublicKeyCredentialDescriptor
import com.linecorp.webauthn.model.PublicKeyCredentialParams
import com.linecorp.webauthn.model.PublicKeyCredentialRpEntity
import com.linecorp.webauthn.model.PublicKeyCredentialType
import com.linecorp.webauthn.model.PublicKeyCredentialUserEntity
import com.linecorp.webauthn.util.MockCredentialSourceStorage
import com.linecorp.webauthn.util.TestAuthenticatorFactory
import com.linecorp.webauthn.util.TestFragmentActivity
import com.linecorp.webauthn.util.toBase64url
import java.security.KeyStore
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

/**
 * Checks that the situation-specific exceptions really are what a device produces.
 *
 * The unit tests cover the same exception types by injecting them into a mocked collaborator, which
 * proves the mapping but not that the situation itself reaches it. Each test here *creates* the
 * situation - a key deleted behind the credential's back, a relying party that was never registered, a
 * credential that is already registered - on the real keystore.
 */
class AuthenticatorExceptionTest {

    private val keyStore: KeyStore = KeyStore.getInstance("AndroidKeyStore").also { it.load(null) }
    private val rpEntity = PublicKeyCredentialRpEntity("example.com", "Example Relying Party")
    private val userEntity = PublicKeyCredentialUserEntity("dXNlci0xMjM", "User Name", "Display Name")
    private val credParams = listOf(
        PublicKeyCredentialParams(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256)
    )
    private val clientDataHash = ByteArray(32) { 7 }

    private lateinit var baselineAliases: Set<String>
    private lateinit var db: MockCredentialSourceStorage
    private lateinit var authenticator: Authenticator

    @BeforeEach
    fun setUp() {
        baselineAliases = keyStore.aliases().toList().toSet()
        db = MockCredentialSourceStorage()
        authenticator = TestAuthenticatorFactory.realAuthenticator(AuthenticatorType.BiometricNone, db)
    }

    @AfterEach
    fun tearDown() {
        TestAuthenticatorFactory.deleteAliases(keyStore, keyStore.aliases().toList() - baselineAliases)
        db.removeAllData()
    }

    @Test
    fun getAssertionReportsKeyNotFoundWhenTheRowOutlivesTheKey(): Unit = onActivity { activity ->
        val credId = register(activity)

        // The state a user reaches by clearing the app's keystore credentials, or by a restore that brings
        // the database back without the hardware keys: the row still names an alias that no longer exists.
        keyStore.deleteEntry(credId)
        assertThat(keyStore.containsAlias(credId)).isFalse()
        assertThat(db.load(credId)).isNotNull()

        val result = authenticator.getAssertion(
            activity = activity,
            rpId = rpEntity.id,
            hash = clientDataHash,
            allowCredDescriptorList = null,
            extensions = null,
        )

        assertThat(result.isFailure).isTrue()
        assertThat(result.exceptionOrNull()).isInstanceOf(WebAuthnException.KeyNotFoundException::class.java)
    }

    @Test
    fun getAssertionReportsNotAllowedForARelyingPartyWithNoCredential(): Unit = onActivity { activity ->
        val result = authenticator.getAssertion(
            activity = activity,
            rpId = "never-registered.example.com",
            hash = clientDataHash,
            allowCredDescriptorList = null,
            extensions = null,
        )

        assertThat(result.isFailure).isTrue()
        assertThat(result.exceptionOrNull())
            .isInstanceOf(WebAuthnException.CoreException.NotAllowedException::class.java)
    }

    @Test
    fun makeCredentialReportsInvalidStateForAnAlreadyRegisteredCredential(): Unit = onActivity { activity ->
        val registeredCredId = register(activity)
        val aliasesAfterRegistration = keyStore.aliases().toList().toSet()

        val result = authenticator.makeCredential(
            activity = activity,
            hash = clientDataHash,
            rpEntity = rpEntity,
            userEntity = userEntity,
            credTypesAndPubKeyAlgs = credParams,
            excludeCredDescriptorList = listOf(
                PublicKeyCredentialDescriptor(
                    type = PublicKeyCredentialType.PUBLIC_KEY.value,
                    id = registeredCredId,
                    transports = null,
                )
            ),
            extensions = null,
        )

        assertThat(result.isFailure).isTrue()
        assertThat(result.exceptionOrNull())
            .isInstanceOf(WebAuthnException.CoreException.InvalidStateException::class.java)
        // The exclusion is checked before any key is generated, so this pins where in the sequence the
        // rejection happens - no key is created at all - and that the cleanup which then runs over an
        // alias that never existed does not take the already registered credential with it. It is
        // deliberately not a test of failure-path cleanup: no key material exists on this path for cleanup
        // to miss. That property is covered by the relying-party rejection in
        // com.linecorp.webauthn.PublicKeyCredentialEndToEndTest, where the key does get created first.
        assertThat(keyStore.aliases().toList().toSet()).isEqualTo(aliasesAfterRegistration)
        assertThat(keyStore.containsAlias(registeredCredId)).isTrue()
        assertThat(db.load(registeredCredId)).isNotNull()
    }

    /** Registers one credential for [rpEntity] and returns its credential id, which is also its alias. */
    private suspend fun register(activity: FragmentActivity): String {
        val result = authenticator.makeCredential(
            activity = activity,
            hash = clientDataHash,
            rpEntity = rpEntity,
            userEntity = userEntity,
            credTypesAndPubKeyAlgs = credParams,
            excludeCredDescriptorList = null,
            extensions = null,
        )
        assertWithMessage("makeCredential failed: ${result.exceptionOrNull()}").that(result.isSuccess).isTrue()
        val credId = result.getOrThrow().credentialId.toBase64url()
        assertThat(keyStore.containsAlias(credId)).isTrue()
        return credId
    }

    private fun onActivity(block: suspend (FragmentActivity) -> Unit) {
        ActivityScenario.launch(TestFragmentActivity::class.java).use { scenario ->
            var launched: TestFragmentActivity? = null
            scenario.onActivity { launched = it }
            val activity = requireNotNull(launched) { "the test activity was not created" }
            runBlocking { block(activity) }
        }
    }
}
