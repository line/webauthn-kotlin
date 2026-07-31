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

package com.linecorp.webauthn

import androidx.fragment.app.FragmentActivity
import androidx.test.core.app.ActivityScenario
import com.google.common.truth.Truth.assertThat
import com.google.common.truth.Truth.assertWithMessage
import com.linecorp.webauthn.exceptions.WebAuthnException
import com.linecorp.webauthn.model.AttestationStatementFormat
import com.linecorp.webauthn.model.AuthenticationMethod
import com.linecorp.webauthn.model.AuthenticatorType
import com.linecorp.webauthn.publickeycredential.PublicKeyCredential
import com.linecorp.webauthn.util.FakeRelyingParty
import com.linecorp.webauthn.util.MockCredentialSourceStorage
import com.linecorp.webauthn.util.TestAuthenticatorFactory
import com.linecorp.webauthn.util.TestFragmentActivity
import java.security.KeyStore
import kotlinx.coroutines.runBlocking
import org.json.JSONObject
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

/**
 * Drives the public entry points - `create`, `get`, `getAllAccounts`, `deleteAccount`,
 * `deleteAllAccounts` - on a real device against the real AndroidKeyStore.
 *
 * Every other instrumented test drives [com.linecorp.webauthn.authenticator.Authenticator] directly, so
 * without this class the facet-ID lookup, the `clientDataJSON` the relying party has to verify, and the
 * account-management APIs never run on a device at all: the unit tests that cover them replace the whole
 * authenticator with a mock.
 *
 * The only substitution is the [com.linecorp.webauthn.authenticator.AuthenticatorProvider], which
 * `PublicKeyCredential` accepts as a public constructor parameter. The authenticator behind it is a real
 * one built by [TestAuthenticatorFactory], so everything from the provider call onwards - key generation,
 * signing, CBOR encoding, storage, cleanup - is production code.
 */
class PublicKeyCredentialEndToEndTest {

    private val keyStore: KeyStore = KeyStore.getInstance("AndroidKeyStore").also { it.load(null) }

    private lateinit var baselineAliases: Set<String>
    private lateinit var db: MockCredentialSourceStorage
    private lateinit var relyingParty: FakeRelyingParty
    private lateinit var publicKeyCredential: PublicKeyCredential

    @BeforeEach
    fun setUp() {
        baselineAliases = keyStore.aliases().toList().toSet()
        db = MockCredentialSourceStorage()
        relyingParty = FakeRelyingParty()
        val authenticator = TestAuthenticatorFactory.realAuthenticator(AuthenticatorType.BiometricNone, db)
        publicKeyCredential = PublicKeyCredential(
            rpClient = relyingParty,
            db = db,
            authenticationMethod = AuthenticationMethod.Biometric,
            attestationStatement = AttestationStatementFormat.NONE,
            authenticatorProvider = TestAuthenticatorFactory.mockedProviderReturning(authenticator),
        )
    }

    @AfterEach
    fun tearDown() {
        // Every alias this test added, whether or not it got as far as recording the credential id. A
        // failed assertion must not leave hardware-backed keys on a shared device.
        TestAuthenticatorFactory.deleteAliases(keyStore, keyStore.aliases().toList() - baselineAliases)
        db.removeAllData()
    }

    @Test
    fun createThenGetSucceedsThroughThePublicApi(): Unit = onActivity { activity ->
        val createResult = publicKeyCredential.create(activity, relyingParty.registrationOptions())

        assertWithMessage("create failed: ${createResult.exceptionOrNull()}")
            .that(createResult.isSuccess).isTrue()

        val created = requireNotNull(relyingParty.lastCreateResult) { "the relying party never saw a result" }
        val createClientData = created.authenticatorAttestationResponse.clientDataJSON.asJson()
        assertThat(createClientData.getString("type")).isEqualTo("webauthn.create")
        assertThat(createClientData.getString("challenge")).isEqualTo(relyingParty.registrationChallenge)
        // The facet ID is computed from the calling package's signing certificate on the device; only its
        // prefix is fixed, and a broken lookup would have failed the create above.
        assertThat(createClientData.getString("origin")).startsWith("android:apk-key-hash-sha256:")
        assertThat(created.authenticatorAttestationResponse.attestationObject).isNotEmpty()

        val getResult = publicKeyCredential.get(activity, relyingParty.authenticationOptions())

        assertWithMessage("get failed: ${getResult.exceptionOrNull()}")
            .that(getResult.isSuccess).isTrue()

        val got = requireNotNull(relyingParty.lastGetResult) { "the relying party never saw a result" }
        val getClientData = got.authenticatorAssertionResponse.clientDataJSON.asJson()
        assertThat(getClientData.getString("type")).isEqualTo("webauthn.get")
        assertThat(getClientData.getString("challenge")).isEqualTo(relyingParty.authenticationChallenge)
        assertThat(got.authenticatorAssertionResponse.signature).isNotEmpty()
        // rpIdHash 32 + flags 1 + signCount 4, with no attested credential data and no extensions.
        assertThat(got.authenticatorAssertionResponse.authenticatorData).hasLength(37)
        assertThat(got.id).isEqualTo(created.id)

        // Exactly one row for one registration: `getAllAccounts` used to loop over all four authenticator
        // types and return every credential once per type.
        assertThat(publicKeyCredential.getAllAccounts()).hasSize(1)
        assertThat(keyStore.containsAlias(created.id)).isTrue()
    }

    @Test
    fun aRelyingPartyThatRejectsARegistrationLeavesNoKeyAndNoRow(): Unit = onActivity { activity ->
        relyingParty.failVerifyRegistrationWith = IllegalStateException("the relying party rejected it")

        val createResult = publicKeyCredential.create(activity, relyingParty.registrationOptions())

        assertThat(createResult.isFailure).isTrue()
        assertThat(createResult.exceptionOrNull()).isInstanceOf(WebAuthnException.RpException::class.java)

        // The failure arrived after the key had been generated and the row written, so this is the whole
        // point of the assertion: cleanup has to name the alias the key actually lives under. An alias
        // derived any other way makes `KeyStore.deleteEntry` a silent no-op and strands the private key.
        val credId = requireNotNull(relyingParty.lastCreateResult) { "verifyRegistration was never called" }.id
        assertThat(keyStore.containsAlias(credId)).isFalse()
        assertThat(keyStore.aliases().toList() - baselineAliases).isEmpty()
        assertThat(publicKeyCredential.getAllAccounts()).isEmpty()
    }

    @Test
    fun deleteAllAccountsRemovesEveryHardwareKey(): Unit = onActivity { activity ->
        val firstCredId = register(activity)
        val secondCredId = register(activity)
        assertThat(secondCredId).isNotEqualTo(firstCredId)
        assertThat(keyStore.containsAlias(firstCredId)).isTrue()
        assertThat(keyStore.containsAlias(secondCredId)).isTrue()

        publicKeyCredential.deleteAllAccounts()

        assertThat(keyStore.containsAlias(firstCredId)).isFalse()
        assertThat(keyStore.containsAlias(secondCredId)).isFalse()
        assertThat(publicKeyCredential.getAllAccounts()).isEmpty()
    }

    @Test
    fun deleteAccountRemovesOnlyTheRequestedCredential(): Unit = onActivity { activity ->
        val firstCredId = register(activity)
        val secondCredId = register(activity)

        publicKeyCredential.deleteAccount(firstCredId)

        assertThat(keyStore.containsAlias(firstCredId)).isFalse()
        assertThat(keyStore.containsAlias(secondCredId)).isTrue()
        val remaining = publicKeyCredential.getAllAccounts()
        assertThat(remaining).hasSize(1)
        assertThat(remaining.first().id).isEqualTo(secondCredId)
    }

    /** Registers one credential through the public API and returns its credential id, which is its alias. */
    private suspend fun register(activity: FragmentActivity): String {
        val result = publicKeyCredential.create(activity, relyingParty.registrationOptions())
        assertWithMessage("create failed: ${result.exceptionOrNull()}").that(result.isSuccess).isTrue()
        return requireNotNull(relyingParty.lastCreateResult) { "the relying party never saw a result" }.id
    }

    /**
     * Launches [TestFragmentActivity] and runs [block] with it.
     *
     * The suspending body deliberately runs on the instrumentation thread rather than inside
     * `onActivity`: nothing here touches the view hierarchy - the prompt is mocked away - and blocking
     * the main thread would deadlock anything the SDK dispatches to it.
     */
    private fun onActivity(block: suspend (FragmentActivity) -> Unit) {
        ActivityScenario.launch(TestFragmentActivity::class.java).use { scenario ->
            var launched: TestFragmentActivity? = null
            scenario.onActivity { launched = it }
            val activity = requireNotNull(launched) { "the test activity was not created" }
            runBlocking { block(activity) }
        }
    }

    private fun ByteArray.asJson(): JSONObject = JSONObject(String(this, Charsets.UTF_8))
}
