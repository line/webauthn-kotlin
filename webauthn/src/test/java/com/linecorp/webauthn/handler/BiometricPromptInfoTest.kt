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

package com.linecorp.webauthn.handler

import android.security.keystore.KeyPermanentlyInvalidatedException
import android.text.TextUtils
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity
import androidx.fragment.app.FragmentManager
import com.google.common.truth.Truth.assertThat
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mockk.unmockkStatic
import kotlin.test.assertFailsWith
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withTimeout
import org.junit.jupiter.api.Test

/**
 * androidx.biometric 1.1.0 returns from `BiometricPrompt.authenticate()` without ever invoking a callback
 * when the host `FragmentManager` has already saved its state (`BiometricPrompt.authenticateInternal`). The
 * SDK's only resume paths are the two `AuthenticationCallback` methods, and the whole ceremony runs under a
 * process-wide mutex, so one such call would wedge every later `create()`/`get()`. Both handlers therefore
 * pre-check `isStateSaved` and fail fast.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class BiometricPromptInfoTest {

    private fun activityWithSavedState(stateSaved: Boolean): FragmentActivity {
        val fragmentManager = mockk<FragmentManager>()
        every { fragmentManager.isStateSaved } returns stateSaved
        return mockk<FragmentActivity>().also { every { it.supportFragmentManager } returns fragmentManager }
    }

    @Test
    fun `biometric handler fails fast instead of hanging when the host has saved state`(): Unit = runTest {
        val handler = BiometricAuthenticationHandler(UnconfinedTestDispatcher(testScheduler))

        // Awaited inside `runTest` rather than in a nested `runBlocking`: if a regression ever turned this
        // into a real suspension, runTest's own timeout fails the test instead of blocking the JVM until
        // Gradle gives up. That matters more here than anywhere, this being the anti-hang suite.
        val e = assertFailsWith<AuthenticationHandler.AuthenticationErrorException> {
            handler.authenticate(activityWithSavedState(true), null, null)
        }

        assertThat(e.errorCode).isEqualTo(AuthenticationHandler.ERROR_HOST_STATE_SAVED)
    }

    @Test
    fun `device credential handler fails fast instead of hanging when the host has saved state`(): Unit = runTest {
        val handler = DeviceCredentialAuthenticationHandler(UnconfinedTestDispatcher(testScheduler))

        val e = assertFailsWith<AuthenticationHandler.AuthenticationErrorException> {
            handler.authenticate(activityWithSavedState(true), null, null)
        }

        assertThat(e.errorCode).isEqualTo(AuthenticationHandler.ERROR_HOST_STATE_SAVED)
    }

    @Test
    fun `the device credential guard does not fire while the host can still show a prompt`(): Unit = runTest {
        // The counterpart the guard must not break: an ordinary foreground host. `isStateSaved` is
        // `mStateSaved || mStopped` and both are cleared by dispatchCreate/dispatchStart/dispatchResume, so a
        // ceremony started from onCreate or onStart reads false here and must run to completion.
        val wrapper: KeyguardManagerWrapper = mockk()
        coEvery { wrapper.authenticate(any(), any()) } returns true
        val handler = DeviceCredentialAuthenticationHandler(UnconfinedTestDispatcher(testScheduler), wrapper)

        val result = handler.authenticate(activityWithSavedState(false), null, null)

        assertThat(result.signature).isNull()
    }

    @Test
    fun `the biometric guard does not fire while the host can still show a prompt`() {
        val handler = BiometricAuthenticationHandler(Dispatchers.Unconfined)

        // Without saved state the handler walks past the guard and goes on to build the prompt, which this
        // strict mock cannot satisfy (it stubs nothing beyond the FragmentManager), so a failure of some
        // kind is expected here and is not what is under test. What must not happen is the state-saved
        // sentinel: that would mean the guard is unconditional and no prompt would ever be shown again.
        val thrown = runCatching {
            runBlocking {
                withTimeout(5_000) { handler.authenticate(activityWithSavedState(false), null, null) }
            }
        }.exceptionOrNull()

        assertThat(thrown).isNotNull()
        assertThat((thrown as? AuthenticationHandler.AuthenticationErrorException)?.errorCode)
            .isNotEqualTo(AuthenticationHandler.ERROR_HOST_STATE_SAVED)
    }

    @Test
    fun `the host-state-saved sentinel stays negative so it cannot collide with a BiometricPrompt code`() {
        // The only numerically load-bearing property of the constant: BiometricPrompt.ERROR_* are 1..15, and
        // Authenticator maps 5, 10 and 13 to UserCancelledException. A positive value here would silently
        // become an existing platform code, and 5/10/13 would misreport this failure as a user cancellation.
        assertThat(AuthenticationHandler.ERROR_HOST_STATE_SAVED).isLessThan(0)

        val platformErrorCodes = listOf(
            BiometricPrompt.ERROR_HW_UNAVAILABLE,
            BiometricPrompt.ERROR_UNABLE_TO_PROCESS,
            BiometricPrompt.ERROR_TIMEOUT,
            BiometricPrompt.ERROR_NO_SPACE,
            BiometricPrompt.ERROR_CANCELED,
            BiometricPrompt.ERROR_LOCKOUT,
            BiometricPrompt.ERROR_VENDOR,
            BiometricPrompt.ERROR_LOCKOUT_PERMANENT,
            BiometricPrompt.ERROR_USER_CANCELED,
            BiometricPrompt.ERROR_NO_BIOMETRICS,
            BiometricPrompt.ERROR_HW_NOT_PRESENT,
            BiometricPrompt.ERROR_NEGATIVE_BUTTON,
            BiometricPrompt.ERROR_NO_DEVICE_CREDENTIAL,
            BiometricPrompt.ERROR_SECURITY_UPDATE_REQUIRED
        )
        assertThat(platformErrorCodes).doesNotContain(AuthenticationHandler.ERROR_HOST_STATE_SAVED)
    }

    @Test
    fun `the prompt requires a class 3 biometric, matching what isSupported gates on`() {
        // PromptInfo.Builder.build() validates its strings through TextUtils.isEmpty, which is an unmocked
        // android.jar stub on the JVM. Only the emptiness answers matter here, and every string this builder
        // sets is non-empty.
        mockkStatic(TextUtils::class)
        every { TextUtils.isEmpty(any()) } returns false

        // Unmocked in a `finally`: a failed assertion below would otherwise leave the TextUtils static mock
        // installed for every test that runs after it in this fork.
        try {
            val promptInfo = BiometricAuthenticationHandler().buildPromptInfo(null)

            assertThat(promptInfo.allowedAuthenticators)
                .isEqualTo(BiometricManager.Authenticators.BIOMETRIC_STRONG)
        } finally {
            unmockkStatic(TextUtils::class)
        }
    }

    @Test
    fun `the keyguard path lets a permanently invalidated key through unwrapped`(): Unit = runTest {
        // Below API 30 the signature is initialised after the keyguard returns, inside
        // `authenticateUserWithKeyguardManager`'s own try, so `initSign` throwing
        // KeyPermanentlyInvalidatedException used to be flattened by the generic `catch (e: Exception)` into
        // an AuthenticationErrorException. `Authenticator.authenticate` matches its
        // AuthenticationErrorException branch before its dedicated KeyPermanentlyInvalidatedException branch,
        // so a state that requires re-registration reached the app as a NotAllowedException with no error
        // code - indistinguishable from a user cancellation. The API >= 30 path calls `signatureProvider()`
        // outside any catch, so it already propagated; this pins the two branches to the same behaviour.
        // `Build.VERSION.SDK_INT` reads 0 on the unit-test JVM, so `authenticate` takes the keyguard branch.
        val wrapper: KeyguardManagerWrapper = mockk()
        coEvery { wrapper.authenticate(any(), any()) } returns true
        val handler = DeviceCredentialAuthenticationHandler(UnconfinedTestDispatcher(testScheduler), wrapper)
        val invalidated = KeyPermanentlyInvalidatedException()

        val thrown = assertFailsWith<KeyPermanentlyInvalidatedException> {
            handler.authenticate(activityWithSavedState(false), null) { throw invalidated }
        }

        // Identity, not just type: `Authenticator` republishes the platform exception on `cause`, so a
        // handler that caught and re-created it would break consumers reading the original off `cause`.
        assertThat(thrown).isSameInstanceAs(invalidated)
    }
}
