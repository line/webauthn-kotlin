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

@file:Suppress("DEPRECATION")

package com.linecorp.webauthn.handler

import android.app.AlertDialog
import android.hardware.fingerprint.FingerprintManager
import android.os.CancellationSignal
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.view.accessibility.AccessibilityNodeInfo
import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentManager
import androidx.lifecycle.Lifecycle
import androidx.test.core.app.ActivityScenario
import androidx.test.platform.app.InstrumentationRegistry
import com.linecorp.webauthn.util.TestFragmentActivity
import io.mockk.every
import io.mockk.mockk
import java.security.KeyPairGenerator
import java.security.Signature
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.cancel
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertSame
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class LegacyFingerprintFallbackRotationTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private val request = RecordingFingerprintRequest()
    private val signature = Signature.getInstance("SHA256withECDSA").apply {
        initSign(KeyPairGenerator.getInstance("EC").apply { initialize(256) }.generateKeyPair().private)
    }
    private val promptInfo = BiometricPrompt.PromptInfo.Builder()
        .setTitle("Verify test account")
        .setSubtitle("Test subtitle")
        .setDescription("Test description")
        .setNegativeButtonText("Stop verification")
        .build()
    private lateinit var scenario: ActivityScenario<TestFragmentActivity>

    @BeforeEach
    fun launchActivity() {
        scenario = ActivityScenario.launch(TestFragmentActivity::class.java)
    }

    @AfterEach
    fun closeActivity() {
        TestFragmentActivity.onCreateAction = null
        scope.cancel()
        instrumentation.waitForIdleSync()
        scenario.close()
    }

    @Test
    fun authenticationStartedInOnCreateSurvivesStart() {
        scenario.close()
        val authentication = AtomicReference<Deferred<Signature>>()
        val initialState = AtomicReference<Lifecycle.State>()
        TestFragmentActivity.onCreateAction = { activity ->
            initialState.set(activity.lifecycle.currentState)
            authentication.set(scope.async(start = CoroutineStart.UNDISPATCHED) {
                LegacyFingerprintFallback.authenticate(activity, promptInfo, signature, request)
            })
        }
        scenario = ActivityScenario.launch(TestFragmentActivity::class.java)

        assertFalse(initialState.get().isAtLeast(Lifecycle.State.STARTED))
        assertTrue(authentication.get().isActive)
        assertEquals(1, request.calls.get())
        scenario.onActivity { request.callback.get().onAuthenticationSucceeded(success()) }
        assertSame(signature, await(authentication.get()))
    }

    @Test
    fun rotationKeepsRequestAndAllowsRetryAndSuccess() {
        val authentication = authenticate()
        scenario.onActivity { request.callback.get().onAuthenticationHelp(1, "Try again") }
        repeat(2) { scenario.recreate() }

        assertTrue(authentication.isActive)
        assertEquals(1, request.calls.get())
        assertFalse(request.signal.get().isCanceled)
        assertTrue(waitForText("Verify test account"))
        assertTrue(waitForText("Test subtitle\n\nTest description\n\nTry again"))

        scenario.onActivity {
            request.callback.get().onAuthenticationFailed()
            assertTrue(authentication.isActive)
            request.callback.get().onAuthenticationSucceeded(success())
        }
        assertSame(signature, await(authentication))
        assertNull((request.callback.get() as LegacyFingerprintFallback.CallbackRelay).target)
        instrumentation.waitForIdleSync()
        scenario.onActivity { assertNull(fingerprintPrompt(it.supportFragmentManager)) }
    }

    @Test
    fun successWhileDetachedDoesNotRestoreACompletedPrompt() {
        val authentication = authenticate()
        val completed = CountDownLatch(1)
        val result = success()
        scenario.onActivity { activity ->
            val prompt = fingerprintPrompt(activity.supportFragmentManager)!!
            activity.afterDestroy = {
                assertTrue(activity.isChangingConfigurations)
                assertFalse(prompt.isAdded)
                request.callback.get().onAuthenticationSucceeded(result)
                completed.countDown()
            }
        }
        scenario.recreate()

        assertTrue(completed.await(5, TimeUnit.SECONDS))
        assertSame(signature, await(authentication))
        instrumentation.waitForIdleSync()
        scenario.onActivity { assertNull(fingerprintPrompt(it.supportFragmentManager)) }
    }

    @Test
    fun leavingForegroundCancelsRequest() {
        val authentication = authenticate()
        scenario.moveToState(Lifecycle.State.CREATED)
        assertError(authentication, BiometricPrompt.ERROR_CANCELED)
        assertTrue(request.signal.get().isCanceled)
    }

    @Test
    fun authenticationOnStoppedActivityIsCanceled() {
        val activity = AtomicReference<TestFragmentActivity>()
        val authentication = AtomicReference<Deferred<Signature>>()
        scenario.onActivity { activity.set(it) }
        scenario.moveToState(Lifecycle.State.CREATED)
        instrumentation.runOnMainSync {
            authentication.set(scope.async(start = CoroutineStart.UNDISPATCHED) {
                LegacyFingerprintFallback.authenticate(activity.get(), promptInfo, signature, request)
            })
        }

        assertError(authentication.get(), BiometricPrompt.ERROR_CANCELED)
        assertEquals(0, request.calls.get())
    }

    @Test
    fun negativeButtonKeepsBiometricPromptErrorCode() {
        val authentication = authenticate()
        scenario.onActivity {
            val dialog = fingerprintPrompt(it.supportFragmentManager)!!.dialog as AlertDialog
            dialog.getButton(AlertDialog.BUTTON_NEGATIVE).performClick()
        }
        assertError(authentication, BiometricPrompt.ERROR_NEGATIVE_BUTTON)
        assertTrue(request.signal.get().isCanceled)
    }

    @Test
    fun dismissingDialogKeepsUserCanceledErrorCode() {
        val authentication = authenticate()
        scenario.onActivity { fingerprintPrompt(it.supportFragmentManager)!!.dialog!!.cancel() }
        assertError(authentication, BiometricPrompt.ERROR_USER_CANCELED)
        assertTrue(request.signal.get().isCanceled)
    }

    @Test
    fun backgroundCallerUsesMainThreadAndCancellationIgnoresLateCallbacks() {
        val authentication = AtomicReference<Deferred<Signature>>()
        scenario.onActivity { activity ->
            authentication.set(scope.async(Dispatchers.Default) {
                LegacyFingerprintFallback.authenticate(activity, promptInfo, signature, request)
            })
        }
        assertTrue(request.started.await(5, TimeUnit.SECONDS))
        assertSame(Looper.getMainLooper(), request.looper.get())

        authentication.get().cancel()
        runBlocking { authentication.get().join() }
        instrumentation.waitForIdleSync()
        assertTrue(request.signal.get().isCanceled)
        scenario.onActivity {
            request.callback.get().onAuthenticationError(BiometricPrompt.ERROR_TIMEOUT, "late error")
            request.callback.get().onAuthenticationSucceeded(success())
            assertNull(fingerprintPrompt(it.supportFragmentManager))
        }
        assertTrue(authentication.get().isCancelled)
    }

    @Test
    fun restoredFragmentWithoutARequestIsRemoved() {
        scenario.onActivity {
            LegacyFingerprintFallback.FingerprintDialogFragment().showNow(it.supportFragmentManager, "restored")
        }
        instrumentation.waitForIdleSync()
        scenario.onActivity { assertNull(it.supportFragmentManager.findFragmentByTag("restored")) }
    }

    private fun authenticate(): Deferred<Signature> {
        val authentication = AtomicReference<Deferred<Signature>>()
        scenario.onActivity { activity ->
            authentication.set(scope.async(start = CoroutineStart.UNDISPATCHED) {
                LegacyFingerprintFallback.authenticate(activity, promptInfo, signature, request)
            })
            assertTrue(authentication.get().isActive)
        }
        return authentication.get()
    }

    private fun success(): FingerprintManager.AuthenticationResult = mockk {
        every { cryptoObject } returns FingerprintManager.CryptoObject(signature)
    }

    private fun await(authentication: Deferred<Signature>): Signature = runBlocking {
        withTimeout(5_000) { authentication.await() }
    }

    private fun assertError(authentication: Deferred<Signature>, code: Int) {
        val error = assertThrows(AuthenticationHandler.AuthenticationErrorException::class.java) { await(authentication) }
        assertEquals(code, error.errorCode)
    }

    private fun fingerprintPrompt(manager: FragmentManager): LegacyFingerprintFallback.FingerprintDialogFragment? =
        manager.fragments.filterIsInstance<LegacyFingerprintFallback.FingerprintDialogFragment>().singleOrNull()

    private fun waitForText(text: String): Boolean {
        fun containsText(node: AccessibilityNodeInfo?): Boolean {
            if (node == null) return false
            if (node.text?.toString() == text) return true
            return (0 until node.childCount).any { containsText(node.getChild(it)) }
        }
        val deadline = SystemClock.elapsedRealtime() + 5_000
        do {
            instrumentation.waitForIdleSync()
            if (containsText(instrumentation.uiAutomation.rootInActiveWindow)) return true
            Thread.sleep(50)
        } while (SystemClock.elapsedRealtime() < deadline)
        return false
    }

    private class RecordingFingerprintRequest : LegacyFingerprintFallback.FingerprintRequest {
        val calls = AtomicInteger()
        val signal = AtomicReference<CancellationSignal>()
        val callback = AtomicReference<FingerprintManager.AuthenticationCallback>()
        val looper = AtomicReference<Looper>()
        val started = CountDownLatch(1)

        override fun authenticate(
            signature: Signature,
            cancellationSignal: CancellationSignal,
            callback: FingerprintManager.AuthenticationCallback,
            handler: Handler,
        ) {
            calls.incrementAndGet()
            signal.set(cancellationSignal)
            this.callback.set(callback)
            looper.set(Looper.myLooper())
            started.countDown()
        }
    }
}
