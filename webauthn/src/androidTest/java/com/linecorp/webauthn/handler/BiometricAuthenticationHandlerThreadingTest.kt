/*
 * Copyright 2026 LY Corporation
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

import android.os.Looper
import androidx.biometric.BiometricPrompt
import androidx.test.core.app.ActivityScenario
import androidx.test.platform.app.InstrumentationRegistry
import com.linecorp.webauthn.util.TestFragmentActivity
import io.mockk.every
import io.mockk.mockk
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertSame
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class BiometricAuthenticationHandlerThreadingTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private val started = CountDownLatch(1)
    private val canceled = CountDownLatch(1)
    private val startLooper = AtomicReference<Looper>()
    private val cancelLooper = AtomicReference<Looper>()
    private val prompt = mockk<BiometricPrompt>()
    private lateinit var scenario: ActivityScenario<TestFragmentActivity>

    @BeforeEach
    fun setUp() {
        every { prompt.authenticate(any<BiometricPrompt.PromptInfo>()) } answers {
            startLooper.set(Looper.myLooper())
            started.countDown()
        }
        every { prompt.cancelAuthentication() } answers {
            cancelLooper.set(Looper.myLooper())
            canceled.countDown()
        }
        scenario = ActivityScenario.launch(TestFragmentActivity::class.java)
    }

    @AfterEach
    fun tearDown() {
        scope.cancel()
        instrumentation.waitForIdleSync()
        scenario.close()
    }

    @Test
    fun nonCryptoAuthenticationUsesMainWithBackgroundDispatcher() {
        val activity = AtomicReference<TestFragmentActivity>()
        scenario.onActivity { activity.set(it) }
        val handler = BiometricAuthenticationHandler(Dispatchers.Default) { _, _, _ ->
            assertSame(Looper.getMainLooper(), Looper.myLooper())
            prompt
        }
        val authentication = scope.async {
            handler.authenticate(activity.get(), null, null)
        }
        val didStart = started.await(10, TimeUnit.SECONDS)
        if (!didStart && authentication.isCompleted) runBlocking { authentication.await() }
        assertTrue(didStart)
        assertSame(Looper.getMainLooper(), startLooper.get())

        runBlocking {
            scope.launch { authentication.cancel() }.join()
            authentication.join()
        }
        assertTrue(canceled.await(5, TimeUnit.SECONDS))
        assertSame(Looper.getMainLooper(), cancelLooper.get())
        assertTrue(authentication.isCancelled)
    }
}
