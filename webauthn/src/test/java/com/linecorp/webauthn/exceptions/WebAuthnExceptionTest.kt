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

package com.linecorp.webauthn.exceptions

import com.google.common.truth.Truth.assertThat
import org.junit.jupiter.api.Test

class WebAuthnExceptionTest {

    @Test
    fun `UserCancelledException is a NotAllowedException so existing catch clauses still match`() {
        val e: Throwable = WebAuthnException.CoreException.UserCancelledException()
        assertThat(e).isInstanceOf(WebAuthnException.CoreException.NotAllowedException::class.java)
        assertThat(e).isInstanceOf(WebAuthnException.CoreException::class.java)
        assertThat(e).isInstanceOf(WebAuthnException::class.java)
    }

    @Test
    fun `NotAllowedException carries the biometric error code`() {
        val e = WebAuthnException.CoreException.NotAllowedException("boom").apply { errorCode = 13 }
        assertThat(e.errorCode).isEqualTo(13)
    }

    @Test
    fun `NotAllowedException errorCode defaults to null`() {
        assertThat(WebAuthnException.CoreException.NotAllowedException().errorCode).isNull()
    }

    @Test
    fun `ConstraintException carries the canAuthenticate status`() {
        val e = WebAuthnException.CoreException.ConstraintException("boom").apply { canAuthenticateStatus = 11 }
        assertThat(e.canAuthenticateStatus).isEqualTo(11)
    }

    @Test
    fun `KeyGenerationException is a SecureExecutionException and carries the keystore error code`() {
        val e = WebAuthnException.KeyGenerationException("boom").apply { keyStoreErrorCode = -100 }
        assertThat(e).isInstanceOf(WebAuthnException.SecureExecutionException::class.java)
        assertThat(e.keyStoreErrorCode).isEqualTo(-100)
    }

    @Test
    fun `DeletionException retains the triggering exception and exposes it as suppressed`() {
        val trigger = IllegalStateException("original failure")
        val cause = RuntimeException("cleanup failure")

        val e = WebAuthnException.DeletionException("delete failed", cause = cause, trigger = trigger)

        assertThat(e.trigger).isSameInstanceAs(trigger)
        assertThat(e.cause).isSameInstanceAs(cause)
        assertThat(e.suppressed.toList()).containsExactly(trigger)
    }

    @Test
    fun `DeletionException does not suppress the trigger when it is also the cause`() {
        val same = RuntimeException("same")

        val e = WebAuthnException.DeletionException("delete failed", cause = same, trigger = same)

        assertThat(e.suppressed).isEmpty()
    }

    @Test
    fun `DeletionException tolerates a null trigger`() {
        val e = WebAuthnException.DeletionException("delete failed")

        assertThat(e.trigger).isNull()
        assertThat(e.suppressed).isEmpty()
    }
}
