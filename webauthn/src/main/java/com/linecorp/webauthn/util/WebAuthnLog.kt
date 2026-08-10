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

package com.linecorp.webauthn.util

import android.util.Log
import com.linecorp.webauthn.BuildConfig

/**
 * Debug logging for the SDK's own use.
 *
 * Gated on [BuildConfig.DEBUG] because the published AAR ships unminified and a consumer's R8 will not
 * strip `Log.d` without an explicit `-assumenosideeffects` rule.
 *
 * Never pass user input, credential material, or relying-party data: logcat is readable by the shell user
 * and by the app's own crash reporters.
 */
internal object WebAuthnLog {
    private const val TAG = "WebAuthn"

    fun d(message: String) {
        if (BuildConfig.DEBUG) {
            Log.d(TAG, message)
        }
    }
}
