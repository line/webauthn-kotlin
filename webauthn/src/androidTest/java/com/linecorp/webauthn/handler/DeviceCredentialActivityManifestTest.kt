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

import android.content.ComponentName
import androidx.test.platform.app.InstrumentationRegistry
import com.google.common.truth.Truth.assertThat
import org.junit.jupiter.api.Test

/**
 * Guards the manifest declaration of the device-credential activity against regression.
 *
 * This activity must never be reachable from outside the host app. It runs a confirm-device-credential
 * Intent under the host's identity, and its result establishes user verification for a WebAuthn
 * ceremony, so an external caller able to start it could influence both. Android lint does not flag an
 * exported activity - being exported is a legitimate choice for most - so nothing else in the build
 * fails if the attribute comes back, which is exactly why it is asserted here.
 *
 * The value has to be read from the merged manifest rather than from the source XML, because a manifest
 * merge is what would reintroduce it: a consumer's or a dependency's manifest, or an AGP default for a
 * component with an intent filter. `getActivityInfo` reads what was actually installed.
 *
 * Needs no particular API level or enrolled credential, only a device or emulator: the activity is never
 * started.
 */
class DeviceCredentialActivityManifestTest {

    @Test
    fun theDeviceCredentialActivityIsNotExported() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        // Named as a string, not as `KeyguardManagerWrapper.AuthenticationActivity::class.java`: the
        // manifest entry is a string too, so a rename that updates the class but not the manifest has to
        // fail here rather than silently follow along.
        val component = ComponentName(
            context,
            "com.linecorp.webauthn.handler.KeyguardManagerWrapper\$AuthenticationActivity"
        )

        val activityInfo = context.packageManager.getActivityInfo(component, 0)

        assertThat(activityInfo.exported).isFalse()
    }
}
