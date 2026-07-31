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

import android.content.Context
import android.os.Build
import android.security.keystore.KeyPermanentlyInvalidatedException
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import com.linecorp.webauthn.model.Fido2PromptInfo
import com.linecorp.webauthn.model.Fido2UserAuthResult
import java.security.Signature
import kotlin.coroutines.resumeWithException
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext

internal class DeviceCredentialAuthenticationHandler(
    private val authHandlerDispatcher: CoroutineDispatcher = Dispatchers.Main,
    private val keyguardManagerWrapper: KeyguardManagerWrapper = KeyguardManagerWrapper(),
) : AuthenticationHandler,
    AuthenticationCapability {

    /**
     * Below API level 30 `KeyguardManager` is the only source of truth and it has no status code, so its
     * boolean answer is mapped onto the two `BiometricManager` values that carry the same meaning.
     */
    override fun canAuthenticateStatus(context: Context): Int = if (
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.R
    ) {
        BiometricManager.from(context).canAuthenticate(
            BiometricManager.Authenticators.BIOMETRIC_STRONG or
                BiometricManager.Authenticators.DEVICE_CREDENTIAL
        )
    } else if (keyguardManagerWrapper.isSupported(context)) {
        BiometricManager.BIOMETRIC_SUCCESS
    } else {
        BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED
    }

    override fun isSupported(context: Context): Boolean =
        canAuthenticateStatus(context) == BiometricManager.BIOMETRIC_SUCCESS

    override suspend fun authenticate(
        activity: FragmentActivity,
        fido2PromptInfo: Fido2PromptInfo?,
        signatureProvider: (() -> Signature)?
    ): Fido2UserAuthResult {
        // Neither path can raise a prompt once the host has saved state — `isStateSaved` is
        // `mStateSaved || mStopped`, so it also covers a stopped host — and both would hang rather than
        // fail: androidx.biometric returns from authenticate() with no callback at all
        // (BiometricPrompt.authenticateInternal), and on API 29 the background-activity-launch rules drop
        // AuthenticationActivity's FLAG_ACTIVITY_NEW_TASK launch without startActivity throwing, so
        // KeyguardManagerWrapper's own continuation never resumes either. Both leave the caller's
        // process-wide lock held. Checked here, ahead of the branch, because the keyguard path never
        // reaches the re-check inside authenticateUserWithBiometricPrompt.
        if (activity.supportFragmentManager.isStateSaved) {
            throw AuthenticationHandler.AuthenticationErrorException(
                errorCode = AuthenticationHandler.ERROR_HOST_STATE_SAVED,
                message = HOST_STATE_SAVED_MESSAGE
            )
        }
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            authenticateUserWithBiometricPrompt(activity, fido2PromptInfo, signatureProvider)
        } else {
            authenticateUserWithKeyguardManager(activity, fido2PromptInfo, signatureProvider)
        }
    }

    private suspend fun authenticateUserWithBiometricPrompt(
        activity: FragmentActivity,
        fido2PromptInfo: Fido2PromptInfo?,
        signatureProvider: (() -> Signature)?
    ): Fido2UserAuthResult = withContext(authHandlerDispatcher) {
        suspendCancellableCoroutine { continuation ->
            // Re-checked one dispatch after the guard in `authenticate`: the `withContext` above hops to
            // Dispatchers.Main, which always posts (it is not Main.immediate), so an onSaveInstanceState or
            // onStop already sitting in the looper queue runs in between. Reading it here, on Main and in
            // the same block as authenticate(), is the only point with nothing left to interleave — and the
            // only read guaranteed to see the Main-thread writes to those non-volatile fields.
            if (activity.supportFragmentManager.isStateSaved) {
                continuation.resumeWithException(
                    AuthenticationHandler.AuthenticationErrorException(
                        errorCode = AuthenticationHandler.ERROR_HOST_STATE_SAVED,
                        message = HOST_STATE_SAVED_MESSAGE
                    )
                )
                return@suspendCancellableCoroutine
            }

            val promptInfo =
                BiometricPrompt.PromptInfo.Builder()
                    .setTitle(fido2PromptInfo?.title ?: "Device Credential Authentication")
                    .setSubtitle(fido2PromptInfo?.subtitle ?: "Enter device credentials to proceed")
                    .setDescription(
                        fido2PromptInfo?.description
                            ?: "Input your Fingerprint or device credential to ensure it's you!",
                    )
                    .setAllowedAuthenticators(
                        BiometricManager.Authenticators.BIOMETRIC_STRONG or
                            BiometricManager.Authenticators.DEVICE_CREDENTIAL
                    )
                    .build()

            val biometricPrompt =
                BiometricPrompt(
                    activity,
                    ContextCompat.getMainExecutor(activity.applicationContext),
                    object : BiometricPrompt.AuthenticationCallback() {
                        override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                            if (continuation.isActive) {
                                continuation.resumeWith(
                                    Result.success(
                                        Fido2UserAuthResult(
                                            signature = result.cryptoObject?.signature
                                        )
                                    )
                                )
                            }
                        }

                        override fun onAuthenticationFailed() {
                            // In the event of an authentication failure, the user is allowed to try again.
                        }

                        override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                            if (continuation.isActive) {
                                continuation.resumeWithException(
                                    AuthenticationHandler.AuthenticationErrorException(
                                        errorCode,
                                        "Biometric authentication error: $errString"
                                    )
                                )
                            }
                        }
                    },
                )

            continuation.invokeOnCancellation {
                biometricPrompt.cancelAuthentication()
            }

            if (signatureProvider != null) {
                val cryptoObject = BiometricPrompt.CryptoObject(signatureProvider())
                biometricPrompt.authenticate(promptInfo, cryptoObject)
            } else {
                biometricPrompt.authenticate(promptInfo)
            }
        }
    }

    private suspend fun authenticateUserWithKeyguardManager(
        activity: FragmentActivity,
        fido2PromptInfo: Fido2PromptInfo?,
        signatureProvider: (() -> Signature)?
    ): Fido2UserAuthResult = withContext(authHandlerDispatcher) {
        try {
            keyguardManagerWrapper.authenticate(activity, fido2PromptInfo)
            val signature = signatureProvider?.invoke()
            return@withContext Fido2UserAuthResult(signature = signature)
        } catch (e: KeyguardManagerWrapper.KeyguardNotSecuredException) {
            throw AuthenticationHandler.AuthenticationErrorException(
                message = "Keyguard not secured",
                cause = e
            )
        } catch (e: KeyguardManagerWrapper.DeviceCredentialIntentNotAvailableException) {
            throw AuthenticationHandler.AuthenticationErrorException(
                message = "Device credential intent not available",
                cause = e
            )
        } catch (e: KeyguardManagerWrapper.KeyguardManagerAuthenticationFailedException) {
            throw AuthenticationHandler.AuthenticationErrorException(
                errorCode = e.errorCode,
                message = e.message,
                cause = e
            )
        } catch (e: KeyPermanentlyInvalidatedException) {
            // Must not be wrapped. `Authenticator.authenticate` has a dedicated mapping for this to
            // `WebAuthnException.AuthenticationException.KeyPermanentlyInvalidatedException`, but its
            // AuthenticationErrorException branch matches first, so wrapping made a condition that requires
            // re-registration arrive as a bare NotAllowedException — indistinguishable from a user
            // cancellation. Only this path needs the rethrow: from API 30 up, `signatureProvider()` is
            // invoked inside `suspendCancellableCoroutine` with no catch around it, so it already propagates.
            //
            // These keys are time-bound (`setUserAuthenticationValidityDurationSeconds`), so
            // `setInvalidatedByBiometricEnrollment` does not apply to them; the trigger here is the secure
            // lock screen being removed or reset, not a new fingerprint enrolment.
            //
            // Deliberately not extended to `UserNotAuthenticatedException`: `Authenticator.authenticate` has
            // no mapping for it, so rethrowing it would only turn a NotAllowedException into an
            // UnknownException.
            throw e
        } catch (e: CancellationException) {
            // Must not be wrapped either, and for the same shape of reason as the branch above: a
            // CancellationException is an IllegalStateException, so the terminal `catch (e: Exception)` below
            // caught it and handed back an AuthenticationErrorException with a null errorCode, which
            // `Authenticator.authenticate` maps to NotAllowedException. On API 28/29 with DeviceCredential —
            // the only configuration that reaches this branch — a back press while the keyguard was showing
            // therefore came back to the caller as `Result.failure(NotAllowedException)` from a coroutine
            // whose scope was already dead.
            //
            // Not redundant with the cancellation that is already in flight, which is the tempting reason to
            // delete this clause: a failure raised while the job is cancelling *wins* over that cancellation,
            // because `JobSupport.getFinalRootCause` prefers the first non-CancellationException among a
            // completing job's exceptions. So without this rethrow the rewrite is what the caller sees. Both
            // keyguard tests in `PublicKeyCredentialTest` fail if it is removed.
            //
            // Only this path needs the rethrow: from API 30 up the prompt runs inside
            // `suspendCancellableCoroutine` with no catch around it, so cancellation already propagates.
            throw e
        } catch (e: Exception) {
            // Named for the same reason as every other unhandled-throwable site in this release: the
            // constant message identified nothing, so an unexpected platform failure on this path - the only
            // one taken on API 28/29 with DeviceCredential - could only be told apart two levels down the
            // cause chain, after `Authenticator.authenticate` had already wrapped it in a NotAllowedException.
            throw AuthenticationHandler.AuthenticationErrorException(
                message = "An unexpected error occurred: ${e::class.java.name}: ${e.message}",
                cause = e
            )
        }
    }
}
