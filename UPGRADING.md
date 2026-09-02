# Upgrading

This document covers the changes that require action from applications using this library. For the full
list of fixes and additions in each release, see [CHANGELOG.md](CHANGELOG.md).

## 1.1.3 to 1.2.0

Registration and authentication responses are byte-for-byte identical to 1.1.3. The attestation object,
the credential public key, `clientDataJSON` and the assertion are unchanged, so credentials already
registered keep verifying and no relying-party parser change is required.

Eight changes are visible to callers. Four need a code change, and one of those four stops a source
upgrade from compiling.

### Action required

#### 1. Catch `UserCancelledException` before `NotAllowedException`

A user dismissing the authentication prompt previously arrived as
`WebAuthnException.CoreException.NotAllowedException`, indistinguishable by type from a hardware failure
or a timeout, so a normal outcome was reported as an SDK error. It now arrives as
`UserCancelledException`, a subtype of `NotAllowedException`.

Existing `catch` clauses keep matching, so nothing breaks if you do nothing. To stop counting
cancellations as failures, handle the subtype first:

```kotlin
try {
    publicKeyCredential.get(activity, options, promptInfo).getOrThrow()
} catch (e: WebAuthnException.CoreException.UserCancelledException) {
    // Normal outcome. Do not report as an error.
} catch (e: WebAuthnException.CoreException.NotAllowedException) {
    // A genuine authentication failure. e.errorCode carries the BiometricPrompt error code.
}
```

`ERROR_CANCELED` is included in the codes treated as a cancellation. The platform also reports it when
the host activity stops or the device locks mid-prompt, so a small number of lifecycle cancellations are
classified as user intent. That is a deliberate trade-off: real dismissals arrive with that code on some
devices.

#### 2. `getAllAccounts()` returns roughly a quarter as many entries

The previous implementation queried the credential storage once per authenticator type and concatenated
the results, so every stored credential was returned four times. It now queries once. Remove any
de-duplication or count adjustment added to compensate.

#### 3. `CredentialSourceStorage.delete(credId)` must honour its `credId` argument

The interface has always documented `delete` as removing the credential named by `credId`, but 1.1.3
often did not reach it: cleanup ran inside a cancellable block, so a coroutine that had already been
cancelled threw before the deletion happened. 1.2.0 runs the terminal cleanup to completion, so
`delete(credId)` is now called on paths that previously skipped it - in particular when the caller's
scope is cancelled during registration, such as the user leaving the screen.

If your implementation ignores `credId` and clears a single stored slot, a cancelled or failed
registration can now delete a **different, still-valid credential**, leaving the user unenrolled locally
with a key stranded in the keystore. Verify your implementation before upgrading:

```kotlin
override fun delete(credId: String) {
    val stored = load(credId) ?: return
    if (stored.id != credId) return
    // remove only this credential
}
```

#### 4. `KeyguardManagerWrapper.AuthenticationActivity.start` is no longer public

This is the only change that stops a source upgrade from compiling. The function was public and accepted
a ready-made `Intent`; it is now `internal`, and the activity builds its own confirm-device-credential
Intent. There is no drop-in replacement. Call the function the SDK itself uses:

```kotlin
KeyguardManagerWrapper().authenticate(context, fido2PromptInfo)
```

Recompiling against 1.2.0 gives a compile error at the call site. Replacing the artifact without
recompiling gives a `NoSuchMethodError` at runtime, because an `internal` function's JVM name is
mangled.

### Behaviour changes to review

#### 5. `deleteAllAccounts()` destroys key material

It previously deleted only the database rows and left every private key in the keystore. It now deletes
the key material as well, which cannot be undone. Confirm that your sign-out or wipe flow expects the
keys to be destroyed and that it still deregisters the credential at the relying party. Use
`deleteAccount(credId)` to remove a single credential.

Two further differences:

- Do not call `deleteAllAccounts()` or `deleteAccount()` while a `create()` or `get()` ceremony is in
  flight. The account APIs deliberately stay outside the lock those two hold, so a concurrent call can
  destroy a key that is in use.
- Failures are no longer wrapped in `CredSrcStorageException`. A key deletion that fails surfaces as
  `SecureExecutionException`, and the first failure is rethrown with any later ones attached as
  suppressed exceptions. Catch `WebAuthnException` rather than the narrower type.

#### 6. A keystore rejection during registration arrives as `KeyGenerationException`

It was previously `UnknownException` with no error code. `KeyGenerationException` is a subtype of
`SecureExecutionException`, so a handler for that type already matches; code branching specifically on
`UnknownException` for this case needs the new type. `keyStoreErrorCode` carries the KeyMint numeric code
on API 33 and above, where the platform exposes it.

#### 7. The biometric registration prompt requires a Class 3 (Strong) authenticator

Support detection already required Class 3 and the generated key is bound to Class 3, but the
registration prompt accepted Class 2 (Weak) because it passes no `CryptoObject`. It is now pinned to
Class 3, which has two consequences:

- On a device with both a Class 3 and a Class 2 biometric enrolled, a user who registered with the
  Class 2 method will be asked for the Class 3 one instead.
- On **Samsung devices running Android 9 (API 28)** the prompt changes from the framework dialog to the
  legacy fingerprint dialog, because `androidx.biometric` falls back for crypto-backed prompts on that
  vendor. Users already saw that dialog during authentication, so this makes registration consistent
  with it. Re-test your registration flow on that combination.

#### 8. Adopt `checkAuthenticationAvailability()` before `create()`

Previously the only way to learn whether the device could authenticate was to call `create()` and
inspect the resulting `ConstraintException`, which reported an expected device state as an error:

```kotlin
val availability = PublicKeyCredential.checkAuthenticationAvailability(
    context,
    AuthenticationMethod.Biometric,
)
if (!availability.isAvailable) {
    when (availability.reason) {
        AuthenticationAvailability.Reason.NONE_ENROLLED -> promptUserToEnrol()
        AuthenticationAvailability.Reason.NO_HARDWARE -> hideBiometricOption()
        else -> showUnavailableMessage()
    }
    return
}
```

It never throws. It answers whether the user can authenticate at all, not whether an already registered
credential is still usable: re-enrolling a biometric invalidates the credential's key while leaving the
result `AVAILABLE`, so `get()` can still fail with `KeyPermanentlyInvalidatedException`.

### Relying-party coordination

Devices where StrongBox rejects key generation now produce TEE-backed keys, because the SDK retries
without StrongBox instead of failing the registration. If your server gates on the attestation security
level, it will see TEE for those devices. Nothing else on the wire changes.

### Known limitations

- **Keys orphaned before 1.2.0 are not recovered.** A registration that failed after key generation left
  a private key in the keystore with no database row naming it. Those keys are still present after
  upgrading, and the SDK does not enumerate the keystore to find them because it does not exclusively
  own it. The fixes in this release stop new orphans from being created.
- **The authentication prompt can hang when the host activity has already saved its instance state.**
  `androidx.biometric` returns from `authenticate()` without invoking any callback in that case, leaving
  the operation suspended and blocking later `create()` and `get()` calls. Do not start a ceremony from
  a screen that is being backgrounded.
