# Change Log

## 1.2.0 (2026-07-31)

### Fixed
- `cleanup()` deleted a re-encoded key alias, so no key the SDK created was ever removed. Failed
  registrations left an orphaned hardware-backed private key behind.
- `deleteAllAccounts()` removed database rows but never the corresponding keystore keys.
- `getAllAccounts()` returned every credential four times.
- The authentication prompt could return without ever invoking a callback when the host activity had
  saved its state, hanging the operation and blocking all later `create()`/`get()` calls.
- `create()`/`get()` reported coroutine cancellation as a relying-party error.
- `KeyPermanentlyInvalidatedException` was reported as a generic authentication error on API 28/29
  device-credential authentication.
- `get()` could fail with a non-`WebAuthnException`, contradicting its documented contract.
- Key generation that requested StrongBox and was rejected by the platform keystore — whether for
  StrongBox unavailability or for any other reason — is now retried without StrongBox instead of failing
  outright. Key generation that did not request StrongBox is unchanged: it is still attempted once.
- The biometric registration prompt allowed Class 2 (Weak) authenticators while support detection and
  the generated key both required Class 3 (Strong).
- `user.id` length is validated in bytes when the value decodes as base64url, so spec-legal 49–64 byte
  user handles are accepted. A value that is not valid base64url still falls back to the previous
  character count.
- AndroidKeyStore work no longer runs on the caller's thread, with one deliberate exception: the
  `Signature` is still created and initialised on the main dispatcher, because `BiometricPrompt` requires
  it and because on API < 30 the device-credential key is authorised for only five seconds, so an extra
  dispatcher hop between the keyguard result and `initSign` could turn a successful ceremony into a
  `UserNotAuthenticatedException`.
- The device-credential activity is no longer exported and no longer launches an Intent supplied
  through its own extras.
- The device-credential activity declares its own AppCompat theme, so it no longer crashes hosts that
  use a non-AppCompat theme.
- `COSEAlgorithmIdentifier.ES256K` is `-47`, its value in the IANA COSE Algorithms registry, instead of
  `-43`, which that registry assigns to SHA-384. `fromValue(-47)` now resolves and `fromValue(-43)`
  returns `null`.
- `COSEAlgorithmIdentifier.ES512` generates over `secp521r1`, the JCA name for the P-521 curve it is
  defined on. The previous `secp512r1` names no curve, so generating an ES512 key through a
  `Fido2KeyGenerator` directly could only fail with `InvalidAlgorithmParameterException`. The
  `Authenticator` never selected ES512, so registration and authentication are unaffected.

### Added
- `PublicKeyCredential.checkAuthenticationAvailability()` reports whether authentication is possible
  and why not, so callers can gate their UI instead of handling `ConstraintException`.
- `WebAuthnException.CoreException.UserCancelledException` distinguishes a deliberate dismissal from a
  genuine failure. It is a subtype of `NotAllowedException`, so existing `catch` clauses still match.
- `WebAuthnException.KeyGenerationException` is a new exception type, a subtype of
  `SecureExecutionException`, reported when the platform keystore rejects an operation during credential
  creation.
- `NotAllowedException.errorCode`, `ConstraintException.canAuthenticateStatus`,
  `KeyGenerationException.keyStoreErrorCode` and `DeletionException.trigger` expose the diagnostic
  detail the SDK previously discarded or hid. The first three are read-only to Kotlin callers: only the
  SDK sets them, so the value always describes the failure the exception was raised for.
- `NotAllowedException` and `SecureExecutionException` are now `open`, which is what lets the new
  `UserCancelledException` and `KeyGenerationException` subclass them without adding a direct subclass to
  a sealed parent. No `when` over `WebAuthnException` stops being exhaustive.
- `PublicKeyCredential.deleteAccount(credId)` removes a single credential and its key material.

### Changed
- `create()`/`get()` now propagate `CancellationException` instead of returning `Result.failure`.
- `deleteAllAccounts()` now deletes hardware key material. This is irreversible.
- `getAllAccounts()` no longer returns duplicates, so the returned list is about a quarter of its
  previous size.
- Devices where StrongBox rejects key generation now produce TEE-backed keys.
- `UnknownException` messages name the throwable the SDK did not handle
  (`Unhandled <class>: <message>`) instead of `An unknown error occurred.`. The exception type and its
  `cause` are unchanged; do not match on the message text.
- `NotAllowedException` and `UserCancelledException` raised from the authentication path now carry
  `errorCode=<code>` in their messages (`Authentication error is occurred. errorCode=7`). The exception
  types and their `cause` are unchanged, and the code is also available as `NotAllowedException.errorCode`;
  as with `UnknownException`, do not match on the message text. This is the SDK's largest error cluster, so
  log aggregation keyed on the message will re-bucket these once.

### Upgrading from 1.1.3

Most of this release is internal, but eleven changes are visible to callers. Five need a code change,
and one of those four stops a source upgrade from compiling.

**Action required**

1. **`create()` and `get()` now throw `CancellationException`** instead of returning
   `Result.failure`. If you bridge these calls to a callback, RxJava, or `runBlocking` boundary, let
   `CancellationException` propagate rather than catching `Throwable`. Note that
   `result.onFailure { showError() }` no longer fires when the user leaves the screen mid-ceremony —
   previously it did, and reported a relying-party error.
2. **Catch `WebAuthnException.CoreException.UserCancelledException` before `NotAllowedException`** and
   do not report it as an error. A user dismissing the prompt is a normal outcome. Without this change
   you keep reporting cancellations as SDK failures; with it, that class of report disappears.
3. **`getAllAccounts()` returns roughly a quarter as many entries.** It previously returned every
   credential four times. Remove any de-duplication or count adjustment you added to compensate.

4. **`CredentialSourceStorage.delete(credId)` must honour its `credId` argument.** The interface has
   always documented it as deleting the credential named by that id, but 1.1.3 rarely reached it on a
   failure path: a cancelled coroutine threw before the deletion ran. 1.2.0 performs the terminal
   cleanup under `NonCancellable` so it now runs to completion, and it also reaches cleanup on paths
   that previously hung instead. If your implementation ignores `credId` and clears a single stored
   slot, a cancelled registration can now delete a *different*, still-valid credential — leaving the
   user unenrolled locally with an unnameable key stranded in the KeyStore. Check your implementation
   before upgrading.

5. **`KeyguardManagerWrapper.AuthenticationActivity.start` is no longer public.** This is the one API
   break in the release, and the only change here that stops a source upgrade from compiling. It was
   public and took a ready-made `Intent`; it is now `internal` and takes the prompt title and description
   instead, because the activity builds the confirm-device-credential `Intent` itself rather than
   launching one handed to it through its own extras. There is no replacement: call
   `KeyguardManagerWrapper.authenticate(context, fido2PromptInfo)`, which is what the SDK itself uses and
   which derives the title and description from your `Fido2PromptInfo`. Recompiling against 1.2.0 gives a
   compile error at the call site; dropping in the new AAR without recompiling gives a
   `NoSuchMethodError` at runtime, because an `internal` function's JVM name is mangled and it is now
   `start$webauthn_release`.

**Behaviour changes to review**

6. **`deleteAllAccounts()` destroys hardware-backed key material and cannot be undone.** It previously
   deleted only the database rows and left every private key in the AndroidKeyStore. Confirm your
   "sign out and wipe" flow expects the keys to be destroyed, and that it still deregisters the
   credential at the relying party. Use the new `deleteAccount(credId)` for a single credential.
7. **The biometric registration prompt no longer accepts Class 2 (Weak) authenticators.** Support
   detection already required Class 3 (Strong), so users should see no new friction, but on **Samsung
   devices running Android 9 (API 28)** the prompt switches from the framework dialog to the legacy
   fingerprint dialog, because androidx falls back for crypto-based prompts on that vendor. Those users
   already saw that dialog for authentication and for `android-key` registration, so this only makes
   `none` registration consistent with it. Re-test your registration flow there.
8. **Adopt `PublicKeyCredential.checkAuthenticationAvailability()`** before calling `create()`. It
   reports whether authentication is possible and why not, so you can show an actionable message
   instead of handling `ConstraintException` after the fact.
9. **On API 28/29 with `AuthenticationMethod.DeviceCredential`,
   `WebAuthnException.AuthenticationException.KeyPermanentlyInvalidatedException` now reaches you** on
   the authentication path, where it was previously flattened into a generic authentication error. Code
   that catches only `NotAllowedException` there will see a type it has not seen before, and should
   prompt the user to re-register rather than retry. Nothing is newly exhaustive: the exception already
   existed and already reached callers on API 30 and above, so no `when` over `WebAuthnException`
   breaks.
**Relying-party coordination**

10. **Devices where StrongBox rejects key generation now produce TEE-backed keys.** If your server
   gates on the attestation security level, it will see TEE for those devices.
11. **Both attestation formats change on the wire.** New registrations send a spec-conformant COSE
    credential public key — coordinates are exactly 32 bytes and the CBOR maps are definite-length — and
    for `android-key` the attestation statement's own nested map is definite-length too, so the
    attestation object's bytes differ from 1.1.3 for `none` and `android-key` alike. Credentials already
    registered are unaffected, because an assertion never carries the public key or an attestation
    statement.

    Three things change, and a server can break on any one of them independently:
    - EC2 coordinates are now exactly 32 bytes. Do not assume 33, and do not read them with a
      sign-aware integer constructor.
    - The CBOR maps are definite-length rather than indefinite-length.
    - **The top-level keys of the attestation object are reordered** from `authData, fmt, attStmt` to
      `fmt, attStmt, authData`, because the canonical encoder sorts them. A server that reads the
      top-level map by position rather than by key breaks on this alone, regardless of the other two.

    Verify against a real registration, not by reading the parser: any standards-compliant CBOR parser
    handles all three, but a hand-rolled or offset-based one may not.

**Not fixed by this release**

- **Keys already orphaned on users' devices are not recovered.** A pre-1.2.0 registration that failed
  after key generation left a private key in the AndroidKeyStore with no database row naming it; those
  keys are still there after upgrading. Recovering them would mean enumerating every AndroidKeyStore
  alias and deleting the ones absent from your `CredentialSourceStorage` — a destructive sweep over a
  keystore this SDK does not exclusively own, which could delete keys belonging to your app or to
  another library — so it is deliberately out of scope. The fixes above stop new orphans from being
  created; the existing ones are inert and occupy a keystore slot each.

## 1.1.3 (2025-09-16)

### Changed
- Remove Gson dependency and migrate to kotlinx.serialization for JSON handling
- Update biometric library version from alpha to stable (1.2.0-alpha05 → 1.1.0)

## 1.1.2 (2025-09-09)

### Changed
- Fix build issue from v1.1.1
 
## 1.1.1 (2025-09-08)

### Changed
- Remove unnecessary permissions (USE_FINGERPRINT) from the manifest file.
