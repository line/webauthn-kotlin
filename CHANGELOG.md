# Change Log

## 1.2.0 (2026-09-02)

Registration and authentication responses are byte-for-byte identical to 1.1.3, so credentials already
registered keep working and no relying-party change is required. Eight changes are visible to callers;
see [UPGRADING.md](UPGRADING.md) for the migration steps.

### Added
- `PublicKeyCredential.checkAuthenticationAvailability()` reports whether authentication is possible on
  the device and why not, so callers can gate their UI instead of handling an exception. It does not
  throw.
- `PublicKeyCredential.deleteAccount(credId)` removes a single credential together with its key
  material.
- `WebAuthnException.CoreException.UserCancelledException` distinguishes a deliberate dismissal of the
  prompt from a genuine failure. It is a subtype of `NotAllowedException`, so existing `catch` clauses
  still match.
- `WebAuthnException.KeyGenerationException` reports a platform keystore rejection during credential
  creation. It is a subtype of `SecureExecutionException`.
- `NotAllowedException.errorCode`, `ConstraintException.canAuthenticateStatus`,
  `KeyGenerationException.keyStoreErrorCode` and `DeletionException.trigger` expose diagnostic detail
  that was previously unavailable to callers. All four are read-only: only the SDK sets them, so the
  value always describes the failure the exception was raised for.
- `NotAllowedException` and `SecureExecutionException` are `open`, which is what lets
  `UserCancelledException` and `KeyGenerationException` extend them without adding a direct subclass to
  a sealed parent. No `when` over `WebAuthnException` stops being exhaustive.

### Fixed
- `cleanup()` used a re-encoded credential id as the keystore alias, so it deleted an alias no key had
  been stored under. `KeyStore.deleteEntry` reports a missing alias as success, so cleanup appeared to
  succeed while the private key remained on the device: every failed or abandoned registration left an
  orphaned hardware-backed key that nothing could name afterwards.
- Cleanup could be interrupted between removing the key and removing the database row, leaving a
  credential that is still listed by `getAllAccounts()` but can never authenticate. Both deletions now
  run to completion.
- `deleteAllAccounts()` deleted database rows and left every private key in the keystore. It also
  stopped at the first failure and replaced the cause with a generic storage error.
- `getAllAccounts()` returned every credential four times.
- Key generation that requested StrongBox was only retried on the TEE for
  `StrongBoxUnavailableException`. Vendor keystores reject with a plain `ProviderException`, so the
  retry never ran and registration failed outright. Both are now retried once without StrongBox. Key
  generation that did not request StrongBox is unchanged: it is still attempted once.
- A keystore rejection during credential creation was reported as `UnknownException` with no error
  code, because key generation calls `KeyPairGenerator` directly. It is now `KeyGenerationException`
  and carries the KeyMint numeric code where the platform exposes it. A rejection during
  authentication is classified the same way.
- Registration on an unsupported device raised `ConstraintException` with no indication of the cause.
  It now carries the `canAuthenticate()` status, and its message names the status, the authenticator
  type, the device model and the API level.
- A pre-flight registration failure - an already-registered credential, an unsupported algorithm, or
  unavailable authentication - was replaced by `DeletionException` when the follow-up cleanup failed
  over state it had never created. Cleanup still runs; only the reported exception changes.
- `DeletionException` discarded the `trigger` it was constructed with. It is now retained as a property
  and attached as a suppressed exception.
- The biometric registration prompt accepted a Class 2 (Weak) authenticator. Support detection requires
  Class 3 (Strong), the generated key is bound to Class 3, and the assertion claims user verification,
  so the prompt is now pinned to Class 3 as well.
- `COSEAlgorithmIdentifier.ES256K` is `-47`, its value in the IANA COSE Algorithms registry, instead of
  `-43`, which that registry assigns to SHA-384. `COSEAlgorithmIdentifier.ES512` generates over
  `secp521r1`; `secp512r1` names no curve. Neither algorithm is reachable from registration or
  authentication, which advertise ES256 only.

### Security
- The device-credential activity is no longer exported, and it builds its confirm-device-credential
  Intent itself instead of launching one supplied through its own extras. An exported component must not
  run an Intent it did not create, and this activity runs one under the host app's identity while its
  result establishes user verification for a WebAuthn ceremony. An instrumented test asserts
  `exported=false` on the merged manifest, which lint does not check.
- The activity's confirmation result was routed through a static field that was never cleared, so a
  result could reach a request other than the one the user confirmed, and a displaced request could
  wait indefinitely. Each request now receives its result exactly once, and a displaced request fails
  immediately.
- `KeyguardManagerWrapper.AuthenticationActivity.start` is `internal`. It was public and accepted a
  ready-made `Intent`, which is how the behaviour above was reachable from outside the SDK. Call
  `KeyguardManagerWrapper.authenticate(context, fido2PromptInfo)` instead.

### Changed
- `deleteAllAccounts()` deletes hardware-backed key material. This cannot be undone.
- `getAllAccounts()` no longer returns duplicates, so the returned list is about a quarter of its
  previous size.
- Devices where StrongBox rejects key generation produce TEE-backed keys, which changes the attestation
  security level reported for them.
- Exception messages carry diagnostic detail that was not there before: `ConstraintException` names the
  `canAuthenticate()` status and the device, and `NotAllowedException` and `UserCancelledException`
  carry `errorCode=<code>`. Exception types and their `cause` are unchanged. Message text is not a
  contract, so do not match on it; log aggregation keyed on these messages will re-bucket them once.
- The device-credential activity declares its own AppCompat theme. It extends `AppCompatActivity`, so a
  host application theme that is not an AppCompat descendant caused the host process to crash.
- `androidx.biometric` is exposed as an `api` dependency. The SDK's public error surface is expressed in
  `BiometricPrompt.ERROR_*` and `BiometricManager.BIOMETRIC_*` values, which callers need these types to
  interpret.
- The published artifact no longer writes to logcat.

### Not fixed in this release
- **Keys already orphaned on a device are not recovered.** A pre-1.2.0 registration that failed after
  key generation left a private key in the keystore with no database row naming it, and those keys are
  still present after upgrading. Recovering them would mean enumerating every keystore alias and
  deleting the ones absent from the caller's `CredentialSourceStorage`, a destructive sweep over a
  keystore this SDK does not exclusively own, so it is out of scope. The fixes above stop new orphans
  from being created; existing ones are inert.
- **The authentication prompt can hang when the host activity has already saved its instance state.**
  `androidx.biometric` returns from `authenticate()` without invoking any callback in that case, leaving
  the operation suspended and blocking later `create()` and `get()` calls. Do not start a ceremony from
  a screen that is being backgrounded.

## 1.1.3 (2025-09-16)

### Changed
- Remove Gson dependency and migrate to kotlinx.serialization for JSON handling
- Update biometric library version from alpha to stable (1.2.0-alpha05 to 1.1.0)

## 1.1.2 (2025-09-09)

### Changed
- Fix build issue from v1.1.1

## 1.1.1 (2025-09-08)

### Changed
- Remove unnecessary permissions (USE_FINGERPRINT) from the manifest file.
