# Change Log

## 1.1.6 (2026-10-28)

### Fixed

- R8 builds failed when the application's compile SDK no longer provided the legacy
  `FingerprintManager` classes referenced by the Android 9 and 10 compatibility paths. The AAR now
  includes consumer rules suppressing missing-class diagnostics for those four platform types.

## 1.1.5 (2026-10-16)

A fix release for biometric authentication on Android 9 and 10, for the encoding of the credential
public key, and for keys left in AndroidKeyStore, with one dependency removed. Authentication responses
are unchanged, and credentials already registered keep working. A registration response differs only
where a public key coordinate was encoded at a length other than 32 bytes, and a relying party that
accepted those also accepts the fixed-length form, so no relying-party change is required. The
androidx.biometric dependency stays at 1.1.0, and biometric authentication on Android 11 and later takes
the same code path as in 1.1.4.

### Fixed
- Biometric registration and authentication threw `ConstraintException` on Android 9 and 10 with a
  fingerprint enrolled, when the application resolves androidx.core 1.18.0 or later. That release made
  `androidx.core.hardware.fingerprint.FingerprintManagerCompat` a no-op that reports no fingerprint
  hardware, and on API 28 and 29 androidx.biometric 1.1.0 answers `canAuthenticate(BIOMETRIC_STRONG)`
  through it, with `BIOMETRIC_STATUS_UNKNOWN`. On those API levels the SDK also accepts a fingerprint
  enrolled with the platform `FingerprintManager`.
- With the same androidx.core, crypto-based biometric prompts on Samsung devices running Android 9 failed
  with `BiometricPrompt.ERROR_HW_NOT_PRESENT` before anything was shown, because androidx.biometric 1.1.0
  runs them through `FingerprintManagerCompat` on those devices. This is every `get`, and a `create` with
  `AttestationStatementFormat.ANDROID_KEY`. On the devices androidx.biometric selects for this, the SDK
  authorises signing through the platform `FingerprintManager` with a dialog of its own. The dialog takes
  its texts from `Fido2PromptInfo` and reports errors with the `BiometricPrompt.ERROR_*` codes, including
  `ERROR_NEGATIVE_BUTTON` for its negative button, `ERROR_USER_CANCELED` for back, and `ERROR_CANCELED`
  when the activity leaves the foreground. As in androidx.biometric, no dialog is drawn on the models
  whose system overlay covers it, such as the Galaxy S10 and Note10 series.
- The P-256 coordinates of the credential public key in a registration response were taken from
  `BigInteger.toByteArray`, which gives 33 bytes when the top bit is set and fewer than 32 when the value
  has leading zero bytes, so about three keys in four had a coordinate that was not 32 bytes. COSE fixes
  them at 32 bytes, and relying parties that check this, such as Fido2NetLib, rejected the registration.
  `EC2COSEKey` stores P-256 coordinates as 32-byte unsigned big-endian values, and throws
  `WebAuthnException.EncodingException` for a coordinate with more significant bytes than that. (#15)
- A registration that failed after its key was generated, such as one the user cancelled at the prompt,
  or that the relying party rejected, left the private key in AndroidKeyStore: the cleanup deleted an
  alias derived from the credential ID instead of the credential ID itself, which is the key's alias.
  `PublicKeyCredential.deleteAllAccounts` removed only the storage rows. Both delete the key together with
  its row, and `deleteAllAccounts` reports a key it cannot delete with
  `WebAuthnException.SecureExecutionException`. Keys left by earlier versions remain until the
  application's data is cleared.

### Changed
- The SDK does not depend on androidx.room, which it does not use, so Room and androidx.sqlite no longer
  reach the runtime classpath of an application through this library. An application that declares an
  earlier Room version than 2.6.1 now resolves the version it declares. (#11)

## 1.1.4 (2026-09-03)

A security release covering the device-credential activity, with two algorithm constants corrected
alongside it. Registration and authentication responses are unchanged, so credentials already registered
keep working and no relying-party change is required. One change requires action from applications; see
the last entry under Security.

### Security
- The device-credential activity is no longer exported, and it builds its confirm-device-credential
  Intent itself instead of launching one supplied through its own extras. An exported component must not
  run an Intent it did not create, and this activity runs one under the host app's identity while its
  result establishes user verification for a WebAuthn ceremony. An instrumented test asserts
  `exported=false` on the merged manifest, which lint does not check.
- The activity's confirmation result was routed through a static field that was never cleared, so a
  result could be delivered twice or hold a cancelled request's continuation for the process lifetime.
  The result is now consumed exactly once, and a cancelled request releases the field.
  `KeyguardManagerWrapper.authenticate` handles one request at a time, which `create` and `get`
  guarantee by serialising on a shared lock.
- `KeyguardManagerWrapper` is `internal`, matching the other authentication handlers. It was public,
  and its nested `AuthenticationActivity.start` accepted a ready-made `Intent`, which is how the
  behaviour above was reachable from outside the SDK. Device-credential authentication goes through
  `PublicKeyCredential.create` and `get` with `AuthenticationMethod.DeviceCredential`; availability
  can be read from `KeyguardManager.isDeviceSecure` or `BiometricManager.canAuthenticate`, which is
  all `isSupported` did. Recompiling against 1.1.4 gives a compile error at a direct reference.

### Fixed
- The device-credential activity extended `AppCompatActivity` while declaring no theme of its own, so
  it inherited the host application theme. `AppCompatDelegate` inflates a sub-decor regardless of
  whether `setContentView` is called and rejects a theme without the AppCompat attributes, which took
  the host process down. It is a plain `Activity`, which draws nothing and imposes no theme requirement,
  and the library ships no resources at all.
- A configuration change during device-credential authentication recreated the activity and showed the
  user a second prompt for one request. A recreated activity no longer relaunches the prompt, and it
  finishes rather than leaving a window with no ceremony behind it.
- A coroutine cancelled before it suspended still launched the credential prompt, whose result nothing
  could consume.
- `COSEAlgorithmIdentifier.ES256K` is `-47`, its value in the IANA COSE Algorithms registry, instead of
  `-43`, which that registry assigns to SHA-384. `COSEAlgorithmIdentifier.ES512` generates over
  `secp521r1`; `secp512r1` names no curve. Neither is reachable from a credential ceremony, because the
  authenticator advertises ES256 only, so no behaviour changes.

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
