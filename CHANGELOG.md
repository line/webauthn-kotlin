# Change Log

## 1.1.4 (2026-09-03)

A security release covering the device-credential activity, with two algorithm constants corrected
alongside it, so it can be taken without the other changes queued for 1.2.0. Registration and
authentication responses are unchanged, so credentials already registered keep working and no
relying-party change is required. One change requires action from applications; see the last entry under
Security.

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
