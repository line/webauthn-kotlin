# Change Log

## 1.2.0 (2026-07-07)

### Fixed
- Fix `cleanup()` deleting a re-encoded KeyStore alias: failed or rolled-back
  registrations left the hardware-backed private key orphaned on the device.
- Fall back to TEE key generation when a vendor StrongBox implementation rejects
  the request with a plain `ProviderException` (e.g. KeyMint `UNIMPLEMENTED`)
  instead of `StrongBoxUnavailableException`.
- Encode COSE EC2 public key coordinates as fixed-length 32-byte values
  (previously `BigInteger.toByteArray()` produced 33- or <32-byte coordinates,
  rejected by strict WebAuthn servers). Applies to new registrations only.
- Emit definite-length CBOR maps for `attestationObject` and
  `credentialPublicKey` (CTAP2 canonical form), replacing indefinite-length maps.
- `getAllAccounts()` no longer returns each credential four times.
- `deleteAllAccounts()` now deletes the KeyStore private keys together with the
  DB rows.
- Validate `user.id` as 1..64 decoded bytes per the WebAuthn spec instead of
  string characters.
- Match `allowCredentials` descriptors by type as well as rpId.
- Fix ES512 curve name (`secp521r1`).
- Run KeyStore access, key generation, and attestation/assertion creation off
  the caller's dispatcher (ANR prevention); `BiometricPrompt` stays on Main.
- Propagate `CancellationException` instead of wrapping it, make rollback
  cleanup `NonCancellable`, and skip cleanup for pre-flight failures.
- Add lifecycle (RESUMED) guards and continuation safety to all authentication
  paths, including the API<30 KeyguardManager flow.
- Pin the biometric prompt to `BIOMETRIC_STRONG` via `setAllowedAuthenticators`.
- Collect a user authorization gesture before surfacing an excludeCredentials
  match (WebAuthn L2 6.3.2 step 3), preventing silent credential probing.

### Added
- `PublicKeyCredential.canAuthenticate(context)`: pre-flight capability check
  returning the raw `BiometricManager` status code.
- `NotAllowedException.errorCode` / `isUserCancellation`: the BiometricPrompt
  error code, so user cancellations can be separated from genuine failures
  without matching localized messages.
- `ConstraintException.capabilityStatus`: the raw `canAuthenticate()` status
  explaining why the device is unsupported.
- `DeletionException.trigger`: the original failure that caused the rollback.
- `UserVerificationRequirement.DISCOURAGED`.

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
