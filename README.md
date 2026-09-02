# WebAuthn Kotlin

WebAuthn Kotlin is an open source toolkit for secure, password-less authentication in mobile apps. Developed in Kotlin, it integrates seamlessly with native Android apps and adheres to WebAuthn 2.0 standards, boosting security and user experience.

Designed to align with modern Android development, the SDK offers easy integration and customization. It equips developers with tools for advanced authentication, such as device credentials and biometrics, simplifying logins and enhancing security.

Release notes are in [CHANGELOG.md](CHANGELOG.md). If you are moving from an earlier version, start with
[UPGRADING.md](UPGRADING.md), which lists only the changes that require action from your application.


## Components

### PublicKeyCredential
The `PublicKeyCredential` serves as the client within the authentication framework, interacting with the authenticator to carry out the authentication process and communicating with the relying party. It supports two primary operations for secure, password-less authentication:

- **create()**: Starts the process of generating new asymmetric key credentials via an authenticator.
- **get()**: Prompts the user to authenticate with a relying party using their existing credentials.

The `PublicKeyCredential` class is now designed for flexible use, allowing users to specify their desired authentication and attestation configurations directly.

To use `PublicKeyCredential`, you need to provide the following parameters when initializing the class:

- **authenticationMethod**: Define the method of authentication to use specific authenticator, such as biometric or device credential authenticator.
- **attestationStatement**: Specify the format for the attestation statement.
  This setup allows you to customize the credential management process according to your specific security requirements.


### RelyingParty

The `RelyingParty` establishes communication with your server to manage access to secure applications. In FIDO2, it generates and handles authentication requests, verifies responses from authenticators, and maintains user credentials, ensuring secure, password-less interactions between the client and server.
Library users must implement the `RelyingParty` interface themselves.

### CredentialSourceStorage
The `CredentialSourceStorage` is an interface that defines the behavior of a database for handling a public key credential source and its signature counter.

## Requirements

### Runtime Requirements
- **Android**: API level 28 (Android 9.0 Pie) or higher
- **Target SDK**: 35 (Android 15)

### Development Requirements  
- **Java**: 21 (for building)
- **Kotlin**: 2.2.10
- **Android Gradle Plugin**: 8.12.1
- **Gradle**: 9.0.0

### Build System
- **Compile SDK**: 35
- **Min SDK**: 28
- **Target SDK**: 35
- **Java Compatibility**: 11 (bytecode target)

**Note**: The library is built with Java 21 for optimal performance but generates Java 11-compatible bytecode for maximum Android compatibility.


## Usage


### Step 1: Implement the `RelyingParty` Interface

First, you need to create an implementation of the `RelyingParty` interface. This interface is crucial for handling communication with your server's FIDO2-compatible endpoints.

To help you get started with your implementation, we recommend checking out a sample application available on GitHub:

* [webauthndemo-kotlin/RelyingParty](https://github.com/line/webauthndemo-kotlin/blob/main/app/src/main/java/jp/co/lycorp/webauthn/sample/network/Fido2RelyingPartyImpl.kt)

This sample provides a practical example of how to implement the `RelyingParty` interface in a real-world Android application. It will give you insights into integrating FIDO2 functionalities effectively with your server setup.

### Step 2: Implement the `CredentialSourceStorage` Interface

Next, you need to create an implementation of the `CredentialSourceStorage ` interface to manage credential source and signature counter.

To help you get started with your implementation, we recommend checking out a sample application available on GitHub:

* [webauthndemo-kotlin/CredentialSourceStorage](https://github.com/line/webauthndemo-kotlin/blob/main/app/src/main/java/jp/co/lycorp/webauthn/sample/data/database/RoomCredentialSourceStorage.kt)

### Step 3: Initialize `PublicKeyCredential`
Once you have your relying party and credential storage implementation ready, you can initialize the public key credential.


```kotlin
val rp = YourRelyingParty()
val db = YourCredentialSourceStorage()

// You can use a biometric authenticator.
val publicKeyCredential = PublicKeyCredential(
    rpClient = rp,
    db = db,
    authenticationMethod = AuthenticationMethod.Biometric,
    attestationStatement = AttestationStatementFormat.NONE,
)

// ,or you can use a device credential.
val publicKeyCredential = DeviceCredential(
    rpClient = rp,
    db = db,
    authenticationMethod = AuthenticationMethod.DeviceCredential,
    attestationStatement = AttestationStatementFormat.NONE,
)

// You can use attestation using AttestationStatementFormat.ANDROID_KEY.
val publicKeyCredential = DeviceCredential(
    rpClient = rp,
    db = db,
    authenticationMethod = AuthenticationMethod.Biometric,
    attestationStatement = AttestationStatementFormat.ANDROID_KEY,
)
```

Here, activity refers to the instance of your current Activity from which you are initiating the authentication process. This allows the `PublicKeyCredential` to interact with the user interface for authentication.

### Step 4: Check Whether the Device Can Authenticate

Before offering registration, check that the device can perform the authentication method you
configured. `checkAuthenticationAvailability` is a static function, it does not require a
`PublicKeyCredential` instance, and it never throws:

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

Calling `create` on a device that cannot authenticate fails with
`WebAuthnException.CoreException.ConstraintException`, which is an expected device state rather than an
error worth reporting. Gating on the result above avoids it.

This reports whether the user can authenticate at all. It does not report whether an already registered
credential is still usable: re-enrolling a biometric invalidates the credential's key while leaving the
result available, so `get` can still fail with
`WebAuthnException.AuthenticationException.KeyPermanentlyInvalidatedException`.

### Step 5: Register and Authenticate Credentials
Before using the `create` and `get` methods of `publicKeyCredential`, configure `options` and `fido2PromptInfo` according to your needs. These configurations will be used for both registration and authentication processes.

When you call the `create` method to register a new credential, or the `get` method to authenticate using an existing credential, the methods will return a `Result<Unit>` type:


#### Registering a Credential
Register a new credential using the `create` method:

```kotlin
val result: Result<Unit> = publicKeyCredential.create(
    activity = activity,
    options = registrationOptions,
    fido2PromptInfo = fido2PromptInfo,
)
```

#### Authenticating with a Credential
Authenticate using an existing credential with the `get` method:

```kotlin
val result: Result<Unit> = publicKeyCredential.get(
    activity = activity,
    options = authenticationOptions,
    fido2PromptInfo = fido2PromptInfo,
)
```

### Step 6: Manage Registered Credentials

`PublicKeyCredential` exposes three suspending functions for the credentials stored on the device. Each
returns or removes entries from the `CredentialSourceStorage` you supplied, and the two deletions also
remove the corresponding hardware-backed private key:

```kotlin
val credentials: List<PublicKeyCredentialSource> = publicKeyCredential.getAllAccounts()

publicKeyCredential.deleteAccount(credId)

publicKeyCredential.deleteAllAccounts()
```

Deleting key material cannot be undone, and a credential that is still registered at the relying party
has to be deregistered there separately. Do not call either deletion while a `create` or `get` ceremony
is in flight: the account functions deliberately stay outside the lock those two hold, so a concurrent
call can destroy a key that is in use.

If a key deletion fails, the database row is kept, because that row is the only record of the keystore
alias. The credential therefore remains listed and the deletion can be retried.

## Error Handling

Both `create` and `get` return `Result`, and every failure they report is a
[`WebAuthnException`](webauthn/src/main/java/com/linecorp/webauthn/exceptions/WebAuthnException.kt). The
types most callers branch on:

| Exception | Meaning |
| --- | --- |
| `CoreException.UserCancelledException` | The user dismissed the prompt. A normal outcome, not a failure to report. A subtype of `NotAllowedException`, so catch it first. |
| `CoreException.NotAllowedException` | Authentication failed or was refused. `errorCode` carries the `BiometricPrompt.ERROR_*` code. |
| `CoreException.ConstraintException` | The device cannot authenticate. `canAuthenticateStatus` carries the `BiometricManager.canAuthenticate()` status. Gate on `checkAuthenticationAvailability` to avoid it. |
| `CoreException.InvalidStateException` | The credential is already registered. |
| `AuthenticationException.KeyPermanentlyInvalidatedException` | The credential's key was invalidated, typically by a biometric re-enrolment. Prompt the user to register again. |
| `KeyGenerationException` | The platform keystore rejected an operation during registration. `keyStoreErrorCode` carries the KeyMint code on API 33 and above. A subtype of `SecureExecutionException`. |
| `KeyNotFoundException` | No key was found for the credential being used. |
| `RpException` | Your `RelyingParty` implementation reported an error. The original is available as `cause`. |
| `CredSrcStorageException` | Your `CredentialSourceStorage` implementation reported an error. |
| `DeletionException` | Cleanup after a failed registration could not complete. `trigger` carries the failure that started it. |

Exception messages carry diagnostic detail intended for logs and are not a stable contract. Branch on
the type and the properties above rather than on message text.

## Build Instructions

### Prerequisites
- Java 21 installed and configured as JAVA_HOME
- Android SDK with API level 35

### Building the Library
```bash
# Clone the repository
git clone https://github.com/line/webauthn-kotlin.git
cd webauthn-kotlin

# Build the library
./gradlew build

# Publish to local Maven repository
./gradlew publishToMavenLocal
```

### IDE Setup
For Android Studio users:
1. **Gradle JVM**: Set to Java 21 in Preferences > Build, Execution, Deployment > Build Tools > Gradle
2. **Project Structure**: Use Project SDK Android API 35, Language Level 11

## License
Apache License 2.0. See [`LICENSE`](./LICENSE).


## Contact Information

We are dedicated to making our work open-source to assist with your specific needs. We are eager to learn how this library is being utilized and the issues it resolves for you. To communicate, we recommend the following approach:

*   For reporting bugs, proposing improvements, or asking questions about the library, please utilize the [**Issues**](https://github.com/line/webauthn-kotlin/issues) section of our GitHub repository. Your feedback is invaluable in helping us address your concerns more effectively and enhances the community's experience.

Please avoid sharing any sensitive or confidential information in the issues. If there is a need to discuss sensitive matters, please indicate so in your issue, and we will arrange a more secure communication method.
