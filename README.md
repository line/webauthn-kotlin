# WebAuthn Kotlin

WebAuthn Kotlin is an open source toolkit for secure, password-less authentication in mobile apps. Developed in Kotlin, it integrates seamlessly with native Android apps and adheres to WebAuthn 2.0 standards, boosting security and user experience.

Designed to align with modern Android development, the SDK offers easy integration and customization. It equips developers with tools for advanced authentication, such as device credentials and biometrics, simplifying logins and enhancing security.


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

* [webauthndemo-kotlin/RelyingParty](https://github.com/line/webauthndemo-kotlin/blob/main/app/src/main/java/com/linecorp/webauthn/sample/network/Fido2RelyingPartyImpl.kt)

This sample provides a practical example of how to implement the `RelyingParty` interface in a real-world Android application. It will give you insights into integrating FIDO2 functionalities effectively with your server setup.

### Step 2: Implement the `CredentialSourceStorage` Interface

Next, you need to create an implementation of the `CredentialSourceStorage ` interface to manage credential source and signature counter.

To help you get started with your implementation, we recommend checking out a sample application available on GitHub:

* [webauthndemo-kotlin/CredentialSourceStorage](https://github.com/line/webauthndemo-kotlin/blob/main/app/src/main/java/com/linecorp/webauthn/sample/data/database/RoomCredentialSourceStorage.kt)

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

### Step 4: Register and Authenticate Credentials
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
1. **Gradle JVM**: Set to Java 21 in Preferences → Build, Execution, Deployment → Build Tools → Gradle
2. **Project Structure**: Use Project SDK Android API 35, Language Level 11

## License
Apache License 2.0. See [`LICENSE`](./LICENSE).


## Contact Information

We are dedicated to making our work open-source to assist with your specific needs. We are eager to learn how this library is being utilized and the issues it resolves for you. To communicate, we recommend the following approach:

*   For reporting bugs, proposing improvements, or asking questions about the library, please utilize the [**Issues**](https://github.com/line/webauthn-kotlin/issues) section of our GitHub repository. Your feedback is invaluable in helping us address your concerns more effectively and enhances the community's experience.

Please avoid sharing any sensitive or confidential information in the issues. If there is a need to discuss sensitive matters, please indicate so in your issue, and we will arrange a more secure communication method.
