## 🔐 VIP Access for Kotlin

[![GitHub Workflow Status][gha_badge]][gha_url]
[![Maven Central Version][maven_img]][maven_url]
[![Kotlin release][kt_img]][kt_url]
[![OpenJDK Version][java_img]][java_url]

Kotlin Multiplatform library for [Symantec VIP Access](https://vip.symantec.com/) TOTP tokens.

### Features

- 🌐 Kotlin Multiplatform — JVM, Native (Linux/macOS/Windows), JS, and Wasm/JS targets
- 🔑 Provision VIP Access credentials directly from Symantec
- ⏱️ Generate TOTP/HOTP codes ([RFC 6238](https://datatracker.ietf.org/doc/html/rfc6238),
  [RFC 4226](https://datatracker.ietf.org/doc/html/rfc4226))
- 🔗 Export to `otpauth://` URIs for any authenticator app
- ✅ Verify and re-sync tokens against the Symantec server

## 🚀 Quick Start

<details>
<summary><b>Kotlin Toolchain</b></summary>

```yaml
# module.yaml
dependencies:
  - dev.suresh.vipaccess:kotlin-vipaccess:0.1.0
```

</details>

<details>
<summary><b>Gradle Kotlin DSL</b></summary>

```kotlin
dependencies {
    implementation("dev.suresh.vipaccess:kotlin-vipaccess:0.1.0")
}
```

</details>

### Provision & Use a Token

```kotlin
val client = VipAccess(clientId = "kotlin-vipaccess")

// Provision a new credential
val token = client.provision()
println("ID: ${token.id}")

// Generate the current OTP
val otp = client.generateTotp(token)
println("OTP: $otp")

// Verify and sync with Symantec
when (client.verifyToken(token)) {
    is Success -> println("✓ Valid")
    is NeedsSync -> client.syncToken(token)
    is Failed -> println("✗ Invalid")
}

// Export for any authenticator app
println("URI: ${client.otpUri(token)}")
```

### Authenticator Setup

Get the OTP URI and add it to your authenticator of choice:

- [Google Authenticator](https://github.com/google/google-authenticator-android) — generate a QR from the URI or
  manually enter the secret
- [Authenticator Extension](https://github.com/Authenticator-Extension/Authenticator) (Chrome) — paste the full
  `otpauth://` URI

## 🎯 Supported Targets

| Target              | Status |
|---------------------|--------|
| JVM                 | ✅     |
| Linux (x64 / arm64) | ✅     |
| macOS (arm64)       | ✅     |
| Windows (mingwX64)  | ✅     |
| JS                  | ✅     |
| Wasm/JS             | ✅     |

## 🔧 Build & Test

```bash
$ ./kotlin build                # Build all targets
$ ./kotlin test                 # Run tests
$ ./kotlin publish mavenLocal   # Publish to local Maven repository
```

## 📦 Release

Push a version tag to publish to Maven Central and create a GitHub release:

```bash
$ git tag -am "Release v1.0.0" v1.0.0
$ git push origin --tags
```

The [build workflow](.github/workflows/build.yaml) handles signing and publishing automatically.

## Credits

Based on the reverse engineering of the VIP Access provisioning protocol
by [Cyrozap](https://www.cyrozap.com/2014/09/29/reversing-the-symantec-vip-access-provisioning-protocol/).

## License

Apache 2.0 — see [LICENSE](LICENSE) for details.

<!-- Badges -->

[gha_url]: https://github.com/sureshg/kotlin-vipaccess/actions/workflows/build.yaml

[gha_badge]: https://img.shields.io/github/actions/workflow/status/sureshg/kotlin-vipaccess/build.yaml?branch=main&style=flat&logo=kotlin&logoColor=3BEA62&label=Kotlin%20Build

[java_url]: https://www.azul.com/downloads/?version=java-25-lts&package=jdk#zulu

[java_img]: https://img.shields.io/badge/OpenJDK-26-e76f00?logo=openjdk&logoColor=e76f00

[kt_url]: https://github.com/JetBrains/kotlin/releases/latest

[kt_img]: https://img.shields.io/github/v/release/Jetbrains/kotlin?include_prereleases&color=7f53ff&label=Kotlin&logo=kotlin&logoColor=7f53ff

[maven_url]: https://central.sonatype.com/artifact/dev.suresh.vipaccess/kotlin-vipaccess

[maven_img]: https://img.shields.io/maven-central/v/dev.suresh.vipaccess/kotlin-vipaccess?logo=apachemaven&logoColor=C71A36&color=C71A36&label=Maven%20Central
