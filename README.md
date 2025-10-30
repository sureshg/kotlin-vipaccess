## 🔐 VIP Access for Kotlin

Kotlin Multiplatform library for [Symantec VIP Access](https://vip.symantec.com/) TOTP tokens.

### Features

- ✅ Kotlin Multiplatform - supports all targets (JVM, Native, JS, Wasm)
- 🔑 Provision VIP Access credentials
- ⏱️ Generate TOTP/HOTP codes (RFC 6238, RFC 4226)
- 🔗 Export to `otpauth://` URIs for authenticator apps
- ✓ Verify and sync tokens with Symantec

### Quick Start

```kotlin
val client = VipAccess(clientId = "kotlin-vipaccess")

// Provision new credential
val token = client.provision()
println("ID: ${token.id}")

// Generate OTP
val otp = client.generateTotp(token)
println("OTP: $otp")

// Verify with Symantec
when (client.verifyToken(token)) {
    is Success -> println("✓ Valid")
    is NeedsSync -> client.syncToken(token)
    is Failed -> println("✗ Invalid")
}

// Export for authenticator apps
println("URI: ${client.otpUri(token)}")
```

### Build

```bash
$ git clone https://github.com/sureshg/kotlin-vipaccess
$ cd kotlin-vipaccess
$ ./amper build
```

### Authenticator Setup

Get the OTP URI and add to your authenticator:

```kotlin
val uri = client.otpUri(token)
```

- [Google Authenticator](https://github.com/google/google-authenticator-android) - Generate QR from URI or manually
  enter the secret
- [Authenticator Extension](https://github.com/Authenticator-Extension/Authenticator) (Chrome) - Paste the full
  `otpauth://` URI

### Credits

This work is based on the amazing reverse engineering of the VIP Access provisioning protocol
by [Cyrozap](https://www.cyrozap.com/2014/09/29/reversing-the-symantec-vip-access-provisioning-protocol/).

### License

Apache 2.0