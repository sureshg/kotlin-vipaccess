import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.algorithms.HMAC
import dev.whyoleg.cryptography.algorithms.SHA1
import kotlinx.io.Buffer
import kotlinx.io.readByteArray
import kotlin.io.encoding.Base64
import kotlin.time.Clock

/**
 * Generate HOTP code (RFC 4226)
 * Based on https://github.com/BastiaanJansen/otp-java
 */
private suspend fun generateHotp(
    secret: ByteArray,
    counter: Long,
    digits: Int
): String {
    // HMAC-SHA1
    val hmac = CryptographyProvider.Default
        .get(HMAC)
        .keyDecoder(SHA1)
        .decodeFromByteArray(RAW, secret)

    // Counter as 8-byte big-endian using kotlinx-io
    val buffer = Buffer()
    buffer.writeLong(counter)
    val counterBytes = buffer.readByteArray()

    val hash = hmac.signatureGenerator().generateSignature(counterBytes)

    // Dynamic truncation (RFC 4226 Section 5.3)
    val offset = hash.last().toInt() and 0x0F
    val truncated = ((hash[offset].toInt() and 0x7F) shl 24) or
            ((hash[offset + 1].toInt() and 0xFF) shl 16) or
            ((hash[offset + 2].toInt() and 0xFF) shl 8) or
            (hash[offset + 3].toInt() and 0xFF)

    val divisor = when (digits) {
        6 -> 1_000_000
        7 -> 10_000_000
        8 -> 100_000_000
        else -> error("Unsupported digits: $digits")
    }

    return (truncated % divisor).toString().padStart(digits, '0')
}

suspend fun generateTotp(
    token: Token,
    timestamp: Long = Clock.System.now().epochSeconds
): String {
    val counter = timestamp / token.period
    return generateHotp(Base64.decode(token.base64Secret), counter, token.digits)
}