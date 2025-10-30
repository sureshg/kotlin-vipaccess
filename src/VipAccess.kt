import TokenResult.*
import com.osmerion.kotlin.io.encoding.Base32
import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import io.github.oshai.kotlinlogging.KotlinLogging
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.plugins.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.plugins.logging.*
import io.ktor.client.plugins.logging.LogLevel.*
import io.ktor.client.plugins.logging.LoggingFormat.*
import io.ktor.client.request.*
import io.ktor.client.request.forms.submitForm
import io.ktor.client.statement.bodyAsText
import io.ktor.http.*
import io.ktor.serialization.kotlinx.xml.*
import io.ktor.util.*
import kotlin.io.encoding.Base64
import kotlin.math.pow
import kotlin.time.Clock
import kotlin.time.Duration.Companion.seconds
import kotlinx.io.Buffer
import kotlinx.io.readByteArray
import nl.adaptivity.xmlutil.XmlDeclMode
import nl.adaptivity.xmlutil.serialization.XML

class VipAccess(val clientId: String = "kotlin-vipaccess") : AutoCloseable {

  private val log = KotlinLogging.logger {}

  private val hmac = CryptographyProvider.Default.get(HMAC)

  private val aes = CryptographyProvider.Default.get(AES.CBC)

  private val HMAC_KEY =
      "dd0ba692c38aa3a993a3aa26968cd9c2aa2aa2cb23b7c2d2aaaf8f8fc9a0a9a1".hexToByteArray()

  private val AES_KEY = "01ad9bc682a3aa93a9a3239a86d6ccd9".hexToByteArray()

  private val xml = XML {
    indent = 2
    autoPolymorphic = true
    xmlDeclMode = XmlDeclMode.Auto
    recommended {
      ignoreNamespaces()
      ignoreUnknownChildren()
    }
  }

  private val client = HttpClient {
    install(ContentNegotiation) { xml(xml) }
    install(HttpRequestRetry) {
      maxRetries = 2
      retryOnException(retryOnTimeout = true)
      retryOnServerErrors()
      exponentialDelay(maxDelayMs = 10.seconds.inWholeMilliseconds)
    }

    install(HttpTimeout) {
      connectTimeoutMillis = 5.seconds.inWholeMilliseconds
      requestTimeoutMillis = 5.seconds.inWholeMilliseconds
      socketTimeoutMillis = 5.seconds.inWholeMilliseconds
    }

    install(Logging) {
      level =
          when {
            log.isDebugEnabled() -> ALL
            log.isLoggingOff() -> NONE
            else -> INFO
          }

      logger =
          object : Logger {
            override fun log(message: String) {
              log.info { message }
            }
          }
      format = OkHttp
      sanitizeHeader { header -> header == HttpHeaders.Authorization }
    }

    followRedirects = true

    expectSuccess = true

    install(DefaultRequest) {
      headers.append(HttpHeaders.ContentType, ContentType.Application.Xml.toString())
    }
  }

  /**
   * Provisions a new VIP Access credential from Symantec's server.
   *
   * @param tokenModel Token model type (default: "SYMC")
   * @return Token with generated ID and secret for OTP generation
   */
  suspend fun provision(tokenModel: String = "SYMC"): Token {
    log.info { "Provisioning Semantic VIP credential..." }
    val timestamp = Clock.System.now().epochSeconds
    val signedData = hmacSha256("$timestamp${timestamp}BOARDID${clientId}Symantec")
    val req =
        """
         <?xml version="1.0" encoding="UTF-8" ?>
         <GetSharedSecret Id="$timestamp" Version="2.0"
             xmlns="http://www.verisign.com/2006/08/vipservice"
             xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
             <TokenModel>$tokenModel</TokenModel>
             <ActivationCode></ActivationCode>
             <OtpAlgorithm type="HMAC-SHA1-TRUNC-6DIGITS"/>
             <SharedSecretDeliveryMethod>HTTPS</SharedSecretDeliveryMethod>
             <Extension extVersion="auth" xsi:type="vip:ProvisionInfoType"
                 xmlns:vip="http://www.verisign.com/2006/08/vipservice">
                 <AppHandle>iMac010200</AppHandle>
                 <ClientIDType>BOARDID</ClientIDType>
                 <ClientID>$clientId</ClientID>
                 <DistChannel>Symantec</DistChannel>
                 <ClientTimestamp>$timestamp</ClientTimestamp>
                 <Data>${Base64.encode(signedData)}</Data>
             </Extension>
         </GetSharedSecret>
        """
            .trimIndent()

    val res =
        client
            .post("https://services.vip.symantec.com/prov") { setBody(req) }
            .body<GetSharedSecretResponse>()

    log.info { "Provisioning response: $res" }
    require(res.Status.StatusMessage == "Success") {
      "Provisioning failed: ${res.Status.StatusMessage}"
    }

    val secret = res.SecretContainer.Device.Secret
    val iv = Base64.decode(res.SecretContainer.EncryptionMethod.IV)
    val cipher = Base64.decode(secret.Data.Cipher)

    val (_, algo, _, digitsStr) = secret.Usage.AI.type.split("-")
    require(digitsStr.endsWith("DIGITS")) { "Unknown algorithm: ${secret.Usage.AI.type}" }

    return Token(
        id = secret.Id,
        secret = Base64.encode(decryptAes(cipher, iv)),
        period = secret.Usage.TimeStep,
        algorithm = algo.lowercase(),
        digits = digitsStr.removeSuffix("DIGITS").toInt(),
    )
  }

  private suspend fun hmacSha256(data: String): ByteArray {
    val hmacSha256 = hmac.keyDecoder(SHA256).decodeFromByteArray(RAW, HMAC_KEY)
    return hmacSha256.signatureGenerator().generateSignature(data.encodeToByteArray())
  }

  private suspend fun decryptAes(cipherText: ByteArray, iv: ByteArray): ByteArray {
    val key = aes.keyDecoder().decodeFromByteArray(RAW, AES_KEY)
    return key.cipher(padding = true).decryptWithIv(iv = iv, ciphertext = cipherText)
  }

  /**
   * Generates an HOTP code (RFC 4226).
   *
   * HOTP Algorithm:
   * 1. Generate HMAC-SHA1 hash of the counter value
   * 2. Dynamic Truncation: Extract a 4-byte substring from the hash
   *     - Use last 4 bits of hash as offset (0-15)
   *     - Read 4 bytes starting at that offset as a big-endian integer
   *     - Clear the sign bit (AND with 0x7FFFFFFF) to get a 31-bit positive number
   * 3. Convert to decimal: Take modulo 10^digits to get the final OTP
   *
   * Example: If hash ends with 0x5A and offset=10, read bytes at positions 10-13, combine them into
   * an integer, then take last 6 digits.
   *
   * @param secret Shared secret key (decoded from Base64)
   * @param counter Moving factor (for TOTP, this is timestamp/period)
   * @param digits Number of digits in the OTP (6, 7, or 8)
   * @return OTP code as a zero-padded string
   */
  private suspend fun generateHotp(secret: ByteArray, counter: Long, digits: Int): String {
    // Step 1: Generate HMAC-SHA1 hash
    val hmacSha1 = hmac.keyDecoder(SHA1).decodeFromByteArray(RAW, secret)

    val buf = Buffer()
    buf.writeLong(counter)
    val hash = hmacSha1.signatureGenerator().generateSignature(buf.readByteArray())

    // Step 2: Dynamic truncation (RFC 4226 Section 5.3)
    val offset = hash.last().toInt() and 0x0F
    val sBits = Buffer()
    sBits.write(source = hash, startIndex = offset, endIndex = offset + 4)
    val truncated = sBits.readInt() and 0x7FFFFFFF

    val divisor = 10.0.pow(digits).toInt()
    return (truncated % divisor).toString().padStart(digits, '0')
  }

  suspend fun generateTotp(token: Token, timestamp: Long = Clock.System.now().epochSeconds) =
      generateHotp(
          secret = Base64.decode(token.secret),
          counter = timestamp / token.period,
          digits = token.digits,
      )

  /**
   * Generates an OTP URI (otpauth://) compatible with authenticator apps.
   *
   * @param token Token configuration
   * @param issuer Issuer name (default: "VIP Access")
   * @param accountName Account name (default: token ID)
   * @return OTP URI string
   */
  fun otpUri(
      token: Token,
      issuer: String = clientId,
      accountName: String = token.id,
  ): String {
    val secret = Base32.encode(Base64.decode(token.secret))
    val params = buildString {
      append("secret=$secret")
      append("&issuer=$issuer")
      if (token.algorithm.uppercase() != "SHA1") append("&algorithm=${token.algorithm.uppercase()}")
      if (token.digits != 6) append("&digits=${token.digits}")
      if (token.period != 30) append("&period=${token.period}")
    }
    return "otpauth://totp/$issuer:$accountName?$params"
  }

  /**
   * Validates token using Symantec's otpCheck endpoint.
   *
   * @param token Token to validate
   * @param timestamp Unix timestamp (default: current time)
   * @return Token validation result
   */
  suspend fun verifyToken(
      token: Token,
      timestamp: Long = Clock.System.now().epochSeconds,
  ): TokenResult =
      try {
        val otp = generateTotp(token, timestamp)
        val response =
            client.submitForm(
                url = "https://vip.symantec.com/otpCheck",
                formParameters =
                    parameters {
                      appendAll(otp.formParams("cr"))
                      append("cred", token.id)
                      append("continue", "otp_check")
                    },
            )

        val text = response.bodyAsText()
        when {
          Success.res in text -> Success
          NeedsSync.res in text -> NeedsSync
          else -> Failed("Unexpected response: $text")
        }
      } catch (e: Exception) {
        log.error(e) { "Token check failed" }
        Failed(e.message ?: "Unknown error")
      }

  /**
   * Syncs the token with Symantec's server using two consecutive OTPs.
   *
   * Note: For TOTP tokens, this will fail if performed less than 2 periods after the last sync or
   * check.
   *
   * @param token Token to sync
   * @param timestamp Unix timestamp (default: current time)
   * @return Token sync result
   */
  suspend fun syncToken(
      token: Token,
      timestamp: Long = Clock.System.now().epochSeconds,
  ): TokenResult =
      try {
        val otp1 = generateTotp(token, timestamp - token.period)
        val otp2 = generateTotp(token, timestamp)

        val response =
            client.submitForm(
                url = "https://vip.symantec.com/otpSync",
                formParameters =
                    parameters {
                      appendAll(otp1.formParams("cr"))
                      appendAll(otp2.formParams("ncr"))
                      append("cred", token.id)
                      append("continue", "otp_sync")
                    },
            )

        val text = response.bodyAsText()
        when {
          Success.res in text -> Success
          NeedsSync.res in text -> NeedsSync
          else -> Failed("Unexpected response: $text")
        }
      } catch (e: Exception) {
        log.error(e) { "Token sync failed" }
        Failed(e.message ?: "Unknown error")
      }

  override fun close() = client.close()
}

/** Converts OTP to Symantec VIP form format: "123456" → {cr1: "1", cr2: "2", ..., cr6: "6"} */
fun String.formParams(prefix: String) =
    mapIndexed { i, c -> "$prefix${i + 1}" to c.toString() }.toMap()
