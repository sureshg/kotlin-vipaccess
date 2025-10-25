import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.algorithms.HMAC
import dev.whyoleg.cryptography.algorithms.SHA256
import io.github.oshai.kotlinlogging.KotlinLogging
import io.ktor.client.*
import io.ktor.client.call.body
import io.ktor.client.engine.curl.*
import io.ktor.client.plugins.*
import io.ktor.client.plugins.compression.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.plugins.logging.*
import io.ktor.client.plugins.logging.LogLevel.*
import io.ktor.client.plugins.logging.LoggingFormat.*
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.http.*
import io.ktor.serialization.kotlinx.xml.*
import io.ktor.util.*
import kotlin.io.encoding.Base64
import kotlin.time.Clock
import kotlin.time.Duration.Companion.seconds
import nl.adaptivity.xmlutil.XmlDeclMode
import nl.adaptivity.xmlutil.serialization.XML

class SvipClient : AutoCloseable {
  val VERIFY_URL = "https://vip.symantec.com/otpCheck"

  private val CLIENT_ID = "kotlin-svip-access-1.0.0"

  private val HMAC_KEY =
      "dd0ba692c38aa3a993a3aa26968cd9c2aa2aa2cb23b7c2d2aaaf8f8fc9a0a9a1".hexToByteArray()

  private val TOKEN_ENCRYPTION_KEY = "01ad9bc682a3aa93a9a3239a86d6ccd9".hexToByteArray()

  private val log = KotlinLogging.logger {}

  private val xml = XML {
    indent = 2
    autoPolymorphic = true
    xmlDeclMode = XmlDeclMode.Auto
    recommended {
      ignoreNamespaces()
      ignoreUnknownChildren()
    }
  }

  private val client =
      HttpClient(Curl) {
        install(ContentNegotiation) { xml(xml) }
        install(ContentEncoding) {
          deflate(1.0F)
          gzip(0.9F)
        }

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
                else -> ALL
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
          headers.appendIfNameAndValueAbsent(
              HttpHeaders.ContentType,
              ContentType.Application.Xml.toString(),
          )
        }
      }

  suspend fun provision(tokenModel: String = "SYMC", verify: Boolean = false): String {
    log.info { "Provisioning Semantic VIP credential (model: $tokenModel)" }
    val timestamp = Clock.System.now().epochSeconds
    val data = "$timestamp${timestamp}BOARDID${CLIENT_ID}Symantec"
    val hmacSha256 =
        CryptographyProvider.Default.get(HMAC).keyDecoder(SHA256).decodeFromByteArray(RAW, HMAC_KEY)
    val signedData = hmacSha256.signatureGenerator().generateSignature(data.encodeToByteArray())

    val requestXml =
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
                 <ClientID>$CLIENT_ID</ClientID>
                 <DistChannel>Symantec</DistChannel>
                 <ClientTimestamp>$timestamp</ClientTimestamp>
                 <Data>${Base64.encode(signedData)}</Data>
             </Extension>
         </GetSharedSecret>
        """
            .trimIndent()

    println(requestXml)
    val res =
        client
            .post("https://services.vip.symantec.com/prov") { setBody(requestXml) }
            .body<GetSharedSecretResponse>()
    log.info { "Provisioning response: $res" }
    return requestXml
  }

  override fun close() = client.close()
}
