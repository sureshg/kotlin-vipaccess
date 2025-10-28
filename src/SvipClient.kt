import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import io.github.oshai.kotlinlogging.KotlinLogging
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.engine.cio.CIO
import io.ktor.client.plugins.*
import io.ktor.client.plugins.compression.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.plugins.logging.*
import io.ktor.client.plugins.logging.LogLevel.*
import io.ktor.client.plugins.logging.LoggingFormat.*
import io.ktor.client.request.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.xml.*
import io.ktor.util.*
import nl.adaptivity.xmlutil.XmlDeclMode
import nl.adaptivity.xmlutil.serialization.XML
import kotlin.io.encoding.Base64
import kotlin.time.Clock
import kotlin.time.Duration.Companion.seconds

class SvipClient : AutoCloseable {


    private val HMAC_KEY =
        "dd0ba692c38aa3a993a3aa26968cd9c2aa2aa2cb23b7c2d2aaaf8f8fc9a0a9a1".hexToByteArray()

    private val TOKEN_ENC_KEY = "01ad9bc682a3aa93a9a3239a86d6ccd9".hexToByteArray()

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
        HttpClient(CIO) {
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

    suspend fun provision(tokenModel: String = "SYMC", verify: Boolean = false): Token {
        log.info { "Provisioning Semantic VIP credential (model: $tokenModel)" }

        val clientID = "kotlin-svip-access-1.0.0"
        val timestamp = Clock.System.now().epochSeconds
        val signedData = hmacSha256("$timestamp${timestamp}BOARDID${clientID}Symantec")
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
                 <ClientID>$clientID</ClientID>
                 <DistChannel>Symantec</DistChannel>
                 <ClientTimestamp>$timestamp</ClientTimestamp>
                 <Data>${Base64.encode(signedData)}</Data>
             </Extension>
         </GetSharedSecret>
        """
                .trimIndent()

        val res =
            client
                .post("https://services.vip.symantec.com/prov") { setBody(requestXml) }
                .body<GetSharedSecretResponse>()

        log.info { "Provisioning response: $res" }
        require(res.status.statusMessage == "Success") {
            "Provisioning failed: ${res.status.statusMessage}"
        }

        val secret = res.secretContainer.device.secret
        val iv = Base64.decode(res.secretContainer.encryptionMethod.iv)
        val cipher = Base64.decode(secret.data.cipher)

        val (_, algo, _, digitsStr) = secret.usage.ai.type.split("-")
        require(digitsStr.endsWith("DIGITS")) { "Unknown algorithm: ${secret.usage.ai.type}" }

        return Token(
            id = secret.id,
            base64Secret = Base64.encode(decryptAes(cipher, iv)),
            period = secret.usage.timeStep,
            algorithm = algo.lowercase(),
            digits = digitsStr.removeSuffix("DIGITS").toInt()
        )
    }


    private suspend fun hmacSha256(data: String): ByteArray {
        val hmacSha256 =
            CryptographyProvider
                .Default
                .get(HMAC)
                .keyDecoder(SHA256)
                .decodeFromByteArray(RAW, HMAC_KEY)
        return hmacSha256.signatureGenerator().generateSignature(data.encodeToByteArray())
    }


    private suspend fun decryptAes(cipherText: ByteArray, iv: ByteArray): ByteArray {
        val key = CryptographyProvider
            .Default
            .get(AES.CBC).keyDecoder()
            .decodeFromByteArray(RAW, TOKEN_ENC_KEY)
        return key.cipher().decryptWithIv(iv = iv, ciphertext = cipherText)
    }

    override fun close() = client.close()
}
