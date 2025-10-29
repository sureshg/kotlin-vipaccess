@file:Suppress("PropertyName")

import kotlin.time.Clock
import kotlinx.serialization.Serializable
import nl.adaptivity.xmlutil.serialization.XmlElement
import nl.adaptivity.xmlutil.serialization.XmlValue

@Serializable
data class GetSharedSecretResponse(
    val RequestId: String,
    val Version: String,
    val Status: Status,
    @XmlElement(true) val SharedSecretDeliveryMethod: String,
    val SecretContainer: SecretContainer,
    @XmlElement(true) val UTCTimestamp: Long,
)

@Serializable
data class Status(
    @XmlElement(true) val ReasonCode: String,
    @XmlElement(true) val StatusMessage: String,
)

@Serializable
data class SecretContainer(
    val Version: String,
    val EncryptionMethod: EncryptionMethod,
    val Device: Device,
)

@Serializable
data class EncryptionMethod(
    @XmlElement(true) val PBESalt: String,
    @XmlElement(true) val PBEIterationCount: Int,
    @XmlElement(true) val IV: String,
)

@Serializable data class Device(val Secret: Secret)

@Serializable
data class Secret(
    val type: String,
    val Id: String,
    @XmlElement(true) val Issuer: String,
    val Usage: Usage,
    @XmlElement(true) val FriendlyName: String,
    val Data: Data,
    @XmlElement(true) val Expiry: String,
)

@Serializable
data class Usage(
    val otp: Boolean,
    val AI: AI,
    @XmlElement(true) val TimeStep: Int,
    @XmlElement(true) val Time: Long,
    @XmlElement(true) val ClockDrift: Int,
)

@Serializable data class AI(val type: String)

@Serializable data class Data(@XmlElement(true) val Cipher: String, val Digest: Digest)

@Serializable data class Digest(val algorithm: String, @XmlValue val value: String)

@Serializable
data class Token(
    val id: String,
    val secret: String,
    val period: Int = 30,
    val counter: Int? = null,
    val algorithm: String = "sha1",
    val digits: Int = 6,
) {
  /** Gets the remaining seconds until the current OTP expires. */
  val remainingSeconds = period - (Clock.System.now().epochSeconds % period).toInt()
}

/** Token validation/sync result */
enum class TokenResult {
  SUCCESS,
  NEEDS_SYNC,
  FAILED,
}
