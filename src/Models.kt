@file:Suppress("PropertyName")

import kotlinx.serialization.Serializable
import nl.adaptivity.xmlutil.serialization.XmlElement
import nl.adaptivity.xmlutil.serialization.XmlValue
import kotlin.time.Clock

@Serializable
public data class GetSharedSecretResponse(
    val RequestId: String,
    val Version: String,
    val Status: Status,
    @XmlElement(true) val SharedSecretDeliveryMethod: String,
    val SecretContainer: SecretContainer,
    @XmlElement(true) val UTCTimestamp: Long,
)

@Serializable
public data class Status(
    @XmlElement(true) val ReasonCode: String,
    @XmlElement(true) val StatusMessage: String,
)

@Serializable
public data class SecretContainer(
    val Version: String,
    val EncryptionMethod: EncryptionMethod,
    val Device: Device,
)

@Serializable
public data class EncryptionMethod(
    @XmlElement(true) val PBESalt: String,
    @XmlElement(true) val PBEIterationCount: Int,
    @XmlElement(true) val IV: String,
)

@Serializable public data class Device(val Secret: Secret)

@Serializable
public data class Secret(
    val type: String,
    val Id: String,
    @XmlElement(true) val Issuer: String,
    val Usage: Usage,
    @XmlElement(true) val FriendlyName: String,
    val Data: Data,
    @XmlElement(true) val Expiry: String,
)

@Serializable
public data class Usage(
    val otp: Boolean,
    val AI: AI,
    @XmlElement(true) val TimeStep: Int,
    @XmlElement(true) val Time: Long,
    @XmlElement(true) val ClockDrift: Int,
)

@Serializable public data class AI(val type: String)

@Serializable public data class Data(@XmlElement(true) val Cipher: String, val Digest: Digest)

@Serializable public data class Digest(val algorithm: String, @XmlValue val value: String)

@Serializable
public data class Token(
    val id: String,
    val secret: String,
    val period: Int = 30,
    val counter: Int? = null,
    val algorithm: String = "sha1",
    val digits: Int = 6,
) {
  /** Gets the remaining seconds until the current OTP expires. */
  val remainingSeconds: Int
    get() = period - (Clock.System.now().epochSeconds % period).toInt()
}

public sealed class TokenResult(public val res: String) {
  public data object Success : TokenResult("VIP Credential is working correctly")

  public data object NeedsSync : TokenResult("VIP credential needs to be sync")

  public data class Failed(val error: String) : TokenResult("")
}
