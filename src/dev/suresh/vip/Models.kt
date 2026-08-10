@file:Suppress("PropertyName")

package dev.suresh.vip

import kotlin.time.Clock
import kotlinx.serialization.Serializable
import nl.adaptivity.xmlutil.serialization.*

@Serializable
public data class Token(
    val id: String,
    val secret: String,
    val period: Int = 30,
    val counter: Long? = null,
    val algorithm: String = "sha1",
    val digits: Int = 6,
) {
  public val type: String
    get() = if (counter == null) "totp" else "hotp"

  /** Gets the remaining seconds until the current OTP expires. */
  public val remainingSeconds: Int
    get() = period - (Clock.System.now().epochSeconds % period).toInt()

  public fun advanced(steps: Int): Token = counter?.let { copy(counter = it + steps) } ?: this
}

public sealed interface TokenResult {
  public data class Success(val token: Token) : TokenResult

  public data object NeedsSync : TokenResult

  public data class Failed(val error: String) : TokenResult
}

@Serializable
internal data class GetSharedSecretResponse(
    val RequestId: String,
    val Version: String,
    val Status: Status,
    @XmlElement(true) val SharedSecretDeliveryMethod: String,
    val SecretContainer: SecretContainer,
    @XmlElement(true) val UTCTimestamp: Long,
)

@Serializable
internal data class Status(
    @XmlElement(true) val ReasonCode: String,
    @XmlElement(true) val StatusMessage: String,
)

@Serializable
internal data class SecretContainer(
    val Version: String,
    val EncryptionMethod: EncryptionMethod,
    val Device: Device,
)

@Serializable
internal data class EncryptionMethod(
    @XmlElement(true) val PBESalt: String,
    @XmlElement(true) val PBEIterationCount: Int,
    @XmlElement(true) val IV: String,
)

@Serializable internal data class Device(val Secret: Secret)

@Serializable
internal data class Secret(
    val type: String,
    val Id: String,
    @XmlElement(true) val Issuer: String,
    val Usage: Usage,
    @XmlElement(true) val FriendlyName: String,
    val Data: Data,
    @XmlElement(true) val Expiry: String,
)

@Serializable
internal data class Usage(
    val otp: Boolean,
    val AI: AI,
    @XmlElement(true) val TimeStep: Int? = null,
    @XmlElement(true) val Counter: Long? = null,
    @XmlElement(true) val Time: Long = 0,
    @XmlElement(true) val ClockDrift: Int = 0,
)

@Serializable internal data class AI(val type: String)

@Serializable internal data class Data(@XmlElement(true) val Cipher: String, val Digest: Digest)

@Serializable internal data class Digest(val algorithm: String, @XmlValue val value: String)
