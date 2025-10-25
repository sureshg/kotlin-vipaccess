import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import nl.adaptivity.xmlutil.serialization.XmlElement
import nl.adaptivity.xmlutil.serialization.XmlValue

@Serializable
data class GetSharedSecretResponse(
    @SerialName("RequestId") val requestId: String,
    @SerialName("Version") val version: String,
    val status: Status,
    @XmlElement(true)
    @SerialName("SharedSecretDeliveryMethod")
    val sharedSecretDeliveryMethod: String,
    val secretContainer: SecretContainer,
    @XmlElement(true) @SerialName("UTCTimestamp") val utcTimestamp: Long,
)

@Serializable
data class Status(
    @XmlElement(true) @SerialName("ReasonCode") val reasonCode: String,
    @XmlElement(true) @SerialName("StatusMessage") val statusMessage: String,
)

@Serializable
data class SecretContainer(
    @SerialName("Version") val version: String,
    val encryptionMethod: EncryptionMethod,
    val device: Device,
)

@Serializable
data class EncryptionMethod(
    @XmlElement(true) @SerialName("PBESalt") val pbeSalt: String,
    @XmlElement(true) @SerialName("PBEIterationCount") val pbeIterationCount: Int,
    @XmlElement(true) @SerialName("IV") val iv: String,
)

@Serializable data class Device(@SerialName("Secret") val secret: Secret)

@Serializable
data class Secret(
    val type: String, // attr "type"
    @SerialName("Id") val id: String, // attr "Id"
    @XmlElement(true) @SerialName("Issuer") val issuer: String,
    val usage: Usage,
    @XmlElement(true) @SerialName("FriendlyName") val friendlyName: String,
    @SerialName("Data") val data: Data,
    @XmlElement(true) @SerialName("Expiry") val expiry: String,
)

@Serializable
data class Usage(
    val otp: Boolean, // attr "otp"
    val ai: AI, // element name from type "AI"
    @XmlElement(true) @SerialName("TimeStep") val timeStep: Int,
    @XmlElement(true) @SerialName("Time") val time: Long,
    @XmlElement(true) @SerialName("ClockDrift") val clockDrift: Int,
)

@Serializable
data class AI(
    val type: String // attr "type"
)

@Serializable
data class Data(@XmlElement(true) @SerialName("Cipher") val cipher: String, val digest: Digest)

@Serializable
data class Digest(
    val algorithm: String, // attr "algorithm"
    @XmlValue val value: String,
)
