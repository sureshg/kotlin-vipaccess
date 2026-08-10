package dev.suresh.vip

import kotlin.io.encoding.Base64
import kotlin.test.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withContext

class VipAccessTest {

  private val vipAccess = VipAccess()

  private val testToken =
      Token(
          id = "SYMC_TEST",
          secret = Base64.encode("12345678901234567890".encodeToByteArray()),
      )

  @Test
  fun provision() = runTest {
    withContext(Dispatchers.Default) {
      val token = vipAccess.provision()
      assertTrue(token.id.startsWith("SYMC"))
      assertTrue(token.secret.isNotEmpty())
      assertEquals(30, token.period)
      assertEquals(6, token.digits)

      val verified =
          when (val result = vipAccess.verifyToken(token)) {
            is Success -> true
            is NeedsSync -> vipAccess.syncToken(token) is Success
            is Failed -> fail(result.error)
          }
      assertTrue(verified)
    }
  }

  @Test
  fun generateTotp() = runTest {
    val otp = vipAccess.generateOtp(testToken, timestamp = 59)
    assertEquals("287082", otp)
  }

  @Test
  fun generateHotp() = runTest {
    val secret = Base64.encode("12345678901234567890".encodeToByteArray())
    val expected: List<String> =
        [
            "755224",
            "287082",
            "359152",
            "969429",
            "338314",
            "254676",
            "287922",
            "162583",
            "399871",
            "520489",
        ]
    expected.forEachIndexed { counter, otp ->
      assertEquals(
          otp,
          vipAccess.generateOtp(Token(id = "HOTP", secret = secret, counter = counter.toLong())),
      )
    }
  }

  @Test
  fun otpUri() {
    val uri = vipAccess.otpUri(testToken)
    assertTrue(uri.startsWith("otpauth://totp/kotlin-vipaccess:${testToken.id}?secret="))
    assertTrue(uri.contains("&issuer=kotlin-vipaccess"))
  }

  @Test
  fun hotpOtpUri() {
    val token = Token(id = "HOTP", secret = Base64.encode([1]), counter = 7)
    val uri = vipAccess.otpUri(token)

    assertTrue(uri.startsWith("otpauth://hotp/"))
    assertTrue("&counter=7" in uri)
    assertTrue("&period=" !in uri)
  }
}
