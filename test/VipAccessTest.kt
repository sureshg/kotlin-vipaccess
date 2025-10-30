import kotlin.test.*
import kotlinx.coroutines.test.runTest

class VipAccessTest {

  private val vipAccess = VipAccess()

  @Test
  fun provision() = runTest {
    val token = vipAccess.provision()

    assertTrue(token.id.startsWith("SYMC"))
    assertTrue(token.secret.isNotEmpty())
    assertEquals(30, token.period)
    assertEquals(6, token.digits)
  }

  @Test
  fun generateTotp() = runTest {
    val token = vipAccess.provision()
    val otp = vipAccess.generateTotp(token)

    assertEquals(6, otp.length)
    assertTrue(otp.all { it.isDigit() })
  }

  @Test
  fun otpUri() = runTest {
    val token = vipAccess.provision()
    val uri = vipAccess.otpUri(token)

    assertTrue(uri.startsWith("otpauth://totp/kotlin-vipaccess:${token.id}?secret="))
    assertTrue(uri.contains("&issuer=kotlin-vipaccess"))
  }

  @Test
  fun verifyAndSync() = runTest {
    val token = vipAccess.provision()

    when (vipAccess.verifyToken(token)) {
      is TokenResult.Success -> return@runTest
      is TokenResult.NeedsSync -> {
        vipAccess.syncToken(token)
        assertTrue(vipAccess.verifyToken(token) is TokenResult.Success)
      }
      is TokenResult.Failed -> fail("Token verification failed")
    }
  }
}
