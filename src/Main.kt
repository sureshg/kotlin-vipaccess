import com.kgit2.kommand.process.Command
import com.kgit2.kommand.process.Stdio
import kotlinx.cinterop.toKString
import kotlinx.cinterop.usePinned
import kotlinx.coroutines.runBlocking
import platform.posix.getenv
import kotlin.time.Clock

fun main() = runBlocking {

    println("Hello World!")
//  val client = SvipClient()
//  println(client.provision())

    println("Connecting to Walmart 2FA VPN...Username: ${getUsername()}")

// Disconnect first
    println("Disconnecting...")
    Command("/opt/cisco/secureclient/bin/vpn")
        .arg("disconnect")
        .stdout(Stdio.Null)
        .stderr(Stdio.Null)
        .spawn()
        .waitWithOutput()
        .also { println("Disconnected! ${it.status}") }

    println("Killing Cisco Secure Client processes...")
    Command("pkill")
        .arg("Cisco Secure Client")
        .stdout(Stdio.Null)
        .stderr(Stdio.Null)
        .spawn()
        .wait()

// Connect with 2FA
    println("Waiting for 2FA...")
    val child = Command("/opt/cisco/secureclient/bin/vpn")
        .arg("-s")
        .stdin(Stdio.Pipe)
        .stdout(Stdio.Pipe)
        .stderr(Stdio.Pipe)
        .spawn()

    val stdin = child.bufferedStdin()
    stdin?.writeLine("connect \"WeC 2 Step Verification\"")
    stdin?.writeLine(getUsername().orEmpty())
    stdin?.writeLine("xxxx")
    stdin?.writeLine("xxxx")
    stdin?.writeLine("y")
// DON'T call stdin?.close() here - waitWithOutput() does it

    val output = child.waitWithOutput()
    println("Status: ${output.status}")
    println("Output: ${output.stdout}")
    println("Errors: ${output.stderr}")
}

fun getUsername(): String? {
    return getenv("USER")?.toKString() ?: getenv("USERNAME")?.toKString()  // Windows fallback
}
//# Walmart 2FA VPN connect
//function vpnconnect() {
//    if [ -x "/opt/cisco/secureclient/bin/vpn" ]; then
//    vpn_bin="/opt/cisco/secureclient/bin/vpn"
//    vpn_proc="Cisco Secure Client"
//    else
//    vpn_bin="/opt/cisco/anyconnect/bin/vpn"
//    vpn_proc="Cisco AnyConnect Secure Mobility Client"
//    fi
//    # go get -u rsc.io/2fa
//    echo "Connecting to Walmart 2FA VPN..."
//    ${vpn_bin} disconnect > /dev/null
//    # To see all profiles - /opt/cisco/anyconnect/bin/vpn hosts
//    pkill ${vpn_proc}
//    ${vpn_bin} -s > /dev/null << EOF
//            connect "WeC Two Factor VPN"
//    $(whoami)
//    ${VOID_TOKEN}
//    $(2fa Walmart)
//    y
//    EOF
//    echo -e "\n\xF0\x9F\x8D\xBB  VPN Connected!"
//}