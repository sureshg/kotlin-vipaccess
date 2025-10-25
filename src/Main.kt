import kotlinx.coroutines.runBlocking

fun main() = runBlocking {
  println("Hello World!")
  val client = SvipClient()
  println(client.provision())
}
