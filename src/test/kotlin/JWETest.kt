import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test

internal class JWETest {
    @Test
    internal fun `encrypt given text`() {
        val encryptedString = JWE.encrypt("hello")

        val decryptedString = JWE.decrypt(encryptedString!!)

        Assertions.assertEquals("hello", decryptedString)
    }
}