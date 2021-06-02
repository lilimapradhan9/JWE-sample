import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test

internal class EncryptJWTTest {
    @Test
    internal fun `encrypt given text`() {
        val encryptedString = EncryptJWT.encrypt("hello")

        val decryptedJWT = EncryptJWT.decrypt(encryptedString!!)

        Assertions.assertEquals("issuee", decryptedJWT?.jwtClaimsSet?.issuer)
        Assertions.assertEquals("hello", decryptedJWT?.jwtClaimsSet?.subject)
    }
}