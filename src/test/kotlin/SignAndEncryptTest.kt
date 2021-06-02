import SignAndEncrypt.senderPublicJWK
import com.nimbusds.jose.crypto.RSASSAVerifier
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test
import kotlin.test.junit5.JUnit5Asserter.assertNotNull

internal class SignAndEncryptTest {
    @Test
    internal fun `should sign and encrypt given text`() {
        val encryptedString = SignAndEncrypt.encrypt("heyyy")

        val signedJWT = SignAndEncrypt.decrypt(encryptedString)

        assertNotNull("Payload not a signed JWT", signedJWT)

        Assertions.assertTrue(signedJWT?.verify(RSASSAVerifier(senderPublicJWK))!!)

        Assertions.assertEquals("encrypp", signedJWT.jwtClaimsSet?.subject);
        Assertions.assertEquals("heyyy", signedJWT.jwtClaimsSet?.claims?.get("name"));
    }
}