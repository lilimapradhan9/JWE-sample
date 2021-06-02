import com.nimbusds.jose.*
import com.nimbusds.jose.crypto.RSADecrypter
import com.nimbusds.jose.crypto.RSAEncrypter
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import java.util.*

object SignAndEncrypt {
    private var senderJWK: RSAKey = RSAKeyGenerator(2048)
        .keyID("123")
        .keyUse(KeyUse.SIGNATURE)
        .generate()
     var senderPublicJWK: RSAKey = senderJWK.toPublicJWK()

    private var recipientJWK = RSAKeyGenerator(2048)
        .keyID("456")
        .keyUse(KeyUse.ENCRYPTION)
        .generate()
    private var recipientPublicJWK = recipientJWK.toPublicJWK()


    fun encrypt(input: String): String {
        val signedJWT = SignedJWT(
            JWSHeader.Builder(JWSAlgorithm.RS256).keyID(senderJWK.keyID).build(),
            JWTClaimsSet.Builder()
                .subject("encrypp")
                .issueTime(Date())
                .claim("name", input)
                .build()
        )

        signedJWT.sign(RSASSASigner(senderJWK))

        val jweObject = JWEObject(
            JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
                .contentType("JWT")
                .build(),
            Payload(signedJWT)
        )

        jweObject.encrypt(RSAEncrypter(recipientPublicJWK))

        return jweObject.serialize()
    }


    fun decrypt(encryptedString: String): SignedJWT? {
        val jweObject = JWEObject.parse(encryptedString)

        jweObject.decrypt(RSADecrypter(recipientJWK))

        return jweObject.payload.toSignedJWT()
    }
}