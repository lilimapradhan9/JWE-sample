import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWEHeader
import com.nimbusds.jose.crypto.RSADecrypter
import com.nimbusds.jose.crypto.RSAEncrypter
import com.nimbusds.jwt.EncryptedJWT
import com.nimbusds.jwt.JWTClaimsSet
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.util.*

object EncryptJWT {
    private val rsaKeyPair: KeyPair = KeyPairGenerator.getInstance("RSA").also {
        it.initialize(2048)
    }.generateKeyPair()

    fun encrypt(input: String): String? {
        val now = Date()

        val jwtClaims = JWTClaimsSet.Builder()
            .issuer("issuee")
            .subject(input)
            .expirationTime(Date(now.time + 1000 * 60 * 10))
            .notBeforeTime(now)
            .issueTime(now)
            .jwtID(UUID.randomUUID().toString())
            .build()

        val header = JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128GCM)
            .customParam("USE", "INTERNAL")
            .build()

        val jwt = EncryptedJWT(header, jwtClaims)

        jwt.encrypt(RSAEncrypter(rsaKeyPair.public as RSAPublicKey))

        return jwt.serialize()
    }

    fun decrypt(encryptedString: String): EncryptedJWT? {
        val jwt = EncryptedJWT.parse(encryptedString)

        val decrypter = RSADecrypter(rsaKeyPair.private as RSAPrivateKey)

        jwt.decrypt(decrypter)

        return jwt
    }
}