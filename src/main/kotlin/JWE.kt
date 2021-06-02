import com.nimbusds.jose.*
import com.nimbusds.jose.crypto.RSADecrypter
import com.nimbusds.jose.crypto.RSAEncrypter
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import javax.crypto.KeyGenerator


object JWE {
    private val rsaKeyPair: KeyPair = KeyPairGenerator.getInstance("RSA").also {
        it.initialize(2048)
    }.generateKeyPair()


    fun encrypt(input: String): String? {
        val alg: JWEAlgorithm = JWEAlgorithm.RSA_OAEP_256
        val enc: EncryptionMethod = EncryptionMethod.A128CBC_HS256
        val publicKey = rsaKeyPair.public as RSAPublicKey

        val keyGenerator = KeyGenerator.getInstance("AES")
        keyGenerator.init(enc.cekBitLength())

        val contentEncryptionKey = keyGenerator.generateKey()

        val jwe = JWEObject(
            JWEHeader(alg, enc),
            Payload(input)
        )

        jwe.encrypt(RSAEncrypter(publicKey, contentEncryptionKey))
        return jwe.serialize()
    }

    fun decrypt(encryptedString: String): String {
        val privateKey = rsaKeyPair.private as RSAPrivateKey
        val jwe = JWEObject.parse(encryptedString)
        jwe.decrypt(RSADecrypter(privateKey))

        return jwe.payload.toString()
    }
}