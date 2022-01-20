package br.com.cbauthserver.jwks

import java.security.interfaces.RSAPublicKey
import java.security.interfaces.RSAPrivateKey
import java.util.UUID
import com.nimbusds.jose.jwk.RSAKey
import java.security.KeyPair
import java.security.KeyPairGenerator

object KeyGeneratorUtils {

    fun generateRSAKey(): RSAKey {
        val keyPair: KeyPair = generateRsaKeyPair()
        val publicKey = keyPair.public as RSAPublicKey
        val privateKey = keyPair.private as RSAPrivateKey

        return RSAKey.Builder(publicKey)
            .privateKey(privateKey)
            .keyID(UUID.randomUUID().toString())
            .build()
    }

    private fun generateRsaKeyPair(): KeyPair = kotlin.runCatching {
        KeyPairGenerator.getInstance("RSA").let { keyPairGenerator ->
            keyPairGenerator.initialize(2048)
            return@runCatching keyPairGenerator.generateKeyPair()
        }
    }.getOrElse { ex -> throw IllegalStateException(ex) }
}