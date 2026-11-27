package ve.psmhackaton.totpsoberano.security

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Bóveda hardware de semillas TOTP sobre Android Keystore / StrongBox (Issue #41 · M2).
 * - Clave AES-256-GCM no exportable generada dentro del módulo de seguridad del dispositivo.
 * - AAD obligatorio ligado al identificador de cuenta para prevenir trasplante de registros cifrados.
 * - Exige autenticación de usuario (biometría o PIN del dispositivo) para operar.
 */
class KeystoreVault(
    private val keyAlias: String = "totp_soberano_master_aes256_v1",
) {
    companion object {
        private const val KEYSTORE_PROVIDER = "AndroidKeyStore"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val GCM_TAG_BITS = 128
    }

    data class EncryptedSeed(
        val iv: ByteArray,
        val ciphertext: ByteArray,
    )

    private fun getOrCreateMasterKey(): SecretKey {
        val ks = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
        (ks.getKey(keyAlias, null) as? SecretKey)?.let { return it }

        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE_PROVIDER)

        fun buildSpec(useStrongBox: Boolean): KeyGenParameterSpec {
            val builder = KeyGenParameterSpec.Builder(
                keyAlias,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setRandomizedEncryptionRequired(true)
                .setUserAuthenticationRequired(true)

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && useStrongBox) {
                builder.setIsStrongBoxBacked(true)
            }
            return builder.build()
        }

        return try {
            generator.init(buildSpec(useStrongBox = true))
            generator.generateKey()
        } catch (_: StrongBoxUnavailableException) {
            // Degradación limpia a TEE si el dispositivo no cuenta con chip StrongBox dedicado
            generator.init(buildSpec(useStrongBox = false))
            generator.generateKey()
        }
    }

    fun encryptSeed(accountId: String, rawSeed: ByteArray): EncryptedSeed {
        require(accountId.isNotBlank()) { "accountId obligatorio para AAD" }
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateMasterKey())
        cipher.updateAAD("totp-soberano:$accountId".toByteArray(Charsets.UTF_8))
        val ct = cipher.doFinal(rawSeed)
        return EncryptedSeed(iv = cipher.iv, ciphertext = ct)
    }

    fun decryptSeed(accountId: String, encrypted: EncryptedSeed): ByteArray {
        require(accountId.isNotBlank()) { "accountId obligatorio para AAD" }
        val cipher = Cipher.getInstance(TRANSFORMATION)
        val spec = GCMParameterSpec(GCM_TAG_BITS, encrypted.iv)
        cipher.init(Cipher.DECRYPT_MODE, getOrCreateMasterKey(), spec)
        cipher.updateAAD("totp-soberano:$accountId".toByteArray(Charsets.UTF_8))
        return cipher.doFinal(encrypted.ciphertext)
    }

    fun wipeMasterKey() {
        val ks = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
        if (ks.containsAlias(keyAlias)) {
            ks.deleteEntry(keyAlias)
        }
    }
}
