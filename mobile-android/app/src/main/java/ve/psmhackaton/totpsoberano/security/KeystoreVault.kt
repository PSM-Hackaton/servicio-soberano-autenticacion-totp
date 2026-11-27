package ve.psmhackaton.totpsoberano.security

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.security.keystore.UserNotAuthenticatedException
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Bóveda hardware de semillas TOTP sobre Android Keystore / StrongBox (Issue #41 · M2).
 * - Clave AES-256-GCM no exportable generada dentro del módulo de seguridad del dispositivo.
 * - AAD obligatorio ligado al identificador de cuenta para prevenir trasplante de registros cifrados.
 * - Compatible con BiometricPrompt.CryptoObject en Android 8+ y Android 11+ (API 30+).
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

    sealed class VaultResult<out T> {
        data class Success<T>(val value: T) : VaultResult<T>()
        data object KeyInvalidated : VaultResult<Nothing>()
        data object UserNotAuthenticated : VaultResult<Nothing>()
        data class Error(val message: String) : VaultResult<Nothing>()
    }

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

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                builder.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
            } else {
                @Suppress("DEPRECATION")
                builder.setUserAuthenticationValidityDurationSeconds(-1)
            }

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

    /**
     * Inicializa un Cipher en modo ENCRYPT listo para envolver en BiometricPrompt.CryptoObject.
     */
    fun createEncryptCipher(): VaultResult<Cipher> = runVaultCatching {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateMasterKey())
        cipher
    }

    /**
     * Inicializa un Cipher en modo DECRYPT con el IV almacenado, listo para BiometricPrompt.CryptoObject.
     */
    fun createDecryptCipher(iv: ByteArray): VaultResult<Cipher> = runVaultCatching {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        val spec = GCMParameterSpec(GCM_TAG_BITS, iv)
        cipher.init(Cipher.DECRYPT_MODE, getOrCreateMasterKey(), spec)
        cipher
    }

    /**
     * Cifra la semilla usando el Cipher autenticado devuelto por BiometricPrompt (result.cryptoObject?.cipher).
     */
    fun encryptSeedWithCipher(
        authenticatedCipher: Cipher,
        accountId: String,
        rawSeed: ByteArray,
    ): VaultResult<EncryptedSeed> = runVaultCatching {
        require(accountId.isNotBlank()) { "accountId obligatorio para AAD" }
        authenticatedCipher.updateAAD("totp-soberano:$accountId".toByteArray(Charsets.UTF_8))
        val ct = authenticatedCipher.doFinal(rawSeed)
        EncryptedSeed(iv = authenticatedCipher.iv, ciphertext = ct)
    }

    /**
     * Descifra la semilla usando el Cipher autenticado devuelto por BiometricPrompt (result.cryptoObject?.cipher).
     */
    fun decryptSeedWithCipher(
        authenticatedCipher: Cipher,
        accountId: String,
        encrypted: EncryptedSeed,
    ): VaultResult<ByteArray> = runVaultCatching {
        require(accountId.isNotBlank()) { "accountId obligatorio para AAD" }
        authenticatedCipher.updateAAD("totp-soberano:$accountId".toByteArray(Charsets.UTF_8))
        authenticatedCipher.doFinal(encrypted.ciphertext)
    }

    fun wipeMasterKey() {
        val ks = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
        if (ks.containsAlias(keyAlias)) {
            ks.deleteEntry(keyAlias)
        }
    }

    private inline fun <T> runVaultCatching(block: () -> T): VaultResult<T> = try {
        VaultResult.Success(block())
    } catch (_: KeyPermanentlyInvalidatedException) {
        VaultResult.KeyInvalidated
    } catch (_: UserNotAuthenticatedException) {
        VaultResult.UserNotAuthenticated
    } catch (e: Exception) {
        VaultResult.Error(e.message ?: "Error en Android Keystore")
    }
}
