package ve.psmhackaton.totpsoberano.security

import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

/**
 * Política de PIN y bloqueo progresivo de la app móvil (Issue #42 · M3).
 * - Exige PIN de al menos 6 dígitos y rechaza secuencias triviales o repeticiones.
 * - Derivación con PBKDF2WithHmacSHA256 (150.000 iteraciones) y comparación en tiempo constante.
 * - Bloqueo progresivo ante intentos fallidos: 30 s → 2 min → 10 min → 1 h.
 */
object PinManager {

    private const val MIN_PIN_LENGTH = 6
    private const val PBKDF2_ITERATIONS = 150_000
    private const val KEY_BITS = 256
    private val BACKOFF_SECONDS = longArrayOf(30L, 120L, 600L, 3600L)

    data class PinHash(val salt: ByteArray, val digest: ByteArray, val iterations: Int = PBKDF2_ITERATIONS)

    fun isStrongPin(pin: String): Boolean {
        if (pin.length < MIN_PIN_LENGTH || !pin.all { it.isDigit() }) return false
        // Rechaza todos iguales (ej. 000000, 111111)
        if (pin.toSet().size <= 1) return false
        // Rechaza secuencias estrictamente ascendentes o descendentes (ej. 123456, 987654)
        var asc = true
        var desc = true
        for (i in 1 until pin.length) {
            val diff = pin[i].digitToInt() - pin[i - 1].digitToInt()
            if (diff != 1) asc = false
            if (diff != -1) desc = false
        }
        return !asc && !desc
    }

    fun hashPin(pin: String): PinHash {
        require(isStrongPin(pin)) { "El PIN debe tener al menos 6 dígitos y no ser una secuencia trivial" }
        val salt = ByteArray(16).also { SecureRandom().nextBytes(it) }
        val digest = derive(pin, salt, PBKDF2_ITERATIONS)
        return PinHash(salt = salt, digest = digest, iterations = PBKDF2_ITERATIONS)
    }

    fun verifyPin(pin: String, stored: PinHash): Boolean {
        val candidate = derive(pin, stored.salt, stored.iterations)
        return MessageDigest.isEqual(candidate, stored.digest)
    }

    fun lockoutSecondsForFailures(failedAttempts: Int): Long {
        if (failedAttempts < 5) return 0L
        val idx = (failedAttempts - 5).coerceIn(0, BACKOFF_SECONDS.lastIndex)
        return BACKOFF_SECONDS[idx]
    }

    private fun derive(pin: String, salt: ByteArray, iterations: Int): ByteArray {
        val spec = PBEKeySpec(pin.toCharArray(), salt, iterations, KEY_BITS)
        return try {
            SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded
        } finally {
            spec.clearPassword()
        }
    }
}
