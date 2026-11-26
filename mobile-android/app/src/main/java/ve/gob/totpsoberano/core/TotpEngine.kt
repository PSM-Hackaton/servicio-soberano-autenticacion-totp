package ve.gob.totpsoberano.core

import java.nio.ByteBuffer
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.math.pow

/**
 * Motor criptográfico HOTP/TOTP propio conforme a RFC 4226 y RFC 6238 (Issue #41 · M2).
 * Cero dependencias externas: utiliza únicamente javax.crypto estándar de Android/JVM.
 */
object TotpEngine {

    enum class Algorithm(val jcaName: String, val keyUriName: String) {
        SHA1("HmacSHA1", "SHA1"),
        SHA256("HmacSHA256", "SHA256"),
        SHA512("HmacSHA512", "SHA512");

        companion object {
            fun parse(raw: String): Algorithm = when (raw.uppercase().replace("-", "").trim()) {
                "SHA1" -> SHA1
                "SHA256" -> SHA256
                "SHA512" -> SHA512
                else -> throw IllegalArgumentException("Algoritmo no soportado: $raw")
            }
        }
    }

    private const val BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

    fun decodeBase32(input: String): ByteArray {
        val cleaned = input.uppercase().replace(Regex("[\\s-]+"), "").trimEnd('=')
        require(cleaned.isNotEmpty()) { "Semilla Base32 vacía" }

        var bits = 0
        var value = 0
        val out = ArrayList<Byte>((cleaned.length * 5) / 8)
        for (ch in cleaned) {
            val idx = BASE32_ALPHABET.indexOf(ch)
            require(idx >= 0) { "Carácter Base32 inválido: $ch" }
            value = (value shl 5) or idx
            bits += 5
            if (bits >= 8) {
                out.add(((value ushr (bits - 8)) and 0xFF).toByte())
                bits -= 8
            }
        }
        require(out.isNotEmpty()) { "Semilla Base32 insuficiente" }
        return out.toByteArray()
    }

    fun generateHotp(
        secret: ByteArray,
        counter: Long,
        algorithm: Algorithm = Algorithm.SHA256,
        digits: Int = 6,
    ): String {
        require(secret.isNotEmpty()) { "La semilla no puede estar vacía" }
        require(digits == 6 || digits == 8) { "Los dígitos soportados son 6 u 8" }

        val msg = ByteBuffer.allocate(8).putLong(counter).array()
        val mac = Mac.getInstance(algorithm.jcaName)
        mac.init(SecretKeySpec(secret, algorithm.jcaName))
        val hash = mac.doFinal(msg)

        val offset = hash[hash.size - 1].toInt() and 0x0F
        val binary =
            ((hash[offset].toInt() and 0x7F) shl 24) or
            ((hash[offset + 1].toInt() and 0xFF) shl 16) or
            ((hash[offset + 2].toInt() and 0xFF) shl 8) or
            (hash[offset + 3].toInt() and 0xFF)

        val mod = 10.0.pow(digits).toInt()
        return (binary % mod).toString().padStart(digits, '0')
    }

    fun generateTotp(
        secret: ByteArray,
        epochSeconds: Long,
        algorithm: Algorithm = Algorithm.SHA256,
        digits: Int = 6,
        periodSeconds: Int = 30,
    ): String {
        require(periodSeconds in 15..60) { "El período debe estar entre 15 y 60 segundos" }
        val step = Math.floorDiv(epochSeconds, periodSeconds.toLong())
        return generateHotp(secret, step, algorithm, digits)
    }
}
