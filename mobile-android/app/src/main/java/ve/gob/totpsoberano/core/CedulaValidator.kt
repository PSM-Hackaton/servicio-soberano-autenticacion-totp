package ve.gob.totpsoberano.core

/**
 * Validación y formateo de cédula de identidad venezolana (Issue #40 · M1).
 * Coincide exactamente con las reglas de demo-portal-tramites/src/cedula.js:
 *   - Nacionalidad V o E + 6 a 9 dígitos sin ceros iniciales (normalizada: "V12345678").
 *   - Acepta entrada con o sin puntos bien agrupados ("12.345.678" o "V-12.345.678").
 *   - Formateo visual para lista de cuentas: "V-12.345.678".
 *
 * Nota de privacidad: la cédula se envía únicamente al portal institucional (1.er factor);
 * el servicio TOTP nunca recibe la cédula en claro, solo un seudónimo HMAC (user_ref).
 */
object CedulaValidator {

    private val REGEX_ENTRADA = Regex("^(?:([VE])\\s?-?\\s?)?([0-9.]{6,11})$")
    private val REGEX_DIGITOS = Regex("^[1-9][0-9]{5,8}$")
    private val REGEX_NORMALIZADA = Regex("^([VE])([0-9]{6,9})$")

    fun conPuntos(digitos: String): String {
        val sb = StringBuilder()
        val len = digitos.length
        for (i in digitos.indices) {
            if (i > 0 && (len - i) % 3 == 0) sb.append('.')
            sb.append(digitos[i])
        }
        return sb.toString()
    }

    fun normalizar(nacionalidadSelector: String, numero: String): String? {
        val texto = numero.trim().uppercase().replace(Regex("\\s+"), " ")
        val m = REGEX_ENTRADA.matchEntire(texto) ?: return null
        val nac = m.groupValues[1].ifEmpty { nacionalidadSelector.trim().uppercase() }
        if (nac != "V" && nac != "E") return null
        val crudo = m.groupValues[2]
        val digitos = crudo.replace(".", "")
        if (!REGEX_DIGITOS.matches(digitos)) return null
        if (crudo.contains('.') && crudo != conPuntos(digitos)) return null
        return "$nac$digitos"
    }

    fun formatear(normalizada: String): String {
        val m = REGEX_NORMALIZADA.matchEntire(normalizada) ?: return ""
        return "${m.groupValues[1]}-${conPuntos(m.groupValues[2])}"
    }
}
