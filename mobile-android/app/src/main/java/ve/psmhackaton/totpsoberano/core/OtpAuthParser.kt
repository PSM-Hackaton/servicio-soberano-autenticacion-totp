package ve.psmhackaton.totpsoberano.core

import java.net.URI
import java.net.URLDecoder
import java.nio.charset.StandardCharsets

/**
 * Analizador y validador estricto de URIs otpauth://totp/ (Issue #43 · M4).
 * Espejo exacto de las reglas de seguridad de authenticator-app/js/otpauth.js.
 */
object OtpAuthParser {

    data class OtpAccountSpec(
        val issuer: String,
        val account: String,
        val secretBase32: String,
        val algorithm: TotpEngine.Algorithm,
        val digits: Int,
        val periodSeconds: Int,
    )

    private val BIDI_AND_CONTROL = Regex("[\\u0000-\\u001F\\u007F-\\u009F\\u200B-\\u200F\\u202A-\\u202E\\u2066-\\u2069\\uFEFF]")
    private const val MAX_URI_LENGTH = 2048

    private fun limpiarTexto(texto: String): String =
        texto.replace(BIDI_AND_CONTROL, "").trim()

    fun parse(rawUri: String): OtpAccountSpec {
        val uriText = rawUri.trim()
        require(uriText.length <= MAX_URI_LENGTH) { "URI demasiado larga" }
        require(uriText.lowercase().startsWith("otpauth://totp/")) {
            if (uriText.lowercase().startsWith("otpauth://hotp/")) "HOTP no está soportado; se requiere TOTP"
            else "La URI debe iniciar con otpauth://totp/"
        }

        val uri = URI(uriText)
        val rawQuery = uri.rawQuery ?: throw IllegalArgumentException("Faltan parámetros en la URI")
        val params = LinkedHashMap<String, String>()
        for (pair in rawQuery.split('&')) {
            if (pair.isEmpty()) continue
            val idx = pair.indexOf('=')
            require(idx > 0) { "Parámetro mal formado en la URI" }
            val k = URLDecoder.decode(pair.substring(0, idx), StandardCharsets.UTF_8.name()).lowercase()
            val v = URLDecoder.decode(pair.substring(idx + 1), StandardCharsets.UTF_8.name())
            require(!params.containsKey(k)) { "Parámetro repetido en la URI: $k" }
            params[k] = v
        }

        require(!params.containsKey("counter")) { "HOTP (counter) no está soportado" }

        val rawPath = uri.rawPath.removePrefix("/")
        val label = URLDecoder.decode(rawPath, StandardCharsets.UTF_8.name())
        val (labelIssuer, labelAccount) = if (label.contains(':')) {
            val sep = label.indexOf(':')
            limpiarTexto(label.substring(0, sep)) to limpiarTexto(label.substring(sep + 1))
        } else {
            "" to limpiarTexto(label)
        }

        val paramIssuer = limpiarTexto(params["issuer"] ?: "")
        if (labelIssuer.isNotEmpty() && paramIssuer.isNotEmpty()) {
            require(labelIssuer == paramIssuer) { "El emisor de la etiqueta no coincide con issuer" }
        }
        val issuer = paramIssuer.ifEmpty { labelIssuer }
        require(issuer.isNotEmpty() || labelAccount.isNotEmpty()) { "La cuenta debe tener al menos un nombre o emisor" }

        val rawSecret = (params["secret"] ?: "").uppercase().replace(Regex("[\\s-]+"), "").trimEnd('=')
        require(rawSecret.isNotEmpty()) { "Falta la clave secreta" }
        val decoded = TotpEngine.decodeBase32(rawSecret)
        require(decoded.size >= 16) { "Semilla demasiado corta (mínimo 128 bits)" }

        val algorithm = TotpEngine.Algorithm.parse(params["algorithm"] ?: "SHA1")
        val digits = (params["digits"] ?: "6").toIntOrNull()
            ?: throw IllegalArgumentException("Dígitos inválidos")
        require(digits == 6 || digits == 8) { "Los dígitos deben ser 6 u 8" }

        val period = (params["period"] ?: "30").toIntOrNull()
            ?: throw IllegalArgumentException("Período debe ser un entero")
        require(period in 15..60) { "El período debe estar entre 15 y 60 segundos" }

        return OtpAccountSpec(
            issuer = issuer,
            account = labelAccount,
            secretBase32 = rawSecret,
            algorithm = algorithm,
            digits = digits,
            periodSeconds = period,
        )
    }
}
