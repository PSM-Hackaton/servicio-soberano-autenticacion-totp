package ve.psmhackaton.totpsoberano.security

/**
 * Mapea códigos de error de androidx.biometric.BiometricPrompt a mensajes claros en español.
 * Evita exponer textos técnicos en inglés del sistema operativo al ciudadano.
 */
object BiometricErrorMapper {

    const val ERROR_HW_UNAVAILABLE = 1
    const val ERROR_UNABLE_TO_PROCESS = 2
    const val ERROR_TIMEOUT = 3
    const val ERROR_CANCELED = 5
    const val ERROR_LOCKOUT = 7
    const val ERROR_LOCKOUT_PERMANENT = 9
    const val ERROR_USER_CANCELED = 10
    const val ERROR_NO_BIOMETRICS = 11
    const val ERROR_HW_NOT_PRESENT = 12
    const val ERROR_NEGATIVE_BUTTON = 13

    fun toSpanishMessage(errorCode: Int): String = when (errorCode) {
        ERROR_USER_CANCELED, ERROR_NEGATIVE_BUTTON, ERROR_CANCELED ->
            "Autenticación cancelada. La bóveda permanece bloqueada."
        ERROR_LOCKOUT ->
            "Demasiados intentos fallidos. Espera 30 segundos antes de reintentar."
        ERROR_LOCKOUT_PERMANENT ->
            "Biometría bloqueada por seguridad. Desbloquea tu teléfono con tu PIN del sistema."
        ERROR_NO_BIOMETRICS ->
            "No hay huella ni biometría configurada en este dispositivo."
        ERROR_HW_NOT_PRESENT, ERROR_HW_UNAVAILABLE ->
            "El sensor biométrico no está disponible en este momento."
        ERROR_TIMEOUT ->
            "Tiempo de espera agotado. Intenta nuevamente."
        ERROR_UNABLE_TO_PROCESS ->
            "No se pudo reconocer la huella. Intenta nuevamente."
        else ->
            "No se pudo completar la autenticación biométrica. La bóveda permanece bloqueada."
    }
}
