package ve.psmhackaton.totpsoberano.core

import ve.psmhackaton.totpsoberano.security.PinManager

/**
 * Pruebas unitarias puras (JVM/Android) de:
 * - Vectores oficiales del Apéndice B del RFC 6238 (SHA-1, SHA-256, SHA-512, 8 dígitos).
 * - Normalización y formateo de cédula (V/E, con y sin puntos).
 * - Validación estricta de URIs otpauth://totp/.
 * - Política de fortaleza de PIN y bloqueo progresivo.
 */
object TotpEngineTest {

    private val SEED_SHA1 = "12345678901234567890".toByteArray(Charsets.US_ASCII)
    private val SEED_SHA256 = "12345678901234567890123456789012".toByteArray(Charsets.US_ASCII)
    private val SEED_SHA512 = "1234567890123456789012345678901234567890123456789012345678901234".toByteArray(Charsets.US_ASCII)

    private data class Vector(val time: Long, val sha1: String, val sha256: String, val sha512: String)

    private val VECTORS = listOf(
        Vector(59L, "94287082", "46119246", "90693936"),
        Vector(1111111109L, "07081804", "68084774", "25091201"),
        Vector(1111111111L, "14050471", "67062674", "99943326"),
        Vector(1234567890L, "89005924", "91819424", "93441116"),
        Vector(2000000000L, "69279037", "90698825", "38618901"),
        Vector(20000000000L, "65353130", "77737706", "47863826"),
    )

    fun runAll() {
        // 1. Vectores RFC 6238 Apéndice B
        for (v in VECTORS) {
            check(TotpEngine.generateTotp(SEED_SHA1, v.time, TotpEngine.Algorithm.SHA1, 8, 30) == v.sha1)
            check(TotpEngine.generateTotp(SEED_SHA256, v.time, TotpEngine.Algorithm.SHA256, 8, 30) == v.sha256)
            check(TotpEngine.generateTotp(SEED_SHA512, v.time, TotpEngine.Algorithm.SHA512, 8, 30) == v.sha512)
        }

        // 2. Cédula venezolana (M1)
        check(CedulaValidator.normalizar("V", "12.345.678") == "V12345678")
        check(CedulaValidator.normalizar("V", "E-81.234.567") == "E81234567")
        check(CedulaValidator.normalizar("V", "1.2345.678") == null)
        check(CedulaValidator.formatear("V12345678") == "V-12.345.678")

        // 3. OtpAuthParser estricto (M4)
        val uri = "otpauth://totp/Portal%20de%20Tr%C3%A1mites:V-12.345.678?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Portal+de+Tr%C3%A1mites&algorithm=SHA256&digits=6&period=30"
        val spec = OtpAuthParser.parse(uri)
        check(spec.issuer == "Portal de Trámites")
        check(spec.account == "V-12.345.678")
        check(spec.algorithm == TotpEngine.Algorithm.SHA256)
        check(spec.digits == 6)

        // 4. PinManager (M3)
        check(!PinManager.isStrongPin("123456"))
        check(!PinManager.isStrongPin("654321"))
        check(!PinManager.isStrongPin("000000"))
        check(PinManager.isStrongPin("294715"))
        check(PinManager.lockoutSecondsForFailures(4) == 0L)
        check(PinManager.lockoutSecondsForFailures(5) == 30L)
        check(PinManager.lockoutSecondsForFailures(8) == 3600L)
    }
}
