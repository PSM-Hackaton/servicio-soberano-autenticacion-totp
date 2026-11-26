package ve.gob.totpsoberano.core

/**
 * Vectores oficiales del Apéndice B del RFC 6238 para SHA-1, SHA-256 y SHA-512 (8 dígitos).
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
        for (v in VECTORS) {
            check(TotpEngine.generateTotp(SEED_SHA1, v.time, TotpEngine.Algorithm.SHA1, 8, 30) == v.sha1)
            check(TotpEngine.generateTotp(SEED_SHA256, v.time, TotpEngine.Algorithm.SHA256, 8, 30) == v.sha256)
            check(TotpEngine.generateTotp(SEED_SHA512, v.time, TotpEngine.Algorithm.SHA512, 8, 30) == v.sha512)
        }
    }
}
