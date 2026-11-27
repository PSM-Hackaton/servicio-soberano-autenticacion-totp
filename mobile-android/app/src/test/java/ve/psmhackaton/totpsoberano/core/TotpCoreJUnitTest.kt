package ve.psmhackaton.totpsoberano.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import ve.psmhackaton.totpsoberano.security.BiometricErrorMapper
import ve.psmhackaton.totpsoberano.security.PinManager
import ve.psmhackaton.totpsoberano.storage.AccountRepository
import java.io.File

class TotpCoreJUnitTest {

    @Test
    fun rfc6238Sha1VectorAt59Seconds() {
        val secret = "12345678901234567890".toByteArray(Charsets.US_ASCII)
        val code = TotpEngine.generateTotp(
            secret = secret,
            epochSeconds = 59L,
            algorithm = TotpEngine.Algorithm.SHA1,
            digits = 8,
            periodSeconds = 30,
        )
        assertEquals("94287082", code)
    }

    @Test
    fun cedulaNormalizationAndFormatting() {
        assertEquals("V12345678", CedulaValidator.normalizar("V", "12.345.678"))
        assertEquals("V-12.345.678", CedulaValidator.formatear("V12345678"))
        assertNull(CedulaValidator.normalizar("V", "000123"))
    }

    @Test
    fun otpAuthParserValidatesStandardUri() {
        val uri = "otpauth://totp/Portal:V-12.345.678?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=Portal&algorithm=SHA256&digits=6&period=30"
        val spec = OtpAuthParser.parse(uri)
        assertEquals("Portal", spec.issuer)
        assertEquals("V-12.345.678", spec.account)
        assertEquals(TotpEngine.Algorithm.SHA256, spec.algorithm)
        assertEquals(6, spec.digits)
    }

    @Test
    fun pinManagerPolicyAndBackoff() {
        assertFalse(PinManager.isStrongPin("123456"))
        assertFalse(PinManager.isStrongPin("000000"))
        assertTrue(PinManager.isStrongPin("482917"))
        assertEquals(0L, PinManager.lockoutSecondsForFailures(4))
        assertEquals(30L, PinManager.lockoutSecondsForFailures(5))
        assertEquals(3600L, PinManager.lockoutSecondsForFailures(9))
    }

    @Test
    fun biometricErrorMapperReturnsSpanishMessages() {
        val canceled = BiometricErrorMapper.toSpanishMessage(BiometricErrorMapper.ERROR_CANCELED)
        assertTrue(canceled.contains("cancelada", ignoreCase = true))
        val lockout = BiometricErrorMapper.toSpanishMessage(BiometricErrorMapper.ERROR_LOCKOUT)
        assertTrue(lockout.contains("30 segundos", ignoreCase = true))
        val noBio = BiometricErrorMapper.toSpanishMessage(BiometricErrorMapper.ERROR_NO_BIOMETRICS)
        assertTrue(noBio.contains("biometría", ignoreCase = true))
    }

    @Test
    fun accountRepositoryPersistsAndClearsEncryptedEnvelope() {
        val tempFile = File.createTempFile("totp_repo_test", ".bin")
        tempFile.delete()
        try {
            val repo = AccountRepository(tempFile)
            val fakeCipher = object : AccountRepository.CipherAdapter {
                override fun encrypt(aad: String, plaintext: ByteArray): Pair<ByteArray, ByteArray> =
                    ByteArray(12) { 7 } to plaintext.reversedArray()

                override fun decrypt(aad: String, iv: ByteArray, ciphertext: ByteArray): ByteArray =
                    ciphertext.reversedArray()
            }

            assertFalse(repo.hasStoredAccounts())
            val spec = OtpAuthParser.OtpAccountSpec(
                issuer = "Portal Soberano",
                account = "V-12.345.678",
                secretBase32 = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
                algorithm = TotpEngine.Algorithm.SHA256,
                digits = 6,
                periodSeconds = 30,
            )
            repo.saveAccounts(listOf(spec), fakeCipher)
            assertTrue(repo.hasStoredAccounts())
            val loaded = repo.loadAccounts(fakeCipher)
            assertEquals(1, loaded.size)
            assertEquals("Portal Soberano", loaded[0].issuer)
            assertEquals("V-12.345.678", loaded[0].account)

            repo.clearAll()
            assertFalse(repo.hasStoredAccounts())
        } finally {
            tempFile.delete()
        }
    }
}
