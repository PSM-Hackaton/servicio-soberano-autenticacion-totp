package ve.psmhackaton.totpsoberano.storage

import org.json.JSONArray
import org.json.JSONObject
import ve.psmhackaton.totpsoberano.core.OtpAuthParser
import ve.psmhackaton.totpsoberano.core.TotpEngine
import java.io.File
import java.util.Base64

/**
 * Persistencia cifrada de cuentas TOTP en almacenamiento interno privado (`filesDir`).
 * Usa un adaptador de cifrado AES-256-GCM (implementado sobre KeystoreVault en producción
 * y sustituible en pruebas unitarias sin hardware Android).
 */
class AccountRepository(
    private val storageFile: File,
) {
    interface CipherAdapter {
        fun encrypt(aad: String, plaintext: ByteArray): Pair<ByteArray, ByteArray>
        fun decrypt(aad: String, iv: ByteArray, ciphertext: ByteArray): ByteArray
    }

    companion object {
        private const val AAD_CONTEXT = "totp-accounts-v1"
    }

    fun hasStoredAccounts(): Boolean = storageFile.exists() && storageFile.length() > 0L

    fun readStoredIv(): ByteArray? {
        if (!hasStoredAccounts()) return null
        val json = JSONObject(storageFile.readText(Charsets.UTF_8))
        val ivB64 = json.optString("iv", "")
        if (ivB64.isEmpty()) return null
        return Base64.getDecoder().decode(ivB64)
    }

    fun saveAccounts(accounts: List<OtpAuthParser.OtpAccountSpec>, cipher: CipherAdapter) {
        val arr = JSONArray()
        for (acc in accounts) {
            arr.put(
                JSONObject().apply {
                    put("issuer", acc.issuer)
                    put("account", acc.account)
                    put("secretBase32", acc.secretBase32)
                    put("algorithm", acc.algorithm.keyUriName)
                    put("digits", acc.digits)
                    put("periodSeconds", acc.periodSeconds)
                },
            )
        }
        val plaintext = arr.toString().toByteArray(Charsets.UTF_8)
        val (iv, ciphertext) = cipher.encrypt(AAD_CONTEXT, plaintext)
        val envelope = JSONObject().apply {
            put("v", 1)
            put("iv", Base64.getEncoder().encodeToString(iv))
            put("ct", Base64.getEncoder().encodeToString(ciphertext))
        }
        storageFile.parentFile?.mkdirs()
        storageFile.writeText(envelope.toString(), Charsets.UTF_8)
    }

    fun loadAccounts(cipher: CipherAdapter): List<OtpAuthParser.OtpAccountSpec> {
        if (!hasStoredAccounts()) return emptyList()
        val envelope = JSONObject(storageFile.readText(Charsets.UTF_8))
        val iv = Base64.getDecoder().decode(envelope.getString("iv"))
        val ct = Base64.getDecoder().decode(envelope.getString("ct"))
        val plaintext = cipher.decrypt(AAD_CONTEXT, iv, ct)
        val arr = JSONArray(String(plaintext, Charsets.UTF_8))
        val out = ArrayList<OtpAuthParser.OtpAccountSpec>(arr.length())
        for (i in 0 until arr.length()) {
            val obj = arr.getJSONObject(i)
            out.add(
                OtpAuthParser.OtpAccountSpec(
                    issuer = obj.optString("issuer", ""),
                    account = obj.optString("account", ""),
                    secretBase32 = obj.getString("secretBase32"),
                    algorithm = TotpEngine.Algorithm.parse(obj.optString("algorithm", "SHA256")),
                    digits = obj.optInt("digits", 6),
                    periodSeconds = obj.optInt("periodSeconds", 30),
                ),
            )
        }
        return out
    }

    fun clearAll() {
        if (storageFile.exists()) {
            storageFile.delete()
        }
    }
}
