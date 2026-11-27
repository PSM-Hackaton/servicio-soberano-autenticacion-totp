package ve.psmhackaton.totpsoberano

import android.Manifest
import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.PersistableBundle
import android.view.View
import android.view.WindowManager
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.core.view.ViewCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.WindowInsetsControllerCompat
import androidx.fragment.app.FragmentActivity
import ve.psmhackaton.totpsoberano.core.OtpAuthParser
import ve.psmhackaton.totpsoberano.core.TotpEngine
import ve.psmhackaton.totpsoberano.databinding.ActivityMainBinding
import ve.psmhackaton.totpsoberano.security.BiometricErrorMapper
import ve.psmhackaton.totpsoberano.security.KeystoreVault
import ve.psmhackaton.totpsoberano.storage.AccountRepository
import java.io.File
import javax.crypto.Cipher

/**
 * Pantalla principal del Autenticador Soberano TOTP.
 * - Edge-to-Edge real para Android 15/16 (API 35/36) respetando statusBar y displayCutout.
 * - Protección FLAG_SECURE contra capturas de pantalla.
 * - Desbloqueo biométrico con BiometricPrompt.CryptoObject y persistencia cifrada multi-cuenta.
 * - Escáner QR soberano (CameraX + ZXing, 0 Google Play Services).
 * - Cero ejecución en segundo plano: el temporizador solo corre entre onResume() y onPause()/onStop().
 */
class MainActivity : FragmentActivity() {

    private lateinit var binding: ActivityMainBinding
    private val vault = KeystoreVault()
    private lateinit var repository: AccountRepository
    private val handler = Handler(Looper.getMainLooper())

    private var unlocked = false
    private val accounts = mutableListOf<OtpAuthParser.OtpAccountSpec>()
    private var selectedIndex = 0
    private var activeSecretBytes: ByteArray? = null
    private var lastGeneratedCode: String = ""

    private val qrScannerLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult(),
    ) { result ->
        if (result.resultCode == RESULT_OK) {
            val qrText = result.data?.getStringExtra(QrScannerActivity.EXTRA_QR_RESULT).orEmpty()
            if (qrText.isNotBlank()) {
                binding.inputOtp.setText(qrText)
                addAccountFromInput()
            }
        }
    }

    private val cameraPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { granted ->
        if (granted) {
            qrScannerLauncher.launch(Intent(this, QrScannerActivity::class.java))
        } else {
            binding.txtStatus.text = getString(R.string.status_camera_denied)
        }
    }

    private val tickRunnable = object : Runnable {
        override fun run() {
            if (!unlocked) return
            renderActiveCode()
            handler.postDelayed(this, 500L)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        WindowCompat.setDecorFitsSystemWindows(window, false)
        WindowInsetsControllerCompat(window, window.decorView).isAppearanceLightStatusBars = false

        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE,
        )

        repository = AccountRepository(File(filesDir, "totp_accounts.bin"))
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        applyEdgeToEdgeInsets()

        binding.btnUnlock.setOnClickListener { startBiometricUnlock() }
        binding.btnScanQr.setOnClickListener { launchQrScanner() }
        binding.btnAddAccount.setOnClickListener { addAccountFromInput() }
        binding.btnCopyCode.setOnClickListener { copyCurrentCode() }
        binding.btnDeleteAccount.setOnClickListener { confirmDeleteAccount() }
        binding.btnPrevAccount.setOnClickListener { switchAccount(-1) }
        binding.btnNextAccount.setOnClickListener { switchAccount(1) }

        updateLockUi()
    }

    private fun launchQrScanner() {
        val granted = ContextCompat.checkSelfPermission(
            this,
            Manifest.permission.CAMERA,
        ) == PackageManager.PERMISSION_GRANTED
        if (granted) {
            qrScannerLauncher.launch(Intent(this, QrScannerActivity::class.java))
        } else {
            cameraPermissionLauncher.launch(Manifest.permission.CAMERA)
        }
    }

    private fun switchAccount(delta: Int) {
        if (accounts.size <= 1) return
        selectedIndex = (selectedIndex + delta + accounts.size) % accounts.size
        activeSecretBytes = TotpEngine.decodeBase32(accounts[selectedIndex].secretBase32)
        renderActiveCode()
    }

    private fun applyEdgeToEdgeInsets() {
        val headerBaseTop = binding.headerContainer.paddingTop
        val headerBaseBottom = binding.headerContainer.paddingBottom
        val headerBaseStart = binding.headerContainer.paddingStart
        val headerBaseEnd = binding.headerContainer.paddingEnd

        ViewCompat.setOnApplyWindowInsetsListener(binding.headerContainer) { v, windowInsets ->
            val bars = windowInsets.getInsets(
                WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.displayCutout(),
            )
            v.setPaddingRelative(
                headerBaseStart + bars.left,
                headerBaseTop + bars.top,
                headerBaseEnd + bars.right,
                headerBaseBottom,
            )
            windowInsets
        }

        val scrollBaseBottom = binding.contentScroll.paddingBottom
        ViewCompat.setOnApplyWindowInsetsListener(binding.contentScroll) { v, windowInsets ->
            val bars = windowInsets.getInsets(WindowInsetsCompat.Type.systemBars())
            v.setPadding(v.paddingLeft, v.paddingTop, v.paddingRight, scrollBaseBottom + bars.bottom)
            windowInsets
        }
    }

    override fun onResume() {
        super.onResume()
        if (unlocked && activeSecretBytes != null) {
            renderActiveCode()
            handler.removeCallbacks(tickRunnable)
            handler.postDelayed(tickRunnable, 500L)
        }
    }

    override fun onPause() {
        super.onPause()
        handler.removeCallbacks(tickRunnable)
    }

    override fun onStop() {
        super.onStop()
        handler.removeCallbacks(tickRunnable)
    }

    private fun startBiometricUnlock() {
        val biometricManager = BiometricManager.from(this)
        val canAuth = biometricManager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)
        if (canAuth != BiometricManager.BIOMETRIC_SUCCESS) {
            binding.txtStatus.text = getString(R.string.status_biometric_unavailable)
            return
        }

        val storedIv = repository.readStoredIv()
        val cipherResult = if (storedIv != null) {
            vault.createDecryptCipher(storedIv)
        } else {
            vault.createEncryptCipher()
        }

        val cipher = when (cipherResult) {
            is KeystoreVault.VaultResult.Success -> cipherResult.value
            is KeystoreVault.VaultResult.KeyInvalidated -> {
                vault.wipeMasterKey()
                repository.clearAll()
                binding.txtStatus.text = getString(R.string.status_key_invalidated)
                return
            }
            is KeystoreVault.VaultResult.UserNotAuthenticated -> {
                binding.txtStatus.text = getString(R.string.status_auth_required)
                return
            }
            is KeystoreVault.VaultResult.Error -> {
                binding.txtStatus.text = cipherResult.message
                return
            }
        }

        authenticateWithCipher(cipher) { authenticatedCipher ->
            unlocked = true
            if (storedIv != null) {
                loadStoredAccountsWithCipher(authenticatedCipher)
            } else {
                binding.txtStatus.text = getString(R.string.status_unlocked_empty)
            }
            updateLockUi()
            if (activeSecretBytes != null) {
                renderActiveCode()
                handler.removeCallbacks(tickRunnable)
                handler.postDelayed(tickRunnable, 500L)
            }
        }
    }

    private fun authenticateWithCipher(cipher: Cipher, onAuthenticated: (Cipher) -> Unit) {
        val executor = ContextCompat.getMainExecutor(this)
        val prompt = BiometricPrompt(
            this,
            executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    val authenticatedCipher = result.cryptoObject?.cipher
                    if (authenticatedCipher == null) {
                        binding.txtStatus.text = getString(R.string.status_auth_required)
                        return
                    }
                    onAuthenticated(authenticatedCipher)
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    binding.txtStatus.text = BiometricErrorMapper.toSpanishMessage(errorCode)
                }
            },
        )

        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle(getString(R.string.biometric_title))
            .setSubtitle(getString(R.string.biometric_subtitle))
            .setNegativeButtonText(getString(R.string.biometric_cancel))
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            .build()

        prompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(cipher))
    }

    private fun loadStoredAccountsWithCipher(authenticatedCipher: Cipher) {
        try {
            val loaded = repository.loadAccounts(vaultCipherAdapter(authenticatedCipher))
            accounts.clear()
            accounts.addAll(loaded)
            if (accounts.isNotEmpty()) {
                selectedIndex = 0
                activeSecretBytes = TotpEngine.decodeBase32(accounts[0].secretBase32)
                binding.txtStatus.text = getString(R.string.status_account_ready)
            } else {
                binding.txtStatus.text = getString(R.string.status_unlocked_empty)
            }
        } catch (_: Exception) {
            binding.txtStatus.text = getString(R.string.status_key_invalidated)
        }
    }

    private fun addAccountFromInput() {
        val raw = binding.inputOtp.text?.toString()?.trim().orEmpty()
        if (raw.isEmpty()) {
            val msg = getString(R.string.status_input_empty)
            binding.inputOtpLayout.error = msg
            binding.inputOtp.error = msg
            binding.inputOtp.requestFocus()
            return
        }
        binding.inputOtpLayout.error = null
        binding.inputOtp.error = null

        val spec = try {
            if (raw.lowercase().startsWith("otpauth://")) {
                OtpAuthParser.parse(raw)
            } else {
                val decoded = TotpEngine.decodeBase32(raw)
                require(decoded.size >= 16) { "Semilla demasiado corta (mínimo 128 bits)" }
                OtpAuthParser.OtpAccountSpec(
                    issuer = getString(R.string.default_issuer),
                    account = "${getString(R.string.default_account)} #${accounts.size + 1}",
                    secretBase32 = raw.uppercase().replace(Regex("[\\s-]+"), "").trimEnd('='),
                    algorithm = TotpEngine.Algorithm.SHA256,
                    digits = 6,
                    periodSeconds = 30,
                )
            }
        } catch (e: Exception) {
            val msg = e.message ?: getString(R.string.status_invalid_input)
            binding.inputOtpLayout.error = msg
            binding.inputOtp.error = msg
            binding.inputOtp.requestFocus()
            return
        }

        val updatedList = accounts.toMutableList().apply {
            removeAll { it.secretBase32 == spec.secretBase32 }
            add(spec)
        }

        val encryptResult = vault.createEncryptCipher()
        if (encryptResult is KeystoreVault.VaultResult.Success) {
            authenticateWithCipher(encryptResult.value) { authenticatedCipher ->
                repository.saveAccounts(updatedList, vaultCipherAdapter(authenticatedCipher))
                applyAccountsList(updatedList, updatedList.lastIndex)
            }
        } else {
            applyAccountsList(updatedList, updatedList.lastIndex)
        }
    }

    private fun applyAccountsList(updated: List<OtpAuthParser.OtpAccountSpec>, focusIdx: Int) {
        accounts.clear()
        accounts.addAll(updated)
        selectedIndex = focusIdx.coerceIn(0, (accounts.size - 1).coerceAtLeast(0))
        activeSecretBytes = accounts.getOrNull(selectedIndex)?.let { TotpEngine.decodeBase32(it.secretBase32) }
        binding.inputOtp.text?.clear()
        binding.inputOtpLayout.error = null
        binding.txtStatus.text = getString(R.string.status_account_ready)
        renderActiveCode()
        handler.removeCallbacks(tickRunnable)
        handler.postDelayed(tickRunnable, 500L)
    }

    private fun confirmDeleteAccount() {
        if (accounts.isEmpty()) return
        AlertDialog.Builder(this)
            .setTitle(R.string.confirm_delete_title)
            .setMessage(R.string.confirm_delete_message)
            .setNegativeButton(R.string.biometric_cancel, null)
            .setPositiveButton(R.string.confirm_delete_yes) { _, _ ->
                val remaining = accounts.toMutableList().apply { removeAt(selectedIndex) }
                if (remaining.isEmpty()) {
                    repository.clearAll()
                    accounts.clear()
                    activeSecretBytes = null
                    lastGeneratedCode = ""
                    handler.removeCallbacks(tickRunnable)
                    binding.cardCode.visibility = View.GONE
                    binding.txtStatus.text = getString(R.string.status_account_deleted)
                } else {
                    val encryptResult = vault.createEncryptCipher()
                    if (encryptResult is KeystoreVault.VaultResult.Success) {
                        authenticateWithCipher(encryptResult.value) { authenticatedCipher ->
                            repository.saveAccounts(remaining, vaultCipherAdapter(authenticatedCipher))
                            applyAccountsList(remaining, 0)
                            binding.txtStatus.text = getString(R.string.status_account_deleted)
                        }
                    } else {
                        applyAccountsList(remaining, 0)
                        binding.txtStatus.text = getString(R.string.status_account_deleted)
                    }
                }
            }
            .show()
    }

    private fun vaultCipherAdapter(cipher: Cipher): AccountRepository.CipherAdapter =
        object : AccountRepository.CipherAdapter {
            override fun encrypt(aad: String, plaintext: ByteArray): Pair<ByteArray, ByteArray> {
                val res = vault.encryptSeedWithCipher(cipher, aad, plaintext)
                require(res is KeystoreVault.VaultResult.Success) { "No se pudo cifrar la cuenta" }
                return res.value.iv to res.value.ciphertext
            }

            override fun decrypt(aad: String, iv: ByteArray, ciphertext: ByteArray): ByteArray {
                val res = vault.decryptSeedWithCipher(
                    cipher,
                    aad,
                    KeystoreVault.EncryptedSeed(iv = iv, ciphertext = ciphertext),
                )
                require(res is KeystoreVault.VaultResult.Success) { "No se pudo descifrar la cuenta" }
                return res.value
            }
        }

    private fun renderActiveCode() {
        val account = accounts.getOrNull(selectedIndex) ?: return
        val secret = activeSecretBytes ?: return
        val nowSec = System.currentTimeMillis() / 1000L
        val code = TotpEngine.generateTotp(
            secret = secret,
            epochSeconds = nowSec,
            algorithm = account.algorithm,
            digits = account.digits,
            periodSeconds = account.periodSeconds,
        )
        val remaining = account.periodSeconds - (nowSec % account.periodSeconds).toInt()
        lastGeneratedCode = code

        val label = if (account.issuer.isNotEmpty() && account.account.isNotEmpty()) {
            "${account.issuer} · ${account.account}"
        } else {
            account.issuer.ifEmpty { account.account }
        }
        binding.accountNavRow.visibility = if (accounts.size > 1) View.VISIBLE else View.GONE
        binding.txtAccountCounter.text = getString(R.string.account_counter, selectedIndex + 1, accounts.size)
        binding.txtAccountLabel.text = label
        binding.txtTotpCode.text = code.chunked(3).joinToString(" ")
        binding.txtRemaining.text = getString(R.string.remaining_seconds, remaining)
        binding.progressPeriod.max = account.periodSeconds
        binding.progressPeriod.progress = remaining
        binding.cardCode.visibility = View.VISIBLE
    }

    private fun copyCurrentCode() {
        if (lastGeneratedCode.isEmpty()) return
        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val clip = ClipData.newPlainText("TOTP", lastGeneratedCode)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            clip.description.extras = PersistableBundle().apply {
                putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true)
            }
        }
        clipboard.setPrimaryClip(clip)
        Toast.makeText(this, getString(R.string.code_copied), Toast.LENGTH_SHORT).show()
    }

    private fun updateLockUi() {
        binding.panelLocked.visibility = if (unlocked) View.GONE else View.VISIBLE
        binding.panelUnlocked.visibility = if (unlocked) View.VISIBLE else View.GONE
    }
}
