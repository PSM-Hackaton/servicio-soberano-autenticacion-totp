package ve.psmhackaton.totpsoberano

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.PersistableBundle
import android.view.View
import android.view.WindowManager
import android.widget.Toast
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import ve.psmhackaton.totpsoberano.core.OtpAuthParser
import ve.psmhackaton.totpsoberano.core.TotpEngine
import ve.psmhackaton.totpsoberano.databinding.ActivityMainBinding
import ve.psmhackaton.totpsoberano.security.KeystoreVault

/**
 * Pantalla principal del Autenticador Soberano TOTP.
 * - Protección FLAG_SECURE contra capturas de pantalla.
 * - Desbloqueo biométrico con BiometricPrompt.CryptoObject (Android 8+ y 11+ / API 30+).
 * - Cero ejecución en segundo plano: el temporizador solo corre entre onResume() y onPause().
 */
class MainActivity : FragmentActivity() {

    private lateinit var binding: ActivityMainBinding
    private val vault = KeystoreVault()
    private val handler = Handler(Looper.getMainLooper())

    private var unlocked = false
    private var activeAccount: OtpAuthParser.OtpAccountSpec? = null
    private var activeSecretBytes: ByteArray? = null
    private var lastGeneratedCode: String = ""

    private val tickRunnable = object : Runnable {
        override fun run() {
            if (!unlocked) return
            renderActiveCode()
            handler.postDelayed(this, 500L)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE,
        )
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        binding.btnUnlock.setOnClickListener { startBiometricUnlock() }
        binding.btnAddAccount.setOnClickListener { addAccountFromInput() }
        binding.btnCopyCode.setOnClickListener { copyCurrentCode() }

        updateLockUi()
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

        val cipherResult = vault.createEncryptCipher()
        val cipher = when (cipherResult) {
            is KeystoreVault.VaultResult.Success -> cipherResult.value
            is KeystoreVault.VaultResult.KeyInvalidated -> {
                vault.wipeMasterKey()
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
                    unlocked = true
                    updateLockUi()
                    if (activeSecretBytes != null) {
                        renderActiveCode()
                        handler.removeCallbacks(tickRunnable)
                        handler.postDelayed(tickRunnable, 500L)
                    }
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    binding.txtStatus.text = errString
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

    private fun addAccountFromInput() {
        val raw = binding.inputOtp.text?.toString()?.trim().orEmpty()
        if (raw.isEmpty()) {
            binding.txtStatus.text = getString(R.string.status_input_empty)
            return
        }
        try {
            val spec = if (raw.lowercase().startsWith("otpauth://")) {
                OtpAuthParser.parse(raw)
            } else {
                val decoded = TotpEngine.decodeBase32(raw)
                require(decoded.size >= 16) { "Semilla demasiado corta (mínimo 128 bits)" }
                OtpAuthParser.OtpAccountSpec(
                    issuer = getString(R.string.default_issuer),
                    account = getString(R.string.default_account),
                    secretBase32 = raw.uppercase(),
                    algorithm = TotpEngine.Algorithm.SHA256,
                    digits = 6,
                    periodSeconds = 30,
                )
            }
            activeAccount = spec
            activeSecretBytes = TotpEngine.decodeBase32(spec.secretBase32)
            binding.inputOtp.text?.clear()
            binding.txtStatus.text = getString(R.string.status_account_ready)
            renderActiveCode()
            handler.removeCallbacks(tickRunnable)
            handler.postDelayed(tickRunnable, 500L)
        } catch (e: Exception) {
            binding.txtStatus.text = e.message ?: getString(R.string.status_invalid_input)
        }
    }

    private fun renderActiveCode() {
        val account = activeAccount ?: return
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
