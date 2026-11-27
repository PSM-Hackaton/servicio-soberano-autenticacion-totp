package ve.psmhackaton.totpsoberano

import android.content.Intent
import android.os.Bundle
import android.view.WindowManager
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageProxy
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.MultiFormatReader
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.common.HybridBinarizer
import ve.psmhackaton.totpsoberano.databinding.ActivityQrScannerBinding
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Escáner QR soberano basado en CameraX + ZXing Core (0 Google Play Services).
 * La cámara se libera automáticamente al cerrar o detectar el primer QR válido.
 */
class QrScannerActivity : FragmentActivity() {

    companion object {
        const val EXTRA_QR_RESULT = "extra_qr_result"
    }

    private lateinit var binding: ActivityQrScannerBinding
    private lateinit var cameraExecutor: ExecutorService
    private val detected = AtomicBoolean(false)

    private val qrReader = MultiFormatReader().apply {
        setHints(mapOf(DecodeHintType.POSSIBLE_FORMATS to listOf(BarcodeFormat.QR_CODE)))
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE,
        )
        binding = ActivityQrScannerBinding.inflate(layoutInflater)
        setContentView(binding.root)

        cameraExecutor = Executors.newSingleThreadExecutor()
        binding.btnCloseScanner.setOnClickListener {
            setResult(RESULT_CANCELED)
            finish()
        }
        startCamera()
    }

    private fun startCamera() {
        val providerFuture = ProcessCameraProvider.getInstance(this)
        providerFuture.addListener(
            {
                val cameraProvider = providerFuture.get()
                val preview = Preview.Builder().build().also {
                    it.setSurfaceProvider(binding.previewView.surfaceProvider)
                }
                val analysis = ImageAnalysis.Builder()
                    .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                    .build()
                    .also {
                        it.setAnalyzer(cameraExecutor) { imageProxy -> analyzeFrame(imageProxy) }
                    }
                try {
                    cameraProvider.unbindAll()
                    cameraProvider.bindToLifecycle(
                        this,
                        CameraSelector.DEFAULT_BACK_CAMERA,
                        preview,
                        analysis,
                    )
                } catch (_: Exception) {
                    setResult(RESULT_CANCELED)
                    finish()
                }
            },
            ContextCompat.getMainExecutor(this),
        )
    }

    private fun analyzeFrame(imageProxy: ImageProxy) {
        try {
            if (detected.get()) return
            val yPlane = imageProxy.planes.firstOrNull() ?: return
            val buffer = yPlane.buffer
            val data = ByteArray(buffer.remaining())
            buffer.get(data)

            val source = PlanarYUVLuminanceSource(
                data,
                imageProxy.width,
                imageProxy.height,
                0,
                0,
                imageProxy.width,
                imageProxy.height,
                false,
            )
            val bitmap = BinaryBitmap(HybridBinarizer(source))
            val result = qrReader.decodeWithState(bitmap)
            val text = result?.text?.trim().orEmpty()
            if (text.isNotEmpty() && detected.compareAndSet(false, true)) {
                runOnUiThread {
                    setResult(RESULT_OK, Intent().putExtra(EXTRA_QR_RESULT, text))
                    finish()
                }
            }
        } catch (_: Exception) {
            // Fotograma sin QR legible
        } finally {
            qrReader.reset()
            imageProxy.close()
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        cameraExecutor.shutdown()
    }
}
