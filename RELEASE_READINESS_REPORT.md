# Release Readiness Report — Autenticador Soberano TOTP (Móvil)

> **Fecha:** 2026-11-27 · **Repositorio:** `servicio-soberano-autenticacion-totp` · **Rama:** `fix/mobile-android-release-ready` (base: `staging`)  
> **Alcance:** Módulo Android nativo (`mobile-android/`) + PWA móvil en producción (`authenticator-app/`).

---

## 1. Veredicto Ejecutivo (Go / No-Go)

| Componente | Veredicto | Madurez Real | Estado Actual |
| :--- | :---: | :---: | :--- |
| **APK Nativa Android (`mobile-android/`)** | **LISTO PARA BUILD EN CI** | **85 %** | Proyecto Gradle completo (AGP 8.7.2, Kotlin 2.0.21, `minSdk 26`, `targetSdk 35`, R8/ProGuard), `KeystoreVault.kt` corregido con `BiometricPrompt.CryptoObject` para Android 11+ (API 30+), `MainActivity` con `FLAG_SECURE` y cero ejecución en segundo plano, pruebas JUnit 4 y workflow de GitHub Actions listo para compilar la APK. Pendiente únicamente verificación del primer build en GitHub Actions e inyección del keystore institucional en Secrets. |
| **PWA Móvil Soberana (`authenticator-app/`)** | **GO** | **98 %** | 264 KB totales, 100 % offline (`sw.js`), timeout HTTP de 6 s (`AbortController`) en `/health`, suspensión total del timer de 250 ms en `document.hidden` / `pagehide`, y **26/26 pruebas unitarias pasando**. |

---

## 2. Ficha Técnica de Compatibilidad (Agente 1 — Release & Packaging)

- **`applicationId` / `namespace`:** `ve.psmhackaton.totpsoberano`
- **SDKs:** `minSdk = 26` (Android 8.0+, >95 % dispositivos activos), `compileSdk = 35`, `targetSdk = 35`.
- **Optimización Release:** `isMinifyEnabled = true`, `isShrinkResources = true`, `proguard-rules.pro` preservando `core.**` y `security.**` y eliminando `Log.v`/`Log.d`.
- **Dependencias mínimas:** `androidx.core:core-ktx`, `androidx.appcompat`, `androidx.biometric`, `com.google.android.material` (cero Google Play Services, cero Firebase, cero telemetría).
- **Firma Release:** Configurada vía variables de entorno (`ANDROID_KEYSTORE_PATH`, `ANDROID_KEYSTORE_PASSWORD`, `ANDROID_KEY_ALIAS`, `ANDROID_KEY_PASSWORD`) con fallback limpio a firma `debug` en CI si los secrets aún no están definidos.

---

## 3. Rendimiento, Segundo Plano y APIs (Agente 2)

- **Cero ejecución en segundo plano:**
  - `MainActivity.kt`: el `Handler` de refresco TOTP solo corre entre `onResume()` y `onPause()`/`onStop()`. Cero `Service`, `WorkManager`, `AlarmManager` o `BroadcastReceiver`.
  - `authenticator-app/js/app.js`: el `setInterval` de 250 ms se detiene con `clearInterval` en `document.hidden` y `pagehide`.
- **APIs y escalabilidad:**
  - `GET /health` (`authenticator-app/js/app.js`): solo bajo demanda del usuario, con `AbortController` de **6 s**, `cache: 'no-store'`, `credentials: 'omit'`.
  - Generación TOTP **100 % local offline** en ambas plataformas (0 carga al servidor ante uso masivo).

---

## 4. Permisos, Seguridad y Estabilidad (Agente 3)

- **Permisos en `AndroidManifest.xml`:** `CAMERA` (`required="false"`), `INTERNET`, `USE_BIOMETRIC` (mínimo privilegio).
- **Banderas de seguridad:** `allowBackup="false"`, `fullBackupContent="false"`, `usesCleartextTraffic="false"`, `FLAG_SECURE` en `MainActivity`, `ClipDescription.EXTRA_IS_SENSITIVE = true` al copiar códigos en API 33+.
- **Bloqueante crítico resuelto (`KeystoreVault.kt`):**
  - `setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)` en API 30+ (fallback a `-1` en API 26–29).
  - Flujo `createEncryptCipher()` / `createDecryptCipher(iv)` → `BiometricPrompt.CryptoObject(cipher)` → `encryptSeedWithCipher` / `decryptSeedWithCipher`.
  - Manejo seguro sin crashes de `KeyPermanentlyInvalidatedException`, `UserNotAuthenticatedException` y biometría no configurada mediante `VaultResult`.

---

## 5. Instrucciones en 3 Pasos para Diego (Keystore de Producción en GitHub Secrets)

1. **Generar el keystore institucional localmente** (nunca subir el `.jks` a Git):
   ```bash
   keytool -genkeypair -v -keystore totp-release.jks -keyalg RSA -keysize 4096 -validity 10000 -alias totp_soberano
   ```
2. **Codificar el archivo en Base64:**
   ```bash
   base64 -w 0 totp-release.jks > totp-release.b64
   ```
3. **Configurar los 4 Secrets en GitHub** (*Settings → Secrets and variables → Actions*):
   - `ANDROID_KEYSTORE_BASE64`: contenido de `totp-release.b64`
   - `ANDROID_KEYSTORE_PASSWORD`: contraseña del keystore
   - `ANDROID_KEY_ALIAS`: `totp_soberano`
   - `ANDROID_KEY_PASSWORD`: contraseña de la clave
