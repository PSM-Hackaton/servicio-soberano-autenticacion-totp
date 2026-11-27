# Plan de Trabajo Final y Reporte de QA en Vivo (ADB + Localhost)

> **Fecha:** 2026-11-27 · **Dispositivo físico:** Motorola Edge 50 Fusion (`ZY22KZG4QS`, Android 16 / API 36, `1080x2400`)  
> **Entorno local:** Backend TOTP (`https://localhost:8443`), Portal de Trámites (`https://localhost:8444`), `adb reverse` activo en `8443` y `8444`.  
> *(Por seguridad, cualquier semilla real de prueba se redacta como `[ADMIN_SEED_REDACTED]`).*

---

## 1. Resumen Ejecutivo de QA en Vivo (ADB + Localhost)

| Prueba | Entorno | Resultado | Evidencia Real |
| :--- | :--- | :---: | :--- |
| **Conexión USB + `adb reverse`** | ADB (`ZY22KZG4QS`) | **PASS** | `adb reverse tcp:8443 tcp:8443` y `8444` activos |
| **Sincronización de reloj (PC vs. Teléfono)** | UTC (`date -u +%s`) | **PASS** | `DRIFT_SEC = 0 s` (tolerancia TOTP: ±30 s) |
| **Salud Backend (`/health` y `/health/ready`)** | `https://localhost:8443` | **PASS** | `{"status":"ok","dbDriver":"sqlite","database":"ok"}` |
| **Portal de Trámites (`/enrolar`)** | `https://localhost:8444` | **PASS** | Con `NODE_EXTRA_CA_CERTS=../backend/certs/ca.crt` genera QR + semilla Base32 |
| **Pruebas automatizadas PWA** | `node --test` | **PASS** | **26/26** pruebas en verde (`0` fallos) |
| **UI Android (Notch / Edge-to-Edge)** | ADB (`uiautomator`) | **PASS** | `tricolorBar` en `y = 94 px`, `txtAppTitle` en `y = 147 px` (**0 px solapamiento**) |
| **Cancelación biometría Android** | ADB (`uiautomator`) | **PASS** | Mensaje en español, bóveda permanece bloqueada |
| **Estabilidad y Segundo Plano Android** | ADB (`logcat`/`services`) | **PASS** | `0` crashes (`AndroidRuntime`), `(nothing)` servicios, `0.0 %` CPU en fondo |
| **Escáner QR en App Android** | `mobile-android/` | **FAIL (Pendiente)** | Solo soporta ingreso manual Base32 / `otpauth://`; no tiene cámara QR |
| **Multi-cuenta en App Android** | `MainActivity.kt:219` | **FAIL (Limitación)** | `repository.saveAccounts(listOf(spec))` sobrescribe la cuenta anterior |

---

## 2. Causa Raíz del Fallo del Código de Administrador

1. **Paridad criptográfica verificada (NO es bug de Base32 ni de algoritmo):**
   - La semilla de administrador (`[ADMIN_SEED_REDACTED]`, 52 caracteres Base32 sin `====` → 32 bytes exactos) decodifica idénticamente en `backend/src/core/totp/base32.js`, `authenticator-app/js/totp.js` y `mobile-android/.../TotpEngine.kt:31-50` (`trimEnd('=')` + acumulador de 5 bits).
   - Ambos lados usan `HmacSHA256`, `6 dígitos`, `30 s` y `DRIFT_SEC = 0 s`.
2. **Causa real observada en pruebas:**
   - En la Consola Administrativa (`admin_seguridad`), el código falló porque **la cuenta de administrador no estaba agregada** en la app móvil (y si se agrega después de una cuenta ciudadana, **`MainActivity.kt:219`** hace `repository.saveAccounts(listOf(spec), ...)`, guardando una sola cuenta y sobrescribiendo la anterior).
   - **Fix puntual si se mantiene la App Android:** Cambiar `activeAccount` por una lista persistida (`accounts: MutableList<OtpAccountSpec>`) con `RecyclerView` o selector de cuentas para soportar simultáneamente `admin_seguridad` + cuentas ciudadanas.

---

## 3. Evaluación Técnica del Escáner QR en Android

- **Payload del QR del Portal:** URI estándar `otpauth://totp/<issuer>:<cuenta>?secret=<BASE32>&issuer=<issuer>&algorithm=SHA256&digits=6&period=30` (ya soportado al 100 % por `OtpAuthParser.kt`).
- **Permiso:** `android.permission.CAMERA` ya está declarado en `AndroidManifest.xml:4`; falta solo `ActivityResultContracts.RequestPermission()` en runtime.
- **Comparativa de implementación:**
  - *Google Code Scanner / ML Kit:* **Descartado** por ADR-004 (exige Google Play Services; rompe soberanía tecnológica).
  - **Solución recomendada (100 % soberana y ligera):** **CameraX (`camera-core`, `camera-camera2`, `camera-lifecycle`, `camera-view`) + ZXing `com.google.zxing:core:3.5.3`** (Java puro, ~550 KB, 0 Google Play Services, compila directo en GitHub Actions).
  - **Archivos a tocar:** `app/build.gradle.kts`, `QrScannerActivity.kt` (nuevo), `activity_qr_scanner.xml` (nuevo), `AndroidManifest.xml`, `MainActivity.kt` (botón «Escanear QR»). **Esfuerzo:** ~30–45 min.

---

## 4. Matriz de Decisión: Opción 1 vs. Opción 2

| Criterio | Opción 1 — Quitar App Mobile (Solo PWA Web `/app/`) | Opción 2 — Quitar Autenticador Web (Solo App Android) |
| :--- | :--- | :--- |
| **Fricción de instalación** | **0 fricción** (abre en cualquier navegador Android/iOS, instalable como PWA, **264 KB**) | Requiere descargar e instalar APK manualmente (solo Android; deja fuera iOS) |
| **Escáner QR** | **Ya funciona** (`escaner.js` con `BarcodeDetector` nativo) + enlace directo `#add=` desde el portal | **Falta implementar** (CameraX + ZXing) |
| **Multi-cuenta y respaldos** | **100 % completo** (múltiples cuentas, PIN PBKDF2 310k, respaldo cifrado export/import, 26/26 tests) | Requiere agregar multi-cuenta (`RecyclerView`) |
| **Seguridad hardware** | Web Crypto AES-256-GCM + IndexedDB (muy sólida, sin Keystore hardware) | **Superior:** `AndroidKeyStore` / StrongBox + `BiometricPrompt.CryptoObject` + `FLAG_SECURE` |
| **Riesgo para la entrega final** | **Muy bajo** (ya probada al 100 % en `verificar-todo.js` y QA real) | **Medio** (requiere tocar rutas `/app/`, pruebas del backend/portal y agregar QR + multi-cuenta en APK) |

### Recomendación Técnica Directa
- **Para entrega inmediata y máxima estabilidad (demo + evaluación):** **Opción 1 (conservar la PWA `/app/` como cliente principal en producción)**, ya que está 100 % completa (QR, multi-cuenta, offline, 26/26 tests, iOS + Android) y no arriesga romper ninguna prueba del backend/portal. *(Opcionalmente se puede dejar `mobile-android/` documentado como módulo nativo complementario sin eliminar el autenticador web, o retirarlo si deseas cero duplicidad).*
- **Solo elige Opción 2** si quieres invertir ~1 hora adicional en agregar **CameraX + ZXing + multi-cuenta** a la APK y actualizar las rutas/tests que hoy referencian `/app/`.

---

## 5. Plan de Trabajo Final (Según tu Elección)

### Si eliges Opción 1 (Quitar App Mobile → Solo PWA `/app/`)
1. Eliminar `mobile-android/` y `.github/workflows/android-apk-build.yml`.
2. Actualizar `README.md` y referencias en docs para dejar la PWA `/app/` como único autenticador oficial.
3. Ejecutar `node scripts/verificar-todo.js` (confirmar TODO VERDE) y subir commit limpio a GitHub + GitLab.

### Si eliges Opción 2 (Quitar Autenticador Web → Solo App Android)
1. Agregar **multi-cuenta** en `MainActivity.kt` + `AccountRepository.kt` (para tener ciudadano + `admin_seguridad` sin sobrescribirse).
2. Integrar **escáner QR soberano** (CameraX + ZXing `core`, 0 Google Play Services) conectado a `OtpAuthParser.kt`.
3. Retirar `authenticator-app/` y ajustar rutas `/app/` en `backend/` y pruebas en `scripts/verificar-todo.js`.
4. Compilar APK en GitHub Actions, instalar por `adb install -r` en el Motorola Edge 50 Fusion y validar flujo completo con QR real.
