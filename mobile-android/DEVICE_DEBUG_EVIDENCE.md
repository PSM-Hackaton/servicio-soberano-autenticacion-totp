# Evidencia de Depuración en Dispositivo Físico (ADB Pre-Fix QA)

> **Fecha:** 2026-11-27 · **Modo:** Solo diagnóstico (0 cambios de código)  
> **Artefactos crudos locales:** `/tmp/totp-adb-qa/` (`01_locked.png`, `ui_01.xml`, `02a_biometric_prompt.png`, `02_after_cancel.png`, `ui_02.xml`, `logcat_b.txt`, `meminfo.txt`, `services.txt`, `top_bg.txt`).

---

## 1. Ficha Real del Dispositivo de Prueba

| Parámetro | Valor Real (ADB) |
| :--- | :--- |
| **Fabricante / Modelo** | `motorola` · `motorola edge 50 fusion` (`ZY22KZG4QS`) |
| **Versión Android / API** | **Android 16 (API 36)** |
| **Resolución / Densidad** | `1080x2400` px · `400 dpi` |
| **Insets reales (`ROTATION_0`)** | `overrideNonDecorInsets=[0,94][0,60]` → **Barra de estado + cutout superior = `94 px`**, barra de navegación inferior = `60 px` |
| **Paquete instalado** | `ve.psmhackaton.totpsoberano` (`firstInstallTime=2026-11-27 13:27:04`) |
| **Permisos concedidos** | `INTERNET`, `USE_BIOMETRIC`, `USE_FINGERPRINT`, `DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION` (`CAMERA` declarada, no solicitada aún en runtime) |

---

## 2. Diagnóstico con Evidencia por Escenario

### Escenario A — Arranque y Solapamiento con Notch / Barra de Estado (**CONFIRMADO**)
- **Evidencia `uiautomator` (`ui_01.xml`):**
  ```text
  android:id/content                      | bounds=[0,0][1080,2400]
  TextView ("Autenticador Soberano TOTP") | bounds=[50,50][1030,114]
  id/txtStatus                            | bounds=[50,134][1030,175]
  id/btnUnlock                            | bounds=[50,235][1030,355]
  ```
- **Prueba matemática del solapamiento:**
  - En Android 15/16 (`targetSdk = 35`), el sistema fuerza **Edge-to-Edge** (`content` inicia en `y = 0`).
  - La barra de estado + cutout ocupa `0..94 px`, pero el título superior comienza en **`y = 50 px`** (`20 dp` de padding en `activity_main.xml` a `400 dpi` = `50 px`).
  - **Solapamiento real:** `94 - 50 = 44 px` invadiendo la barra de estado y el cutout frontal.
- **Código culpable:**
  - `mobile-android/app/src/main/res/layout/activity_main.xml:2-13` (sin `fitsSystemWindows` ni insets dinámicos).
  - `mobile-android/app/src/main/java/ve/psmhackaton/totpsoberano/MainActivity.kt:46-52` (no registra `ViewCompat.setOnApplyWindowInsetsListener` con `WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.displayCutout()`).

---

### Escenario B — Cancelación de Biometría
- **Evidencia `logcat` (`logcat_b.txt`):**
  ```text
  Biometrics/AcquisitionClient: onErrorInternal code: 5, finish: true
  BiometricStatusRepositoryImpl: authenticationState updated: Error(biometricSourceType=FINGERPRINT, errString=Fingerprint operation canceled, errCode=5)
  ```
- **Evidencia `uiautomator` (`ui_02.xml`):**
  ```text
  id/txtStatus   | text='Fingerprint operation canceled by user' | bounds=[50,134][1030,175]
  id/panelLocked | bounds=[50,235][1030,355]
  id/btnUnlock   | text='DESBLOQUEAR CON BIOMETRÍA' | bounds=[50,235][1030,355]
  ```
- **Resultado:**
  - **Seguridad OK:** La bóveda **permaneció bloqueada** tras cancelar (`panelUnlocked` oculto, no expuso `AGREGAR CUENTA TOTP`).
  - **Hallazgo UX:** `MainActivity.kt:126` (`binding.txtStatus.text = errString`) muestra el mensaje técnico del SO en inglés (`"Fingerprint operation canceled by user"`) en lugar de un texto limpio en español mapeado por `errorCode` (`ERROR_USER_CANCELED` / `ERROR_NEGATIVE_BUTTON`).

---

### Escenario C — Flujo "AGREGAR CUENTA TOTP" (Auditoría Estática + UI)
- Al estar protegida por biometría real, la pantalla desbloqueada requiere huella física para interactuar en vivo.
- **Hallazgos confirmados en código (`MainActivity.kt:139-165` y `activity_main.xml:48-65`):**
  1. **Sin persistencia cifrada:** `addAccountFromInput()` guarda `activeAccount` solo en memoria RAM; al cerrar la app se pierde la cuenta y no usa aún `KeystoreVault.encryptSeedWithCipher()` contra `SharedPreferences`/almacenamiento local.
  2. **Feedback pobre al pulsar vacío:** Si se toca `btnAddAccount` con `inputOtp` vacío, solo actualiza `txtStatus` arriba (sin `inputOtp.error` ni foco visual), dando la sensación de que el botón "no hace nada".
  3. **Sin escáner QR conectado:** `CAMERA` está declarada en `AndroidManifest.xml:4`, pero no hay botón ni flujo de cámara QR aún.

---

### Escenario D — Recursos, RAM y Cero Segundo Plano (**APROBADO**)
- **Memoria en primer plano (`meminfo.txt`):**
  - `TOTAL PSS`: **15,638 KB (~15.3 MB)** (`Native Heap: 6.1 MB`, `Dalvik Heap: 1.2 MB`). Consumo excelente para teléfonos de gama baja.
- **Servicios en segundo plano (`services.txt`):** `(nothing)` — **0 servicios activos**.
- **CPU en segundo plano 5 s tras `KEYCODE_HOME` (`top_bg.txt`):**
  ```text
  19204 u0_a442  20  0  14G 125M 88M S  0.0  1.6  0:00.70 ve.psmhackaton.totpsoberano
  ```
  **`0.0 % CPU`**, estado `S` (dormido). Cumple estrictamente el estándar de cero ejecución en segundo plano.

---

## 3. Plan Exacto de Corrección Técnica (Listo para Siguiente Enjambre)

1. **Corregir Edge-to-Edge / Notch (`MainActivity.kt` + `activity_main.xml`):**
   - Aplicar `ViewCompat.setOnApplyWindowInsetsListener(binding.root)` sumando `insets.getInsets(WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.displayCutout())` al padding superior/inferior del contenedor principal.
2. **Localizar errores de `BiometricPrompt` (`MainActivity.kt:125-127`):**
   - Mapear `BiometricPrompt.ERROR_USER_CANCELED`, `ERROR_NEGATIVE_BUTTON` y `ERROR_CANCELED` a mensajes claros en español (`strings.xml`).
3. **Mejorar flujo y persistencia de "Agregar cuenta TOTP":**
   - Mostrar error directo en `inputOtp.error` cuando el campo esté vacío o inválido.
   - Persistir cuentas cifradas en almacenamiento local usando `KeystoreVault.encryptSeedWithCipher` / `decryptSeedWithCipher` (con soporte multi-cuenta).
