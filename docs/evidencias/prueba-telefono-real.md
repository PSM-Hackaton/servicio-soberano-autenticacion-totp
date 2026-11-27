# Protocolo y Registro de Prueba en Teléfono Real (Issue #67 · G6)

Este documento complementa la verificación automatizada de formato Key URI (`authenticator-app/tests/otpauth.test.mjs`) y la matriz `docs/evidencias/compatibilidad-clientes-totp.md` con el procedimiento reproducible y la ficha de registro en un **dispositivo móvil físico** dentro de la red local.

---

## 1. Preparación en la red local (3 minutos)

1. Obtener la IP local del equipo que ejecuta el servicio (ejemplo: `ip -4 addr show | grep inet`).
2. Emitir certificado TLS con esa IP en SAN (README §6.6):
   ```bash
   cd backend
   TLS_SAN_IPS=<IP_LOCAL> npm run certs
   npm start
   ```
3. Iniciar el Portal de Trámites accesible en la LAN (`HOST=0.0.0.0 npm start` en `demo-portal-tramites/`).
4. Desde el teléfono conectado a la misma red Wi-Fi:
   - Abrir `https://<IP_LOCAL>:8443/instalar-certificado` y descargar `ca.crt` verificando su huella SHA-256.
   - Instalar el certificado CA en Android (*Ajustes → Seguridad → Cifrado y credenciales → Instalar certificado → Certificado de CA*) o iOS (*Perfil descargado → Confianza en certificados*).

---

## 2. Casos de prueba a registrar en dispositivo físico

| Caso | Flujo probado | Criterio de éxito | Estado |
| :--- | :--- | :--- | :---: |
| **T-01 · PWA instalada** | Abrir `https://<IP_LOCAL>:8443/app/`, instalar en pantalla de inicio, configurar PIN y activar modo avión | La app abre sin conexión y genera códigos TOTP válidos | `[ ] Pendiente físico` |
| **T-02 · Enrolamiento QR en Aegis / FreeOTP+** | Enrolar usuario demo en el portal (`V-10.000.001`), escanear QR SVG con **Aegis** o **FreeOTP+** | Cliente reconoce `issuer`, cuenta, `SHA256`, `6 dígitos` y `30 s` | `[ ] Pendiente físico` |
| **T-03 · Verificación cruzada en el portal** | Introducir en el Portal el código generado en el teléfono (Aegis/FreeOTP+ y PWA) | Portal valida JWT Ed25519 y concede acceso + *step-up* | `[ ] Pendiente físico` |
| **T-04 · Alta perfil SHA-512 / 8 dígitos** | Cambiar política del Portal a `SHA512 / 8 dígitos` y escanear nuevo QR | PWA y Aegis/FreeOTP+ generan el mismo código de 8 dígitos | `[ ] Pendiente físico` |

---

## 3. Ficha de evidencia física (completar al ejecutar con el teléfono)

- **Fecha y hora:** `YYYY-MM-DD HH:MM`
- **Modelo de teléfono:** _(ej. Xiaomi / Samsung / Pixel)_
- **Sistema operativo y navegador:** _(ej. Android 14 + Chrome / Firefox)_
- **Cliente TOTP estándar probado:** _(ej. Aegis v3.x / FreeOTP+ v2.x)_
- **Capturas adjuntas en `docs/evidencias/telefono-real/`:**
  - `01-pwa-instalada-offline.png`
  - `02-qr-escaneado-cliente-estandar.png`
  - `03-verificacion-exitosa-portal.png`

> **Nota de trazabilidad:** La interoperabilidad criptográfica de los 3 perfiles (`SHA256/6`, `SHA512/8`, `SHA1/6`) y la codificación QR SVG ISO/IEC 18004 están verificadas automáticamente en `backend/src/core/qr/qr.test.js`, `backend/src/core/totp/totp.test.js` y `authenticator-app/tests/otpauth.test.mjs`, y la vista móvil responsiva cuenta con capturas headless en `docs/evidencias/qa-navegador/`. Esta ficha registra exclusivamente la validación presencial en hardware móvil real.
