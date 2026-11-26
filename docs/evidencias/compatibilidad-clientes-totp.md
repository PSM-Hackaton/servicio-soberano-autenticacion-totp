# Compatibilidad con Clientes TOTP Estándar (Issue #29 · D3)

El Servicio Soberano emite URIs conformes al estándar abierto **Key URI (`otpauth://totp/Issuer:Cuenta?secret=...&issuer=...&algorithm=...&digits=...&period=...`)** y códigos conformes a **RFC 6238 / RFC 4226**.

---

## 1. Matriz de Compatibilidad por Perfil Criptográfico

| Cliente Autenticador | Licencia / Tipo | SHA-256 / 6 dígitos (Por defecto) | SHA-512 / 8 dígitos (Alta seguridad) | SHA-1 / 6 dígitos (Modo compatibilidad) | Notas de verificación |
| :--- | :--- | :---: | :---: | :---: | :--- |
| **Autenticador Soberano PWA** (`/app/`) | GNU AGPL-3.0 (Propio) | ✅ Verificado (vectores RFC + E2E) | ✅ Verificado (vectores RFC + E2E) | ✅ Verificado (con aviso visual) | 100 % offline, bóveda cifrada por PIN, cero dependencias externas |
| **Aegis Authenticator** (v3.x, Android) | GPL-3.0 (Libre) | ✅ Compatible por especificación Key URI + RFC 6238 | ✅ Compatible (soporta SHA-512 y 8 dígitos) | ✅ Compatible | Escanea el QR SVG ISO/IEC 18004 o importa URI `otpauth://` |
| **FreeOTP+** (v2.x, Android) | Apache-2.0 (Libre) | ✅ Compatible por especificación Key URI + RFC 6238 | ✅ Compatible (soporta SHA-512 y 8 dígitos) | ✅ Compatible | Respeta `algorithm`, `digits` y `period` de la URI |
| **Google / Microsoft Authenticator** | Propietario | ⚠️ Ignoran `algorithm` (usan SHA-1) | ❌ Ignoran `algorithm` y/o `digits=8` | ✅ Compatible si `permitir_sha1=true` | Por esta limitación el servicio provee su propia PWA soberana |

> **Prueba automatizada de formato Key URI:** `authenticator-app/tests/otpauth.test.mjs` verifica automáticamente `buildOtpauthUri` del backend en los 3 perfiles (`SHA256/6`, `SHA512/8`, `SHA1/6`), validando codificación de etiqueta `issuer:cuenta`, Base32 sin relleno y parámetros obligatorios `secret`, `issuer`, `algorithm`, `digits` y `period`.

---

## 2. Política Recomendada por Aplicación (`permitir_sha1`)

1. **Política institucional por defecto (`SHA256`, 6 dígitos, `permitir_sha1: false`):** recomendada para todos los portales ciudadanos que despliegan el **Autenticador Soberano PWA** o apps libres compatibles (Aegis, FreeOTP+).
2. **Sistemas de alta sensibilidad (`SHA512`, 8 dígitos, `permitir_sha1: false`):** recomendada para el **Reto 1** y trámites administrativos críticos.
3. **Modo de compatibilidad heredado (`permitir_sha1: true`):** solo debe habilitarse por aplicación desde la Consola Administrativa (rol `Administrador`) cuando un grupo de usuarios dependa temporalmente de clientes comerciales que ignoran `algorithm=SHA256`, documentando el riesgo en la auditoría (`app.politica_actualizada`).
