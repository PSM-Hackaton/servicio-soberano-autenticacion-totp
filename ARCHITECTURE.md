# ARCHITECTURE.md — Servicio Soberano de Autenticación TOTP

> **Alineación oficial:** Integra `docs/analisis/analisis-tecnico.html` (v1.2) con **arquitectura modular en capas** y **ADR-002 (stack 100 % propio y autoejecutable en Node.js 22.5+ sin dependencias npm)**.

---

## 1. Decisiones Arquitectónicas (ADR)

### ADR-001: Arquitectura Modular por Capas
- **Decisión:** Mantener separación estricta entre núcleo criptográfico puro (`backend/src/core/{totp,vault,tokens,qr}`), casos de uso (`backend/src/application/use-cases/`), seguridad (`backend/src/security/`), IA local (`backend/src/heuristics/`), auditoría (`backend/src/audit/`), persistencia (`backend/src/infrastructure/persistence/`) y capa HTTP/TLS (`backend/src/api/`).
- **Beneficio:** Cada módulo es 100 % testeable en aislamiento con `node:test`, sin red ni base externa.

### ADR-002: Stack Oficial — 100 % propio y autoejecutable (decisión del 26-11-2026)
- **Regla:** todo lo que se ejecuta lo escribimos nosotros. **Cero dependencias npm** en ejecución y pruebas. Solo módulos nativos de Node.js 22.5+.
- **Lenguaje:** JavaScript moderno (ESM, `"type": "module"`), con JSDoc para tipos.
- **Backend:** `node:https` (servidor TLS 1.3 y enrutador propios), `node:crypto` (TOTP, AES-256-GCM, Ed25519, scrypt, HMAC), JWT EdDSA propio, generador QR ISO/IEC 18004 + Reed-Solomon propio, `node:sqlite` (SQLite WAL nativa), `node:test`.
- **Base de datos:** SQLite única (`contracts/schema.sqlite.sql` / `backend/migrations/001_esquema.sql`). PostgreSQL y Docker quedan fuera.
- **TLS y Despliegue:** Node HTTPS directo con TLS 1.3 (`TLS_MODE=node`, certificados vía `openssl` o CA institucional) + unidad `systemd` endurecida en `deploy/servicio-totp.service`.
- **Frontends (`authenticator-app/`, `admin-console/`, `demo-portal-tramites/`):** HTML + CSS + JavaScript propios, sin React, Vite ni CDNs. El propio servidor backend sirve la PWA en `/app/` y la consola administrativa en `/consola/`.
- **Integración con Reto 3:** `backend/scripts/semilla.js` registra automáticamente la app `Agente Evaluador (Reto 3)`, integrable con `sdk/src/index.js` (ver `sdk/INTEGRACION_RETO3.md`).

### ADR-003: Controles Criptográficos, de Integridad y Resiliencia
- **AES-256-GCM con AAD:** `AAD = enrollment_id + ":" + key_version` + script `rotar-llave-maestra.js`.
- **Anti-Replay SQL atómico:** `UPDATE enrollments SET last_step = ?, drift_steps = ? WHERE id = ? AND last_step < ?` + tabla `consumed_jti` de clave primaria única.
- **Resiliencia *Fail-Closed*:** `/health`, `/health/ready`, `/metrics` (Prometheus) y `/admin/api/metrics` (JSON); `503` si cae SQLite; `Idempotency-Key` en `/api/v1/verify`; SDK con timeout 3 s + 1 reintento idempotente + validación offline de JWT vía caché JWKS.
- **Anonimización:** `user_ref_hash = HMAC-SHA256(user_ref, USER_REF_PEPPER)` e `ip_hash = HMAC-SHA256(ip, DAILY_IP_PEPPER_SEED + fecha)`.
- **Auditoría inmutable (`audit_log`):** cadena SHA-256 verificable desde `GET /admin/api/audit/verify-chain`.
- **Trazabilidad:** SBOM CycloneDX 1.5 en `docs/sbom/sbom.cdx.json` con **0 dependencias npm de terceros**.

### ADR-004: Plataforma de la App Móvil del Autenticador Soberano (Issue #39 · M0)
- **Contexto:** Además de la PWA offline (`authenticator-app/`), los dispositivos móviles ciudadanos requieren protección en hardware para las semillas TOTP, bloqueo biométrico y distribución sin depender de Google Play ni App Store.
- **Alternativas evaluadas:**
  1. **Android nativo en Kotlin (sin librerías de terceros):** utiliza **Android Keystore / StrongBox** (llaves AES-256-GCM no exportables respaldadas por hardware), `javax.crypto` (HMAC-SHA256/512/1 estándar), `Camera2` nativo, `BiometricPrompt`, `FLAG_SECURE` y `android:allowBackup="false"`. Distribución directa mediante APK firmado desde el servidor institucional (`https://<servidor>:8443/descargas/`) y F-Droid.
  2. **PWA empaquetada (Trusted Web Activity / WebView):** reutiliza `authenticator-app/` con menor esfuerzo inicial, pero el almacenamiento en IndexedDB depende del motor del navegador sin aislamiento en StrongBox/TEE ni garantías nativas de `FLAG_SECURE`.
- **Decisión:** **Opción 1 — Android nativo en Kotlin sin dependencias propietarias** (carpeta `mobile-android/`, licencia GNU AGPL-3.0-or-later), manteniendo la PWA (`authenticator-app/`) como alternativa universal multiplataforma (iOS, escritorio y equipos sin APK).
- **Riesgos y mitigación:**
  - *Dispositivos sin StrongBox:* degradación automática a TEE de Android Keystore con `setUserAuthenticationRequired(true)`.
  - *Fragmentación de cámaras:* escaneo con `Camera2` + plan B de pegado de URI `otpauth://` y clave manual Base32.
  - *Soberanía:* 0 SDKs de Google/Firebase, 0 analítica, compilación reproducible con OpenJDK + Gradle + Android SDK libre y publicación del SHA-256 del APK en el SBOM.

---

## 2. Flujo de Integración (Portal de Trámites & Reto 3)

```text
[App Integradora: Portal Trámites / Reto 3]
    |  (Auth: X-Client-Id + X-Client-Secret sobre TLS 1.3 + Idempotency-Key en verify)
    |
    +--> 1. POST /api/v1/enrollments              --> enrollment_id + QR SVG + otpauth:// (pendiente 10 min)
    +--> 2. POST /api/v1/enrollments/:id/activate --> valida primer código -> ACTIVO + 10 códigos recuperación
    +--> 3. POST /api/v1/verify                   --> RFC 6238 + deriva + anti-replay + bloqueos + Isolation Forest
    |                                                 --> JWT Ed25519 (5 min, jti único, amr: ["otp"])
    +--> 4. POST /api/v1/tokens/validate          --> valida JWT y consume jti (o offline vía caché /.well-known/jwks.json)
```

Consola: `POST /admin/api/login` (contraseña + TOTP) emite la cookie `sst_admin` (`HttpOnly; Secure; SameSite=Strict; Path=/admin`, 30 min deslizantes, tope 8 h) y un `csrf_token` que se envía en `X-CSRF-Token` en cada petición que modifica. RBAC: `Administrador` (todo), `Operador` (apps, enrolamientos, inventario de llaves, anomalías, métricas), `Auditor` (auditoría, verificación de cadena, inventario de llaves, anomalías, métricas). El inventario de llaves (`GET /admin/api/keys`, acción `llaves.leer`) solo muestra `kid`, estado y fechas; rotar (`llaves.rotar`) es exclusivo del Administrador.

Gestión desde la consola (#21): el Administrador y el Operador suspenden, reactivan y revocan enrolamientos (`enrolamientos.gestionar`; activo ↔ suspendido, activo | suspendido → revocado, final; un suspendido responde en verify igual que un código incorrecto). Solo el Administrador regenera el `client_secret` de una app (`apps.secreto`, invalida la caché de autenticación de apps) y gestiona las cuentas de la consola (`admins.leer` / `admins.escribir`). Una cuenta nueva recibe contraseña aleatoria y TOTP propio en la app interna "Consola Administrativa", activado en el mismo acto (misma función que la semilla, `use-cases/administradores.js`): así nunca existe una cuenta con solo contraseña ni un enrolamiento pendiente que caduque; contraseña, URI y QR se entregan una vez y el primer login demuestra que el factor quedó instalado. No se puede deshabilitar la propia cuenta ni al último Administrador activo, y deshabilitar cierra sus sesiones.

Cédula de identidad (ADR, #21): el contrato de integradores no cambia, `user_ref` sigue siendo opaco y la cédula nunca se guarda en claro. Para que el soporte pueda buscar el factor de un ciudadano por cédula, cada app declara `user_ref_desde_cedula`: `ninguno` (por defecto; el soporte busca por `user_ref` exacto) o `hmac`, en cuyo caso la app deriva `user_ref = prefijo + base64url(HMAC-SHA256(cédula canónica, secreto))` con el SDK (`derivarUserRefDesdeCedula`) y comparte el secreto con el servicio al registrarse (lo genera el servicio y lo entrega una vez, o lo aporta la app). El secreto se guarda cifrado con la bóveda (AAD `cedula:<app_id>`, incluido en la rotación de la llave maestra). `GET /admin/api/enrollments?app_id=…&cedula=V-12.345.678` normaliza la cédula (`core/identidad/cedula.js`, copia idéntica en `sdk/src/cedula.js`), recalcula el `user_ref` y busca por `user_ref_hash`; cada búsqueda se audita solo con `HMAC-SHA256('cedula:' + canónica, USER_REF_PEPPER)`. Se eligió HMAC con secreto por app (y no un hash sin clave) porque el espacio de cédulas es pequeño y un hash sin secreto se invierte por fuerza bruta en segundos.

---

## 3. Áreas de trabajo (Unificadas en rama `laya` listas para PR → `staging`)

| Área | Responsable | Carpetas | Estado |
| :--- | :--- | :--- | :--- |
| **A — Núcleo y API** | Diego | `backend/` (`core/{totp,vault,tokens,qr}`, `infrastructure/`, `application/`, `api/`, `security/`, `audit/`, `heuristics/`, `migrations/`, `scripts/`) | Completado y verificado |
| **B — Clientes, contratos, laboratorio y entrega** | Laya + Diego | `contracts/`, `authenticator-app/`, `admin-console/`, `sdk/`, `demo-portal-tramites/`, `attack-lab/`, `deploy/`, `docs/sbom/`, `docs/GUION_DEMO.md`, documentos raíz | Completado y verificado |

---

## 4. Comandos de Arranque y Verificación (Node.js 22.5+, 0 dependencias)

```bash
# 1. Preparar y arrancar el backend HTTPS TLS 1.3 (sirve API + /app/ + /consola/)
cd backend
npm run env && npm run certs && npm run seed
npm test && npm start

# 2. Pruebas de clientes, SDK, Portal Demo y Attack Lab
node --test authenticator-app/tests/*.test.mjs
node --test sdk/tests/sdk.test.js demo-portal-tramites/tests/portal.test.js
cd attack-lab && npm test

# 3. Smoke tests contra la API HTTPS
curl --cacert backend/certs/ca.crt https://localhost:8443/health/ready
curl --cacert backend/certs/ca.crt https://localhost:8443/.well-known/jwks.json
```
