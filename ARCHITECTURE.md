# ARCHITECTURE.md — Servicio Soberano de Autenticación TOTP

> **Alineación oficial:** Integra `docs/analisis/analisis-tecnico.html` (v1.2) con **Puertos Hexagonales** y **ADR-002 (stack 100 % propio y autoejecutable en Node.js 22.5+ sin dependencias npm)**.

---

## 1. Decisiones Arquitectónicas (ADR)

### ADR-001: Modularización + Puertos Hexagonales
- **Decisión:** Mantener separación estricta entre núcleo criptográfico puro (`backend/src/core/{totp,vault,tokens,qr}`), casos de uso (`backend/src/application/use-cases/`), seguridad (`backend/src/security/`), IA local (`backend/src/heuristics/`), auditoría (`backend/src/audit/`), persistencia (`backend/src/infrastructure/persistence/`) y capa HTTP/TLS (`backend/src/api/`).
- **Beneficio:** Cada módulo es 100 % testeable en aislamiento con `node:test`, sin red ni base externa.

### ADR-002: Stack Oficial — 100 % propio y autoejecutable (decisión del 26-11-2026)
- **Regla:** todo lo que se ejecuta lo escribimos nosotros. **Cero dependencias npm** en ejecución y pruebas. Solo módulos nativos de Node.js 22.5+.
- **Lenguaje:** JavaScript moderno (ESM, `"type": "module"`), con JSDoc para tipos.
- **Backend:** `node:https` (servidor TLS 1.3 y enrutador propios), `node:crypto` (TOTP, AES-256-GCM, Ed25519, scrypt, HMAC), JWT EdDSA propio, generador QR ISO/IEC 18004 + Reed-Solomon propio, `node:sqlite` (SQLite WAL nativa), `node:test`.
- **Base de datos:** SQLite única (`contracts/schema.sqlite.sql` / `backend/migrations/001_esquema.sql`). PostgreSQL y Docker quedan fuera.
- **TLS y Despliegue:** Node HTTPS directo con TLS 1.3 (`TLS_MODE=node`, certificados vía `openssl` o CA institucional) + unidad `systemd` endurecida en `deploy/servicio-totp.service`.
- **Frontends (`authenticator-app/`, `admin-console/`, `demo-portal-tramites/`):** HTML + CSS + JavaScript propios, sin React, Vite ni CDNs. El propio servidor backend sirve la PWA en `/app/` y la consola administrativa en `/consola/`.
- **Integración con Reto 1:** `backend/scripts/semilla.js` registra automáticamente la app `Reto 1`, integrable con `sdk/src/index.js` (ver `sdk/INTEGRACION_RETO1.md`).

### ADR-003: Controles Criptográficos, de Integridad y Resiliencia
- **AES-256-GCM con AAD:** `AAD = enrollment_id + ":" + key_version` + script `rotar-llave-maestra.js`.
- **Anti-Replay SQL atómico:** `UPDATE enrollments SET last_step = ?, drift_steps = ? WHERE id = ? AND last_step < ?` + tabla `consumed_jti` de clave primaria única.
- **Resiliencia *Fail-Closed*:** `/health`, `/health/ready`, `/metrics` (Prometheus) y `/admin/api/metrics` (JSON); `503` si cae SQLite; `Idempotency-Key` en `/api/v1/verify`; SDK con timeout 3 s + 1 reintento idempotente + validación offline de JWT vía caché JWKS.
- **Anonimización:** `user_ref_hash = HMAC-SHA256(user_ref, USER_PEPPER)` e `ip_hash = HMAC-SHA256(ip, DAILY_IP_PEPPER)`.
- **Auditoría inmutable (`audit_log`):** cadena SHA-256 verificable desde `GET /admin/api/audit/verify-chain`.
- **Trazabilidad:** SBOM CycloneDX 1.5 en `docs/sbom/sbom.cdx.json` con **0 dependencias npm de terceros**.

---

## 2. Flujo de Integración (Portal de Trámites & Reto 1)

```text
[App Integradora: Portal Trámites / Reto 1]
    |  (Auth: X-Client-Id + X-Client-Secret sobre TLS 1.3 + Idempotency-Key en verify)
    |
    +--> 1. POST /api/v1/enrollments              --> enrollment_id + QR SVG + otpauth:// (pendiente 10 min)
    +--> 2. POST /api/v1/enrollments/:id/activate --> valida primer código -> ACTIVO + 10 códigos recuperación
    +--> 3. POST /api/v1/verify                   --> RFC 6238 + deriva + anti-replay + bloqueos + Isolation Forest
    |                                                 --> JWT Ed25519 (5 min, jti único, amr: ["otp"])
    +--> 4. POST /api/v1/tokens/validate          --> valida JWT y consume jti (o offline vía caché /.well-known/jwks.json)
```

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
