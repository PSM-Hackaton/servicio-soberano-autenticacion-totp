# ARCHITECTURE.md — Servicio Soberano de Autenticación TOTP

> **Alineación oficial:** Integra el análisis técnico aprobado en `docs/analisis/analisis-tecnico.html` (v1.2) con **Puertos Hexagonales** y **ADR-002 (stack 100 % propio y autoejecutable en Node.js 22 sin dependencias npm)**.

---

## 1. Decisiones Arquitectónicas (ADR)

### ADR-001: Modularización + Puertos Hexagonales
- **Decisión:** Conservar exactamente las carpetas definidas en el análisis técnico (`backend/src/core/{totp,vault,tokens,qr}`, `security/`, `heuristics/`, `audit/`, `api/`, `migrations/`, `authenticator-app/`, `admin-console/`, `sdk/`, `demo-portal-tramites/`, `attack-lab/`, `docs/`) e introducir `backend/src/application/{ports,use-cases}` + `backend/src/infrastructure/{persistence,config}` como capa de desacople.
- **Beneficio inmediato:**
  1. El motor RFC 6238 (`core/totp`), vault AES-256-GCM (`core/vault`), tokens Ed25519 (`core/tokens`) y QR (`core/qr`) son **100 % puros y testeables sin base de datos**.
  2. El punto de unión entre Área A (Diego) y Área B (Laya) es `contracts/openapi.yaml` + `contracts/mocks/`, permitiendo desarrollo paralelo y transición a la API real sin cambios de contrato.

### ADR-002: Stack Oficial — 100 % propio y autoejecutable (decisión del 26-11-2026)
- **Regla:** todo lo que se ejecuta lo escribimos nosotros. **Cero dependencias npm** en tiempo de ejecución y en pruebas. Solo módulos nativos de Node.js 22.
- **Lenguaje:** JavaScript moderno (ESM, `"type": "module"`), con comentarios JSDoc para tipos. Sin TypeScript (el Node de las estaciones no lo ejecuta sin paquetes externos).
- **Backend:** `node:https` (servidor y enrutador propios), `node:crypto` (TOTP, AES-256-GCM, Ed25519, scrypt, HMAC), JWT EdDSA propio (sin `jose`), `node:sqlite` (SQLite WAL nativo, sin `better-sqlite3` ni `pg`), `node:test` (pruebas).
- **Base de datos:** solo SQLite (`contracts/schema.sqlite.sql`). PostgreSQL y Docker quedan fuera: no están disponibles en las estaciones.
- **TLS:** Node HTTPS directo con certificado generado por `openssl` del sistema (`TLS_MODE=node`). Sin Caddy.
- **Frontends (`authenticator-app/`, `admin-console/`, `demo-portal-tramites/`):** HTML + CSS + JavaScript propios, servidos por nuestro servidor. Sin React, Vite ni CDNs. La PWA usa `manifest.json` + Service Worker propios y Web Crypto del navegador.
- **Código QR:** generador propio (`backend/src/core/qr/`); plan B: alta con clave manual Base32 y pegado de URI `otpauth://`.
- **Integración con Reto 1:** se registra como una `app` más (`client_id` + `client_secret`) y usa `sdk/`.

### ADR-003: Controles Criptográficos, de Integridad y Resiliencia
- **AES-256-GCM con AAD:** `AAD = enrollment_id + ":" + key_version` (previene trasplante de filas cifradas). En la PWA: PBKDF2-SHA256 (150.000 iteraciones) + AES-256-GCM en IndexedDB.
- **Anti-Replay SQL atómico:** `UPDATE enrollments SET last_step = $T, drift_steps = $drift WHERE id = $id AND last_step < $T` + consumo único de `jti` en `consumed_jti`.
- **Resiliencia *Fail-Closed*:** `/health/ready` y `/metrics` (formato Prometheus local); `503` si cae SQLite; `Idempotency-Key` en `/api/v1/verify`; SDK con timeout de 3 s + 1 reintento idempotente + validación offline de JWT con caché JWKS.
- **Anonimización:** `user_ref_hash = HMAC-SHA256(user_ref, USER_PEPPER)` y `ip_hash = HMAC-SHA256(ip, DAILY_IP_PEPPER)`.
- **Auditoría inmutable (`audit_log`):** Cadena de hashes `hash = SHA-256(prev_hash || ts || actor || accion || objetivo || detalle)` verificable desde `admin-console/`.
- **Trazabilidad:** SBOM CycloneDX 1.5 en `docs/sbom/sbom.cdx.json` declarando **0 dependencias npm de terceros**.

---

## 2. Flujo de Integración (Portal de Trámites & Reto 1)

```text
[App Integradora: Portal Trámites / Reto 1]
    |  (Auth: X-Client-Id + X-Client-Secret sobre TLS 1.3 + Idempotency-Key en verify)
    |
    +--> 1. POST /api/v1/enrollments              --> enrollment_id + QR SVG + otpauth:// (pendiente 10m)
    +--> 2. POST /api/v1/enrollments/:id/activate --> valida primer código -> ACTIVO + 10 códigos recuperación
    +--> 3. POST /api/v1/verify                   --> { user_ref, code } -> RFC 6238 + drift + anti-replay + IA local
    |                                                 --> JWT Ed25519 (5m, jti único, amr: ["otp"])
    +--> 4. POST /api/v1/tokens/validate          --> valida JWT y consume jti (o offline vía caché /.well-known/jwks.json)
```

---

## 3. Áreas de trabajo (Diego y Laya)

| Área | Responsable | Rama | Carpetas |
| :--- | :--- | :--- | :--- |
| **A — Núcleo y API** | Diego | `diego` | `backend/src/core/{totp,vault,tokens,qr}`, `backend/src/infrastructure/`, `backend/src/application/`, `backend/src/api/`, `backend/src/security/`, `backend/src/audit/`, `backend/src/heuristics/`, `backend/migrations/` |
| **B — Clientes, contratos e integración** | Laya | `laya` | `contracts/`, `sdk/`, `authenticator-app/`, `admin-console/`, `demo-portal-tramites/`, `attack-lab/`, `docs/sbom/`, `docs/GUION_DEMO.md`, documentos raíz |

**Punto de unión:** `contracts/openapi.yaml` y `contracts/mocks/`. Laya construye los clientes contra los mocks y un adaptador criptográfico standalone mientras Diego construye la API; al integrar en `staging` (Issue #16 C1), los clientes apuntan a `https://localhost:8443` sin cambios de contrato.

---

## 4. Comandos de Arranque y Verificación (Node.js 22, 0 dependencias)

```bash
# Backend (Área A — tras integrar en staging)
cp .env.example backend/.env
cd backend && npm test && npm start

# Clientes y Demo Interactiva (Área B — funciona hoy 100 % standalone)
node demo-portal-tramites/server.js

# Suites de pruebas del Área B
node --test authenticator-app/totp-core.test.js admin-console/admin-api.test.js sdk/sdk.test.js demo-portal-tramites/portal.test.js attack-lab/attack-lab.test.js

# Attack Lab + Pruebas de Caos (genera attack-lab/REPORTE_DEMO.md)
node attack-lab/run-all.js

# Smoke tests contra la API HTTPS
curl -k https://localhost:8443/health
curl -k https://localhost:8443/health/ready
curl -k https://localhost:8443/metrics
curl -k https://localhost:8443/.well-known/jwks.json
```
