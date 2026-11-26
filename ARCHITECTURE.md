# ARCHITECTURE.md — Servicio Soberano de Autenticación TOTP

> **Alineación oficial:** Integra el análisis técnico aprobado en `docs/analisis/analisis-tecnico.html` (commit `95c0fbd` en `main`) con **Puertos y Adaptadores Hexagonales** para habilitar ejecución paralela inmediata y compatibilidad dual **Docker/PostgreSQL 16** + **Sin Docker/SQLite WAL**.

---

## 1. Decisiones Arquitectónicas (ADR)

### ADR-001: Modularización de `main` + Puertos Hexagonales
- **Decisión:** Conservar exactamente las carpetas definidas en `docs/analisis/analisis-tecnico.html` (`backend/src/core/{totp,vault,tokens}`, `security/`, `heuristics/`, `audit/`, `api/`, `migrations/`, `authenticator-app/`, `admin-console/`, `sdk/`, `demo-portal-tramites/`, `attack-lab/`, `deploy/`, `docs/`) e introducir `backend/src/application/{ports,use-cases}` + `backend/src/infrastructure/{persistence,config}` como capa de desacople.
- **Beneficio inmediato:**
  1. El motor RFC 6238 (`core/totp`), vault AES-256-GCM (`core/vault`) y tokens Ed25519 (`core/tokens`) son **100% puros y testeables sin base de datos**.
  2. El mismo código corre con **PostgreSQL 16 + Caddy + Docker Compose** (`DB_DRIVER=postgres`) y con **SQLite WAL + Node TLS** (`DB_DRIVER=sqlite`) en estaciones del hackatón que no tienen Docker instalado.
  3. El módulo `heuristics/` soporta `MockAnomalyAdapter` para desarrollo paralelo del Frontend y `LocalAnomalyAdapter` (Isolation Forest / scoring conductual local) en producción/demo.

### ADR-002: Stack Oficial — 100 % propio y autoejecutable (decisión del 26-11-2026)
- **Regla:** todo lo que se ejecuta lo escribimos nosotros. **Cero dependencias npm** en tiempo de ejecución y en pruebas. Solo módulos nativos de Node.js 22.
- **Lenguaje:** JavaScript moderno (ESM, `"type": "module"`), con comentarios JSDoc para tipos. Sin TypeScript (el Node de las estaciones no lo ejecuta sin paquetes externos).
- **Backend:** `node:https` (servidor y enrutador propios), `node:crypto` (TOTP, AES-256-GCM, Ed25519, scrypt, HMAC), JWT EdDSA propio (sin `jose`), `node:sqlite` (SQLite WAL nativo, sin `better-sqlite3` ni `pg`), `node:test` (pruebas).
- **Base de datos:** solo SQLite (`contracts/schema.sqlite.sql`). PostgreSQL y Docker quedan fuera: no están disponibles en las estaciones.
- **TLS:** Node HTTPS directo con certificado generado por `openssl` del sistema (`TLS_MODE=node`). Sin Caddy.
- **Frontends (`authenticator-app/`, `admin-console/`, `demo-portal-tramites/`):** HTML + CSS + JavaScript propios, servidos por nuestro servidor. Sin React, Vite ni CDNs. La PWA usa `manifest.json` + Service Worker propios y Web Crypto del navegador.
- **Código QR:** generador propio (`backend/src/core/qr/`); plan B: alta con clave manual Base32.
- **Integración con Reto 1:** se registra como una `app` más (`client_id` + `client_secret`) y usa `sdk/`.

### ADR-003: Controles Criptográficos y de Integridad
- **AES-256-GCM con AAD:** `AAD = enrollment_id + ":" + key_version` (previene trasplante de filas cifradas).
- **Anti-Replay SQL atómico:** `UPDATE enrollments SET last_step = $T, drift_steps = $drift WHERE id = $id AND last_step < $T` + consumo único de `jti` en `consumed_jti`.
- **Anonimización:** `user_ref_hash = HMAC-SHA256(user_ref, USER_PEPPER)` y `ip_hash = HMAC-SHA256(ip, DAILY_IP_PEPPER)`.
- **Auditoría inmutable (`audit_log`):** Cadena de hashes `hash = SHA-256(prev_hash || ts || actor || accion || objetivo || detalle)` verificable desde `admin-console/`.
- **Trazabilidad:** SBOM CycloneDX en `docs/sbom/` + `npm audit` sin vulnerabilidades críticas.

---

## 2. Flujo de Integración (Portal de Trámites & Reto 1)

```text
[App Integradora: Portal Trámites / Reto 1]
    |  (Auth: X-Client-Id + X-Client-Secret sobre TLS 1.3)
    |
    +--> 1. POST /api/v1/enrollments           --> devuelve enrollment_id + QR SVG + otpauth:// (pendiente 10m)
    +--> 2. POST /api/v1/enrollments/:id/activate --> valida primer código -> ACTIVO + 10 códigos recuperación
    +--> 3. POST /api/v1/verify                --> { user_ref, code } -> RFC 6238 + drift + anti-replay + IA local
    |                                              --> devuelve JWT Ed25519 (5m, jti único, amr: ["otp"])
    +--> 4. POST /api/v1/tokens/validate       --> valida JWT y consume jti (o verificación offline vía /.well-known/jwks.json)
```

---

## 3. Áreas de trabajo (Diego y Laya)

| Área | Responsable | Rama | Carpetas |
| :--- | :--- | :--- | :--- |
| **A — Núcleo y API** | Diego | `diego` | `backend/src/core/{totp,vault,tokens,qr}`, `backend/src/infrastructure/`, `backend/src/application/`, `backend/src/api/`, `backend/src/security/`, `backend/src/audit/`, `backend/src/heuristics/`, `backend/migrations/` |
| **B — Clientes, contratos e integración** | Laya | `laya` | `contracts/`, `sdk/`, `authenticator-app/`, `admin-console/`, `demo-portal-tramites/`, `attack-lab/`, `deploy/`, documentos raíz |

**Punto de unión:** `contracts/openapi.yaml` y `contracts/mocks/`. Laya construye los clientes contra los mocks mientras Diego construye la API; al integrar en `staging`, los clientes pasan de los mocks a la API real sin cambios de contrato.

## 3.1 Propiedad de Carpetas y Tracks Paralelos (detalle original)

| Track / Rol | Carpetas Propias | Rama Sugerida |
| :--- | :--- | :--- |
| **Lead / Arquitectura / Contratos / SDK** (J Laya) | Raíz (`AGENTS.md`, `ARCHITECTURE.md`, `SYSTEM_GRAPH.md`, `TASKS.md`, `CONTRIBUTING.md`), `contracts/`, `sdk/` | `feat/lead-*` |
| **Backend & Criptografía** | `backend/src/core/{totp,vault,tokens}`, `backend/src/application/`, `backend/src/api/`, `backend/src/infrastructure/`, `backend/migrations/` | `feat/backend-*` |
| **Frontend & UX** | `authenticator-app/`, `admin-console/`, `demo-portal-tramites/` | `feat/frontend-*` |
| **Seguridad, Infra, IA Local & Attack Lab** | `backend/src/security/`, `backend/src/heuristics/`, `backend/src/audit/`, `attack-lab/`, `deploy/`, `docs/sbom/` | `feat/security-*` / `feat/ai-*` |
| **Solo lectura** | `docs/reto/`, `docs/analisis/` | — |

---

## 4. Comandos de Arranque (Dual: Docker y Sin Docker)

```bash
# Sin instalar nada (Node 22): SQLite nativo + HTTPS de Node
cp .env.example backend/.env
cd backend && npm test && npm start

# Smoke tests
curl -k https://localhost:8443/health
curl -k https://localhost:8443/.well-known/jwks.json
```
