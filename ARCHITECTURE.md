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

### ADR-002: Stack Oficial
- **Backend:** Node.js 22 + TypeScript + Fastify + `node:crypto` nativo (cero librerías OTP externas) + `jose` (EdDSA/JWKS) + `pg` (PostgreSQL 16) + `better-sqlite3` (fallback sin Docker).
- **Frontends:** React + Vite + TypeScript (sin CDNs externos):
  - `authenticator-app/` — PWA offline instalable con bloqueo por PIN (semillas cifradas localmente con clave derivada del PIN), QR / alta manual, soporte SHA-256 y SHA-512 (6 u 8 dígitos).
  - `admin-console/` — Consola administrativa protegida con RBAC (`Administrador`, `Operador`, `Auditor`), cookies `HttpOnly; Secure; SameSite=Strict` + CSRF + nuestro propio TOTP.
  - `demo-portal-tramites/` — Sistema institucional demo integrado con `sdk/`.
- **Integración con Reto 1:** El equipo del Reto 1 (*Agente Evaluador de Propuestas*) se registra como una `app` más en la tabla `apps` (`client_id` + `client_secret`) y consume `sdk/` sin acoplar bases de datos.
- **Borde y despliegue:** `deploy/docker-compose.yml` + `deploy/Caddyfile` (`tls internal`, TLS 1.3, HSTS, rate limit y tamaño máximo de cuerpo).

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

## 3. Propiedad de Carpetas y Tracks Paralelos

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
# Modo A: Con Docker Compose (PostgreSQL 16 + Caddy TLS 1.3)
docker compose -f deploy/docker-compose.yml up --build

# Modo B: Sin Docker (Estación Ubuntu del hackatón — SQLite WAL + Node TLS)
cp .env.example backend/.env   # Configurar DB_DRIVER=sqlite
cd backend && npm install && npm test && npm run dev

# Smoke tests
curl -k https://localhost:8443/health
curl -k https://localhost:8443/.well-known/jwks.json
```
