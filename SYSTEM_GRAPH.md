# Grafo de Arquitectura y Red del Sistema — Servicio Soberano TOTP

> **Protocolo Graphy:** Consultar antes de crear/modificar código; actualizar (alta/poda) en cada avance.
> **Estado actual:** Fase 1 — Alineado 100% con `docs/analisis/analisis-tecnico.html` (`origin/main`) + Puertos Hexagonales.

## 1. Mapa de Conexiones (Red Viva)

```mermaid
flowchart TD
    %% Clientes / Frontends
    PWA["authenticator-app/\n(PWA Offline, PIN, QR/Manual, SHA-256/512)"]
    ADMIN["admin-console/\n(Consola RBAC + TOTP Propio + Auditoría)"]
    DEMO["demo-portal-tramites/\n(Portal Institucional Demo)"]
    RETO1["Reto 1: Evaluador de Propuestas\n(Integrador externo vía sdk/)"]
    ATK["attack-lab/\n(Simulador Replay, Fuerza Bruta, Spraying)"]

    %% SDK y Borde TLS
    SDK["sdk/\n(Cliente TypeScript + Verificador JWKS)"]
    EDGE["deploy/ Caddy TLS 1.3\n(o Node HTTPS en modo sin Docker)"]

    %% API & Seguridad Perimetral
    API["backend/src/api/\n(Fastify v1 + /admin/api + /.well-known/jwks.json)"]
    SEC["backend/src/security/\n(Auth Apps client_id/secret, Rate Limit, Bloqueo Progresivo)"]

    %% Capa de Aplicación (Casos de Uso + Puertos Hexagonales)
    UC["backend/src/application/use-cases/\n(Enroll, Activate, Verify, Resync, Recovery, ValidateToken, Admin)"]

    %% Núcleo Criptográfico Puro (0 dependencias OTP externas)
    TOTP["backend/src/core/totp/\n(RFC 6238 Propio + Deriva + Tests Apéndice B)"]
    VAULT["backend/src/core/vault/\n(AES-256-GCM con AAD + Llave Maestra Versionada)"]
    TOKENS["backend/src/core/tokens/\n(JWT Ed25519 EdDSA + JWKS + jti único)"]

    %% IA Local y Auditoría Encadenada
    HEUR["backend/src/heuristics/\n(Detector Local de Anomalías + Respuesta Adaptativa)"]
    AUDIT["backend/src/audit/\n(Bitácora Encadenada prev_hash -> hash + Métricas Anon)"]

    %% Persistencia Dual (Puerto Hexagonal)
    DB[("PostgreSQL 16 (Docker)\n/ SQLite WAL (Fallback sin Docker)\n8 Tablas Oficiales")]

    %% Flujos
    PWA -->|"QR / Código 6-8 dig"| DEMO
    PWA -->|"QR / Código"| RETO1
    DEMO --> SDK
    RETO1 --> SDK
    SDK -->|"HTTPS TLS 1.3"| EDGE
    ADMIN -->|"HTTPS + Cookie HttpOnly + TOTP"| EDGE
    ATK -->|"Tráfico simulado"| EDGE

    EDGE --> API
    API --> SEC
    SEC --> UC

    UC --> TOTP
    UC --> VAULT
    UC --> TOKENS
    UC --> HEUR
    UC --> AUDIT
    UC --> DB
    HEUR --> DB
    AUDIT --> DB
```

## 2. Catálogo de Interfaces y Contratos (`contracts/openapi.yaml` & `contracts/schema.sql`)

| Módulo / Interfaz | Funciones / Endpoints Clave | Entradas / Salidas | Conexiones / Consumidores |
| :--- | :--- | :--- | :--- |
| `backend/src/api/v1` | `POST /api/v1/enrollments`, `POST /api/v1/enrollments/{id}/activate`, `POST /api/v1/verify`, `POST /api/v1/tokens/validate`, `GET /.well-known/jwks.json`, `POST /api/v1/enrollments/{id}/resync`, `POST /api/v1/recovery`, `DELETE /api/v1/enrollments/{id}` | Credenciales App (`client_id`/`client_secret`) + JSON estricto -> QR SVG, códigos recuperación, JWT Ed25519, JWKS | `sdk/`, `demo-portal-tramites/`, `RETO1`, `attack-lab/`, `UC` |
| `backend/src/api/admin` | `POST /admin/api/login`, `GET/PUT /admin/api/apps`, `GET /admin/api/enrollments`, `POST /admin/api/keys/rotate`, `GET /admin/api/audit`, `GET /admin/api/audit/verify-chain`, `GET /admin/api/anomalies` | Cookie `HttpOnly; Secure; SameSite=Strict` + CSRF + RBAC -> Políticas, rotación `kid`, integridad de bitácora, alertas IA | `admin-console/`, `UC` |
| `backend/src/core/totp` | `generateHotp()`, `generateTotp()`, `verifyTotpWithDrift()`, `resyncTwoConsecutiveCodes()` | Seed Buffer + Epoch + Policy -> `{ valid, matchedStep, driftSteps }` | `UC` (Verify, Activate, Resync) |
| `backend/src/core/vault` | `generateSeed(alg)`, `encryptSeed(seed, enrollmentId, keyVer)`, `decryptSeed()`, `hashPepper(val, pepper)` | Buffer + AAD -> `{ ct, nonce, authTag, keyVersion }` | `UC`, `TOKENS` |
| `backend/src/core/tokens` | `signMfaJwt()`, `verifyMfaJwt()`, `getPublicJwks()`, `rotateEd25519Key()` | Claims + PrivateKey -> JWT `EdDSA` (`jti`, `kid`, `amr: ["otp"]`) / JWKS | `UC`, `API` |
| `backend/src/heuristics` | `evaluateRisk(signals)`, `recordAttempt()` | Features locales de `attempts` -> `{ riskScore, level, action, reasons, inferenceMs }` | `UC`, `admin-console/` |
| `backend/src/audit` | `appendChainedEvent()`, `verifyHashChain()` | Evento -> Fila encadenada (`prev_hash` -> `hash`) / `{ intact, brokenAtId }` | `UC`, `admin-console/` |
| `backend/src/infrastructure/persistence` | Repositorios para las 8 tablas: `apps`, `enrollments`, `recovery_codes`, `attempts`, `consumed_jti`, `signing_keys`, `admins`, `audit_log` | Puertos Hexagonales <-> PostgreSQL 16 / SQLite WAL | Todos los casos de uso |

## 3. Bitácora de Sincronización y Modelos

| Fecha | Acción (Alta / Poda / Refactor) | Módulos Afectados | Modelo Utilizado |
| :--- | :--- | :--- | :--- |
| 2026-11-26 | Alta inicial (Fase 1) | Estructura hexagonal base y contratos iniciales | Gemini Neon |
| 2026-11-26 | Refactor / Alineación 100% con `origin/main` (`95c0fbd`) | Poda de `frontend/*` y `qa/`; alta de `backend/src/core/{totp,vault,tokens}`, `security/`, `heuristics/`, `audit/`, `api/`, `authenticator-app/`, `admin-console/`, `demo-portal-tramites/`, `attack-lab/`, `deploy/`, 9 endpoints v1 y 8 tablas oficiales (con `audit_log` encadenado y `recovery_codes`) | Gemini Neon |
