# Grafo de Arquitectura y Red del Sistema — Servicio Soberano MFA / TOTP

> **Protocolo Graphy:** Todo agente y desarrollador debe consultar este grafo antes de crear o modificar módulos, y actualizarlo (alta/poda) en cada avance arquitectónico.
> **Estado actual:** Fase 1 (Estructura Hexagonal y Contratos Congelados en `contracts/`).

## 1. Mapa de Conexiones (Red Viva — Arquitectura Hexagonal)

```mermaid
flowchart TD
    %% Clientes y Sistemas Externos (Adaptadores de Entrada)
    PWA["Cliente Autenticador PWA Soberano\n(frontend/authenticator-pwa)"]
    ADMIN["Consola Administrativa\n(frontend/console)"]
    DEMO["Portal Institucional Demo\n(frontend/demo-portal)"]
    RETO1["Reto 1: Evaluador de Propuestas\n(Consumidor externo vía sdk/)"]

    %% Capa HTTP / Seguridad Perimetral (Infrastructure - In)
    HTTP["Fastify API Gateway TLS 1.3\n(OWASP Headers + Rate Limit + Anti-DDoS + RBAC)"]

    %% Casos de Uso (Application Layer)
    ENROLL_UC["EnrollUserService\n(application/use-cases)"]
    VERIFY_UC["VerifyTotpService\n(application/use-cases)"]
    VALIDATE_UC["ValidateTokenService\n(application/use-cases)"]
    ADMIN_UC["AdminGovernanceService\n(application/use-cases)"]

    %% Núcleo de Dominio Puro (Domain Layer)
    TOTP_CORE["TotpGenerator + TimeDriftCalculator\n(domain/services — RFC 6238)"]

    %% Puertos y Adaptadores de Salida (Infrastructure - Out)
    CRYPTO["NodeCryptoVaultAdapter\n(CSPRNG + AES-256-GCM + Ed25519 JWT/JWKS + IP HMAC)"]
    AI_LOCAL["LocalAnomalyAdapter\n(IA Heurística Local <15ms, 0 Telemetría)"]
    REPLAY["ReplayGuardAdapter\n(Caché Memoria TTL + SQLite)"]
    DB[("SQLite WAL Cifrada\n(contracts/schema.sql)")]

    %% Flujos de entrada
    PWA -->|"Escanea QR / Genera Código"| DEMO
    DEMO -->|"HTTPS TLS 1.3"| HTTP
    ADMIN -->|"HTTPS TLS 1.3 (Admin JWT)"| HTTP
    RETO1 -->|"sdk/: /enroll, /verify, /.well-known/jwks.json"| HTTP

    %% Flujos hacia Casos de Uso
    HTTP --> ENROLL_UC
    HTTP --> VERIFY_UC
    HTTP --> VALIDATE_UC
    HTTP --> ADMIN_UC

    %% Flujos del Núcleo y Adaptadores
    ENROLL_UC --> CRYPTO
    ENROLL_UC --> DB

    VERIFY_UC --> AI_LOCAL
    VERIFY_UC --> REPLAY
    VERIFY_UC --> TOTP_CORE
    VERIFY_UC --> CRYPTO
    VERIFY_UC --> DB

    VALIDATE_UC --> CRYPTO
    ADMIN_UC --> CRYPTO
    ADMIN_UC --> DB
```

## 2. Catálogo de Interfaces y Contratos Congelados (`contracts/openapi.yaml`)

| Módulo / Interfaz | Funciones / Endpoints Clave | Entradas / Salidas | Conexiones / Consumidores |
| :--- | :--- | :--- | :--- |
| `HttpAuthController` (`backend/src/infrastructure/adapters/in/http`) | `POST /api/v1/enroll`, `POST /api/v1/verify`, `POST /api/v1/token/validate`, `GET /.well-known/jwks.json`, `GET /health` | DTOs JSON -> QR/URI `otpauth://`, JWT `EdDSA`, JWKS público | `PWA`, `DEMO`, `RETO1`, `EnrollUserService`, `VerifyTotpService`, `ValidateTokenService` |
| `HttpAdminController` (`backend/src/infrastructure/adapters/in/http`) | `POST /api/v1/admin/login`, `GET/PUT /api/v1/admin/policies`, `POST /api/v1/admin/keys/rotate`, `POST /api/v1/admin/users/:id/revoke`, `GET /api/v1/admin/audit`, `GET /api/v1/admin/anomalies` | Admin JWT -> Políticas, Rotación `kid`, Auditoría anonimizada, Alertas IA | `ADMIN`, `AdminGovernanceService` |
| `TotpGenerator` (`backend/src/domain/services`) | `generateCode(secret, step, alg, digits)`, `verifyWithDrift(secret, code, now, policy)` | Buffer + Timestamp -> `{ valid, matchedStep, driftSteps }` | `VerifyTotpService` |
| `CryptoVaultPort` (`backend/src/application/ports/out`) | `generateSeed()`, `encryptAes256Gcm()`, `decryptAes256Gcm()`, `signMfaJwt()`, `verifyMfaJwt()`, `getPublicJwks()`, `rotateSigningKey()`, `anonymizeIp()` | Plaintext/Claims -> Ciphertext/JWT/JWKS/HMAC | `EnrollUserService`, `VerifyTotpService`, `ValidateTokenService`, `AdminGovernanceService` |
| `ReplayGuardPort` (`backend/src/application/ports/out`) | `isCodeUsed(enrollmentId, step)`, `markCodeUsed(enrollmentId, step, expiresAt)` | `(enrollmentId, step)` -> `boolean` | `VerifyTotpService` |
| `AnomalyDetectorPort` (`backend/src/application/ports/out`) | `evaluateAttempt(signals)`, `recordAttempt(signals, outcome)` | Señales locales anonimizadas -> `{ riskScore, level, action, reasons }` | `VerifyTotpService`, `HttpAdminController` |
| `SqliteRepositoryAdapter` (`backend/src/infrastructure/adapters/out/persistence`) | CRUD de `user_enrollments`, `totp_policies`, `signing_keys`, `replay_guard`, `auth_audit_events`, `anomaly_alerts` | Entidades <-> SQLite WAL | Todos los casos de uso |
| `MfaClientSdk` (`sdk/`) | `enroll()`, `verify()`, `validateTokenOnline()`, `verifyJwtOffline(token, jwksUrl)` | API REST / JWKS -> Sesión verificada | `RETO1`, `DEMO` |

## 3. Bitácora de Sincronización y Modelos

| Fecha | Acción (Alta / Poda / Refactor) | Módulos Afectados | Modelo Utilizado |
| :--- | :--- | :--- | :--- |
| 2026-11-26 | Alta inicial (Fase 1 — Esqueleto Hexagonal y Contratos Congelados) | `AGENTS.md`, `ARCHITECTURE.md`, `contracts/openapi.yaml`, `contracts/schema.sql`, `contracts/mocks/`, estructura `backend/src/` y `frontend/` | Gemini Neon |
