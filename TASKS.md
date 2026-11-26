# TASKS.md — Pizarrón Vivo (`servicio-soberano-autenticacion-totp`)

> **Regla de Oro:** Solo se marca `[x]` con evidencia verificada. Prohibido commitear en `main`.
> **Remotos:** Pushes **EXCLUSIVAMENTE en GitHub (`origin`)**. **GitLab BLOQUEADO** hasta `/push gitlab final`.

---

## FASE 0 & FASE 1: Análisis, Esqueleto Hexagonal y Contratos Congelados (`feat/lead-arquitectura-totp`)
- [x] `[LEAD]` Lectura de especificaciones oficiales (`docs/reto/`) e `instructivo_gitlab.pdf`.
- [x] `[LEAD]` Auditoría del esqueleto hexagonal de referencia y adaptación a Node.js 22 + TypeScript + Reto 2 TOTP.
- [x] `[LEAD]` Creación de guías al unísono (`AGENTS.md`, `ARCHITECTURE.md`, `ANALISIS_FASE0.md`, `SYSTEM_GRAPH.md`, `CONTRIBUTING.md`, `TASKS.md`, `.env.example`, `.gitignore`).
- [x] `[LEAD]` Creación de estructura Hexagonal (`backend/src/{domain,application,infrastructure}`, `frontend/{console,authenticator-pwa,demo-portal}`, `contracts/`, `sdk/`, `qa/`).
- [x] `[LEAD]` Congelar contratos (`contracts/openapi.yaml`, `contracts/schema.sql`, `contracts/mocks/*.json`) y subir rama `feat/lead-arquitectura-totp` a GitHub.
- [ ] `[LEAD]` Emitir prompts oficiales de 8 secciones para Compañero 2 (`backend/`), Compañero 3 (`frontend/`) y nota de integración para el sub-equipo de Reto 1.

---

## FASE 2: Desarrollo Paralelo (Tracks Aislados)

### Track A — Backend, Criptografía e IA Local (`feat/backend-*` — `backend/`)
- [ ] `[BACKEND]` Setup TypeScript + Fastify + SQLite WAL + TLS local + `DependencyInjection.ts`.
- [ ] `[BACKEND]` Dominio puro RFC 6238 (`TotpGenerator`, `TimeDriftCalculator`, `HMAC-SHA256`, `HMAC-SHA512`, `timingSafeEqual`).
- [ ] `[BACKEND]` `NodeCryptoVaultAdapter` (CSPRNG 256-bit, AES-256-GCM en reposo, Ed25519 JWT + `/.well-known/jwks.json` + rotación `kid`, anonimización HMAC de IPs).
- [ ] `[BACKEND]` `ReplayGuardAdapter` (caché memoria + tabla `replay_guard`) + rate limiting/anti-DDoS + bloqueo progresivo + cabeceras OWASP.
- [ ] `[BACKEND]` `LocalAnomalyAdapter` (IA heurística/estadística local <15 ms, 0 telemetría externa) + `MockAnomalyAdapter`.
- [ ] `[BACKEND]` Endpoints completos de `contracts/openapi.yaml` (`/enroll`, `/verify`, `/token/validate`, `/.well-known/jwks.json`, `/admin/*`) + tests unitarios en verde.

### Track B — Frontend Consola Admin, Cliente PWA y Portal Demo (`feat/frontend-*` — `frontend/`)
- [ ] `[FRONTEND]` Setup React + Vite + Tailwind + cliente HTTP configurable (modo mocks `contracts/mocks/` -> modo API real).
- [ ] `[FRONTEND]` Cliente Autenticador PWA Soberano (escaneo/pegado `otpauth://` QR, cálculo TOTP local SHA256/SHA512 en navegador con temporizador 30s).
- [ ] `[FRONTEND]` Consola Administrativa (login RBAC, gestión de políticas TOTP, enrolamiento/revocación, rotación de llaves JWT, alertas IA en vivo y auditoría anonimizada).
- [ ] `[FRONTEND]` Mini Portal Institucional Demo (login + verificación TOTP + visor de JWT Ed25519 verificado).

### Track C — Integración Reto 1, QA & Seguridad (`feat/lead-*` — `sdk/` y `qa/`)
- [ ] `[LEAD]` `sdk/` cliente ligero TS/JS para consumo desde Reto 1 y Portal Demo (verificación online y offline vía JWKS).
- [ ] `[QA]` Suite de pruebas automatizadas: RFC 6238 vectores de prueba, anti-replay, *time-drift*, cifrado AES-256 verificado en archivo SQLite, OWASP headers.
- [ ] `[QA]` Script simulador de ataques en vivo (replay + fuerza bruta distribuida + drift) para defensa ante jurado.
- [ ] `[QA]` Generación y verificación de SBOM (`qa/sbom-backend.json`, `qa/sbom-frontend.json`) con 0 vulnerabilidades críticas.

---

## FASE 3: Integración, Demo y Entrega Final
- [ ] `[LEAD]` Integrar ramas en GitHub (`avance`) y probar integración end-to-end con el sub-equipo de Reto 1.
- [ ] `[LEAD]` **CODE FREEZE** + actualizar `README.md` con los 6 apartados obligatorios del instructivo.
- [ ] `[LEAD]` Solo bajo orden explícita `/push gitlab final`: sincronizar entrega final en GitLab (`avance` y `terminado`).
