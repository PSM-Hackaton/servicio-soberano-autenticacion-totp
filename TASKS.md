# TASKS.md — Pizarrón Vivo (`servicio-soberano-autenticacion-totp`)

> **Regla de Oro:** Solo se marca `[x]` con evidencia real en verde. Prohibido tocar `main`.
> **Remotos:** Pushes **EXCLUSIVAMENTE a GitHub (`origin`)**. **GitLab BLOQUEADO** hasta `/push gitlab final`.
> **Stack vigente:** **ADR-002** (26-11-2026) — 100 % Node.js 22.5+ nativo, **0 dependencias npm**, SQLite WAL única, HTML+CSS+JS propios.

---

## FASE 0 & FASE 1: Sincronización, Estructura y Contratos Congelados
- [x] `[LEAD]` Lectura de `docs/reto/`, `docs/analisis/analisis-tecnico.html` e `instructivo_gitlab.pdf`.
- [x] `[LEAD]` Alineación de estructura oficial + Puertos Hexagonales y guías al unísono (`AGENTS.md`, `ARCHITECTURE.md`, `SYSTEM_GRAPH.md`, `CONTRIBUTING.md`, `TASKS.md`).

---

## FASE 2 — ÁREA A (Backend & Criptografía — Issues #2 a #9, #17, #18)
- [x] `[TOTP]` `backend/src/core/totp/`: Motor RFC 6238/4226 propio en JS sin dependencias con vectores Apéndice B en verde.
- [x] `[A1 · #2]` `backend/src/core/vault/`: AES-256-GCM con AAD (`enrollment_id:key_version`), llave maestra versionada y recifrado.
- [x] `[A2 · #3]` `backend/src/core/tokens/`: JWT Ed25519 (`EdDSA`) propio, JWKS y rotación por `kid`.
- [x] `[A3 · #4]` `backend/src/infrastructure/persistence/`: Persistencia `node:sqlite` (8 tablas, migraciones, anti-replay atómico, `jti` único y rotación de llave maestra).
- [x] `[A4 · #5]` `backend/src/api/`: Servidor `node:https` TLS 1.3, enrutador propio, endpoints v1 y admin, `/health`, `/health/ready`, `/metrics` e `Idempotency-Key`.
- [x] `[A5 · #6]` `backend/src/security/`: Secretos scrypt, limitador, bloqueo progresivo, validación estricta, cabeceras OWASP y errores genéricos.
- [x] `[A6 · #7]` `backend/src/audit/`: Bitácora encadenada SHA-256 y métricas locales Prometheus/JSON.
- [x] `[A7 · #8]` `backend/src/heuristics/`: Isolation Forest propio y detector local de anomalías explicable (<15 ms).
- [x] `[A8 · #9]` `backend/src/core/qr/`: Generador de código QR propio (ISO/IEC 18004 + Reed-Solomon) con salida SVG.
- [x] `[A9 · #17]` `backend/src/application/use-cases/`: Casos de uso completos (enroll, activate, verify, validateToken, resync, recovery, revoke y consola RBAC).
- [x] `[A10 · #18]` `backend/` + `scripts/`: `npm start`, `npm run env`, `npm run certs`, `npm run seed`, `npm run rotar-llave-maestra` y `deploy/servicio-totp.service`.

---

## FASE 2 — ÁREA B (Contratos, Clientes, SDK, Attack Lab y Entrega — Issues #10 a #15)
- [x] `[B1 · #10]` `contracts/`: `openapi.yaml` alineado al servidor real (`/health/ready`, `/metrics`, `/admin/api/*`, `Idempotency-Key`, `503`), `schema.sqlite.sql` único con los 4 índices adicionales y 30 mocks oficiales.
- [x] `[B2 · #11]` `authenticator-app/`: PWA offline propia (servida en `/app/`), Web Crypto SHA-256/512, PIN + IndexedDB cifrado, alta por enlace/URI/clave/cámara y tests en verde.
- [x] `[B3 · #12]` `admin-console/`: Consola administrativa RBAC propia (servida en `/consola/`), validada contra el backend real + modo mock.
- [x] `[B4 · #13]` `sdk/` y `demo-portal-tramites/`: SDK ESM sin dependencias (caché JWKS offline, timeout 3 s + 1 reintento idempotente, servicio falso), guía [`sdk/INTEGRACION_RETO1.md`](./sdk/INTEGRACION_RETO1.md) y Portal de Trámites demo con step-up MFA.
- [x] `[B5 · #14]` `attack-lab/`: 9 escenarios de ataque y caos (replay, JWT, entradas, fuerza bruta local y distribuida, spraying, inundación, proxy TCP de caos y reinicio) + pruebas unitarias en verde.
- [x] `[B6 · #15]` Raíz y `docs/`: `AGENTS.md`, `ARCHITECTURE.md` y `SYSTEM_GRAPH.md` sincronizados; `README.md` final con los 6 apartados oficiales; SBOM CycloneDX 1.5 en `docs/sbom/sbom.cdx.json` (8 módulos, 0 deps npm) y guion de demo en `docs/GUION_DEMO.md`.

---

## FASE 3 — INTEGRACIÓN Y ENTREGA (Issue #16 C1)
- [x] `[C1 · #16]` Integración unificada de `origin/diego` + `laya` verificada con todas las suites en verde y prueba E2E real contra el servidor HTTPS TLS 1.3 en rama `laya`.
- [ ] `[C1 · #16]` Pull Request en GitHub `laya` → `staging` → `main` y ensayo de demo con equipo Reto 1.
- [ ] `[LEAD]` Solo bajo orden explícita `/push gitlab final`: sincronizar entrega final en GitLab (`avance` y `terminado`).
