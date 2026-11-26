# TASKS.md — Pizarrón Vivo (`servicio-soberano-autenticacion-totp`)

> **Regla de Oro:** Solo se marca `[x]` con evidencia real en verde. Prohibido tocar `main`.
> **Remotos:** Pushes **EXCLUSIVAMENTE a GitHub (`origin`)**. **GitLab BLOQUEADO** hasta `/push gitlab final`.
> **Stack vigente:** **ADR-002** (26-11-2026) — 100 % Node.js 22 nativo, 0 dependencias npm, SQLite WAL única, HTML+CSS+JS propios.

---

## FASE 0 & FASE 1: Sincronización, Estructura y Contratos Congelados
- [x] `[LEAD]` Lectura de `docs/reto/`, `docs/analisis/analisis-tecnico.html` e `instructivo_gitlab.pdf`.
- [x] `[LEAD]` Alineación de estructura oficial + Puertos Hexagonales y guías al unísono (`AGENTS.md`, `ARCHITECTURE.md`, `SYSTEM_GRAPH.md`, `CONTRIBUTING.md`, `TASKS.md`).
- [x] `[LEAD]` División de áreas de trabajo en GitHub sin solapamiento: **Área A (`diego`)** vs. **Área B (`laya`)** con unión en `staging`.

---

## FASE 2 — ÁREA B (J Laya · rama `laya` · Issues #10 a #15)
- [x] `[LAYA · B1 · #10]` `contracts/`: OpenAPI v1.1 con `/health/ready`, `/metrics`, `Idempotency-Key` en `/api/v1/verify` y respuestas `503`; `schema.sqlite.sql` marcado como esquema oficial único (PostgreSQL deprecado); mocks actualizados y ampliados (`contracts/mocks/`).
- [x] `[LAYA · B2 · #11]` `authenticator-app/`: PWA offline propia (HTML+CSS+JS, `manifest.json`, `sw.js`), Web Crypto RFC 6238 (SHA-256/512/1, 6/8 dígitos, vectores Apéndice B en verde), bóveda IndexedDB cifrada con PIN (PBKDF2-SHA256 + AES-256-GCM), alta Base32 + URI `otpauth://` + cámara QR, anillo 30 s y copiar con un toque.
- [x] `[LAYA · B3 · #12]` `admin-console/`: Consola administrativa propia con login RBAC (`Administrador`/`Operador`/`Auditor`) + TOTP, apps/políticas, enrolamientos y revocación, rotación de llaves Ed25519 1-clic, verificador de cadena `audit_log` (con demo de alteración), parser `/metrics` y alertas IA (modo Mocks y API Real).
- [x] `[LAYA · B4 · #13]` `sdk/` y `demo-portal-tramites/`: SDK JS ESM cero dependencias (timeout 3 s, 1 reintento idempotente con `Idempotency-Key`, caché JWKS Ed25519 offline, fail-closed), guía `sdk/INTEGRACION_RETO1.md`, y Portal de Trámites demo completo con servidor Node 22 nativo.
- [x] `[LAYA · B5 · #14]` `attack-lab/`: Suite Node 22 cero dependencias con 7 escenarios (replay, fuerza bruta distribuida, spraying, deriva+resync, caos caída SQLite, corte de red+reintento+JWKS offline, latencia artificial) + generación automática de `attack-lab/REPORTE_DEMO.md` y `reporte-demo.json`.
- [x] `[LAYA · B6 · #15]` Raíz y `docs/`: `AGENTS.md`, `ARCHITECTURE.md` y `SYSTEM_GRAPH.md` sincronizados a ADR-002; `README.md` final con los 6 apartados oficiales; SBOM CycloneDX 1.5 en `docs/sbom/sbom.cdx.json`; guion de demo en `docs/GUION_DEMO.md`.

---

## FASE 2 — ÁREA A (Diego · rama `diego` · Issues #2 a #9, #17, #18)
- [x] `[DIEGO · TOTP]` `backend/src/core/totp/`: Motor RFC 6238/4226 propio en JS sin dependencias con tests oficiales en verde (`3304341`/`574d9d6`).
- [x] `[DIEGO · A1 · #2]` `backend/src/core/vault/`: AES-256-GCM con AAD y llave maestra versionada (`4222262`).
- [x] `[DIEGO · A2 · #3]` `backend/src/core/tokens/`: JWT EdDSA propio, JWKS y rotación `kid` (`f40d0ad`).
- [x] `[DIEGO · A3 · #4]` `backend/src/infrastructure/persistence/`: Persistencia `node:sqlite` (8 tablas, migraciones, anti-replay atómico y `jti` único) (`5136937`).
- [ ] `[DIEGO · A4 · #5]` `backend/src/api/`: Servidor `node:https` y endpoints v1 + `/health/ready`, `/metrics`, `Idempotency-Key`.
- [x] `[DIEGO · A5 · #6]` `backend/src/security/`: Secretos scrypt, bloqueo progresivo, limitador, validación estricta, cabeceras y errores genéricos (`325b902`).
- [x] `[DIEGO · A6 · #7]` `backend/src/audit/`: Bitácora encadenada SHA-256 y métricas Prometheus locales (`c5f98ad`).
- [ ] `[DIEGO · A7 · #8]` `backend/src/heuristics/`: Detector local de anomalías (Isolation Forest propio <15 ms).
- [x] `[DIEGO · A8 · #9]` `backend/src/core/qr/`: Generador de código QR propio (ISO/IEC 18004 + Reed-Solomon) salida SVG (`3ee768f`).
- [ ] `[DIEGO · A9 · #17]` `backend/src/application/use-cases/`: Casos de uso completos uniendo módulos.
- [ ] `[DIEGO · A10 · #18]` `backend/` + `config/`: `npm start`, `npm run certs`, `npm run seed`.

---

## FASE 3 — INTEGRACIÓN Y ENTREGA (Issue #16 C1)
- [ ] `[C1 · #16]` Unión de ramas `diego` y `laya` en `staging` + clientes contra la API real (sin mocks) + prueba sin Internet + PR `staging` → `main`.
- [ ] `[LEAD]` **CODE FREEZE** + ensayo final con `docs/GUION_DEMO.md`.
- [ ] `[LEAD]` Solo bajo orden explícita `/push gitlab final`: sincronizar entrega final en GitLab (`avance` y `terminado`).
