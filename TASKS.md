# TASKS.md — Pizarrón Vivo (`servicio-soberano-autenticacion-totp`)

> **Regla de Oro:** Solo se marca `[x]` con evidencia real en verde. Prohibido tocar `main`.
> **Remotos:** Pushes **EXCLUSIVAMENTE a GitHub (`origin`)**. **GitLab BLOQUEADO** hasta `/push gitlab final`.
> **Stack vigente:** **ADR-002** (26-11-2026) — 100 % Node.js 22.5+ nativo, **0 dependencias npm**, SQLite WAL única, HTML+CSS+JS propios.
> **Última verificación (26-11-2026, copia limpia del árbol de trabajo, Node.js 22.22.1):** 258 pruebas en verde (backend 171, app 25, SDK 23, portal 12, attack-lab 27 con DAST); escáner DAST propio en vivo 9/9 verificaciones OK (0 hallazgos críticos/altos); verificación institucional `systemd` 10/10 (`systemd-analyze security: 3.0 OK`, `VACUUM INTO`, `SIGTERM` 4 ms).

---

## FASE 0 & FASE 1: Sincronización, Estructura y Contratos Congelados
- [x] `[LEAD]` Lectura de `docs/reto/`, `docs/analisis/analisis-tecnico.html` e `instructivo_gitlab.pdf`.
- [x] `[LEAD]` Alineación de estructura oficial y guías al unísono (`AGENTS.md`, `ARCHITECTURE.md`, `SYSTEM_GRAPH.md`, `CONTRIBUTING.md`, `TASKS.md`).

---

## FASE 2 — ÁREA A (Backend & Criptografía — Issues #2 a #9, #17, #18)
- [x] `[TOTP]` `backend/src/core/totp/`: motor RFC 6238/4226 propio con vectores del Apéndice B — `totp.test.js` (10).
- [x] `[A1 · #2]` `backend/src/core/vault/`: AES-256-GCM con AAD (`enrollment_id:key_version`), llave maestra versionada y recifrado — `vault.test.js` (12).
- [x] `[A2 · #3]` `backend/src/core/tokens/`: JWT Ed25519 (`EdDSA`) propio, JWKS y rotación por `kid` — `tokens.test.js` (16).
- [x] `[A3 · #4]` `backend/src/infrastructure/persistence/`: `node:sqlite` (8 tablas, migraciones, anti replay atómico, `jti` único, rotación de llave maestra) — `persistencia.test.js` (10), `rotacion.test.js` (4).
- [x] `[A4 · #5]` `backend/src/api/`: servidor `node:https` TLS 1.3, enrutador propio, rutas v1 y admin, `/health`, `/health/ready`, `/metrics`, `Idempotency-Key` — `api.test.js`.
- [x] `[A5 · #6]` `backend/src/security/`: scrypt, limitador, bloqueo progresivo, validación estricta, cabeceras OWASP y errores genéricos — `security.test.js` (17).
- [x] `[A6 · #7]` `backend/src/audit/`: bitácora encadenada SHA-256 y métricas locales — `audit.test.js` (17).
- [x] `[A7 · #8]` `backend/src/heuristics/`: Isolation Forest propio y detector explicable (p95 < 15 ms) — `heuristics.test.js` (9); spraying real: riesgo 100 CRITICAL.
- [x] `[A8 · #9]` `backend/src/core/qr/`: QR propio (ISO/IEC 18004 + Reed-Solomon) en SVG — `qr.test.js` (11).
- [x] `[A9 · #17]` `backend/src/application/use-cases/`: enrolar, activar, verificar, validar, resync, recuperación, revocación y consola RBAC — `casos.test.js`.
- [x] `[A10 · #18]` `npm start`, `npm run env`, `npm run certs`, `npm run seed`, `npm run rotar-llave-maestra` y `deploy/servicio-totp.service` — ejecutados en la verificación del 26-11-2026 (salvo la unidad `systemd`).

---

## FASE 2 — ÁREA B (Contratos, Clientes, SDK, Attack Lab y Entrega — Issues #10 a #15)
- [x] `[B1 · #10]` `contracts/`: `openapi.yaml` alineado al servidor real, `schema.sqlite.sql` y mocks oficiales.
- [x] `[B2 · #11]` `authenticator-app/`: PWA offline propia en `/app/`, Web Crypto SHA-256/512, PIN + almacenamiento cifrado, alta por enlace/URI/clave — `authenticator-app/tests/*.test.mjs` (25).
  - [ ] Alta por **cámara**: bloqueada en `/app/` por `Permissions-Policy: camera=()` (`backend/src/security/cabeceras.js`). Corrección propuesta: `camera=(self)` solo para `/app/`.
- [x] `[B3 · #12]` `admin-console/`: consola RBAC propia en `/consola/`, validada contra el backend real.
  - [ ] Pantallas para registrar apps, crear cuentas Operador/Auditor y revocar enrolamientos (la API de consola no expone las dos últimas).
- [x] `[B4 · #13]` `sdk/` y `demo-portal-tramites/`: SDK sin dependencias, guía `sdk/INTEGRACION_RETO1.md` y Portal con *step-up* — `sdk.test.js` (23), `portal.test.js` (12); flujo real del portal comprobado de punta a punta.
- [x] `[B5 · #14]` `attack-lab/`: 9 escenarios de ataque y caos — `npm test` (25); `ejecutar-todo.js --rapido` 8/8 y 85/85, `caos/reinicio.js` 4/4 (0,33 s).
- [x] `[B6 · #15]` `README.md` final con los 6 apartados oficiales, participantes y roles, instalación probada paso a paso; SBOM CycloneDX 1.5 regenerado.

---

## Entregables documentales (26-11-2026)
- [x] `README.md` — 6 apartados del instructivo de GitLab en orden; variables de entorno reales del backend y del portal; pasos 1–11 ejecutados en una copia limpia.
- [x] `LICENSE` — texto oficial completo de la GNU AGPL-3.0 con cabecera «Copyright (C) 2026 Equipo PSM-Hackaton» (`AGPL-3.0-or-later`).
- [x] `docs/sbom/` — `generar-sbom.js` (propio, sin dependencias, rutas relativas): revisa los 4 `package.json` (0 dependencias), escanea las importaciones (0 externas, solo `node:*`), hashes SHA-256 por componente y por archivo; `sbom.cdx.json` (CycloneDX 1.5), `hashes-sha256.txt`, `README.md`.
- [x] `docs/api/README.md` — guía HTTP de integración con peticiones y respuestas reales (`curl --cacert`); enlaza `sdk/INTEGRACION_RETO1.md`.
- [x] `docs/cumplimiento/matriz-cumplimiento.{html,pdf}` — cada requisito citado de los TdR y del enunciado, y cada criterio con su peso, con código y prueba.
- [x] `docs/manual/manual-usuario.{html,pdf}` — ciudadano (app y portal) y administrador (consola).
- [x] `docs/presentacion/guion-demo.{html,pdf}` — guion de 5–7 min con plan B (consolida `docs/GUION_DEMO.md`, que ahora apunta al PDF).
- [x] `docs/evidencias/` — informe HTML/JSON del laboratorio de ataques de la verificación.
- [ ] `docs/escalabilidad/` — en preparación por otro integrante (enlazado desde el README y la matriz).

---

## Pendientes detectados en la verificación
- [ ] Cámara en la PWA (ver B2).
- [ ] Consola: registrar apps, crear Operador/Auditor, revocar (ver B3).
- [ ] `PORTAL_STEPUP_MINUTOS` se lee en `demo-portal-tramites/src/config.js` pero no se usa.
- [ ] `sdk/package.json` declara `"license": "UNLICENSED"`; alinear con AGPL-3.0-or-later.
- [ ] `npm run certs` solo emite para `localhost`; el README §6 (Paso 6) documenta el certificado con la IP de la red local para el teléfono.
- [x] `[C6 · #24]` Escaneo dinámico OWASP propio (`attack-lab/escenarios/dast.js` + `dast.test.js`): 9/9 verificaciones OK en vivo contra producción TLS 1.3 (`docs/evidencias/dast-informe-2026-11-26.{html,json}`).
- [x] `[C7 · #25]` Prueba de despliegue institucional `systemd` (`deploy/verificar-despliegue.js` + `docs/evidencias/prueba-despliegue-systemd.md`): 10/10 controles OK (`systemd-analyze verify`, `security: 3.0 OK`, TLS 1.3, `VACUUM INTO`, `SIGTERM` 4 ms).
- [x] `[C8 · #26]` Limpieza final: `SYSTEM_GRAPH.md` sin rastros de herramientas/modelos, `AGENTS.md` actualizado, SBOM CycloneDX 1.5 regenerado (128 archivos JS, 0 deps npm) y 258/258 pruebas en verde.

---

## FASE 3 — INTEGRACIÓN Y ENTREGA (Issue #16 C1)
- [x] `[C1 · #16]` Integración de `origin/diego` + `laya` verificada con todas las suites en verde y prueba E2E real contra el servidor HTTPS TLS 1.3.
- [ ] `[C1 · #16]` Pull Request `laya` → `staging` → `main` y ensayo de demo con el equipo del Reto 1.
- [ ] `[LEAD]` Solo bajo orden explícita `/push gitlab final`: sincronizar la entrega final en GitLab (`avance` y `terminado`).
