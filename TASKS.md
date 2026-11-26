# TASKS.md — Pizarrón Vivo (`servicio-soberano-autenticacion-totp`)

> **Regla de Oro:** Solo se marca `[x]` con evidencia real en verde. Prohibido tocar `main`.
> **Remotos:** Pushes **EXCLUSIVAMENTE a GitHub (`origin`)**. **GitLab BLOQUEADO** hasta `/push gitlab final`.
> **Stack vigente:** **ADR-002** (26-11-2026) — 100 % Node.js 22.5+ nativo, **0 dependencias npm**, SQLite WAL única, HTML+CSS+JS propios.
> **Última verificación (26-11-2026, copia limpia del árbol de trabajo, Node.js 22.22.1):** `node scripts/verificar-todo.js` en verde: **309 pruebas** (backend 211, app 26, SDK 28, portal 16, attack-lab 28); contrato con las **31 rutas** del servidor; laboratorio **11/11** escenarios y **116/116** verificaciones; DAST en vivo **12/12** (34 sondas, `camera=(self)` en `/app/`); verificación institucional `systemd` 10/10 (`systemd-analyze security: 3.0 OK`, `VACUUM INTO`, `SIGTERM` 5 ms).

---

## FASE 0 & FASE 1: Sincronización, Estructura y Contratos Congelados
- [x] `[LEAD]` Lectura de `docs/reto/`, `docs/analisis/analisis-tecnico.html` e `instructivo_gitlab.pdf`.
- [x] `[LEAD]` Alineación de estructura oficial y guías al unísono (`AGENTS.md`, `ARCHITECTURE.md`, `SYSTEM_GRAPH.md`, `CONTRIBUTING.md`, `TASKS.md`).

---

## FASE 2 — ÁREA A (Backend & Criptografía — Issues #2 a #9, #17, #18)
- [x] `[TOTP]` `backend/src/core/totp/`: motor RFC 6238/4226 propio con vectores del Apéndice B — `totp.test.js` (11).
- [x] `[A1 · #2]` `backend/src/core/vault/`: AES-256-GCM con AAD (`enrollment_id:key_version`), llave maestra versionada y recifrado — `vault.test.js` (12).
- [x] `[A2 · #3]` `backend/src/core/tokens/`: JWT Ed25519 (`EdDSA`) propio, JWKS y rotación por `kid` — `tokens.test.js` (16).
- [x] `[A3 · #4]` `backend/src/infrastructure/persistence/`: `node:sqlite` (8 tablas, migraciones, anti replay atómico, `jti` único, rotación de llave maestra) — `persistencia.test.js` + `rotacion.test.js` (14).
- [x] `[A4 · #5]` `backend/src/api/`: servidor `node:https` TLS 1.3, enrutador propio, rutas v1 y admin, `/health`, `/health/ready`, `/metrics`, `Idempotency-Key` — `api.test.js`.
- [x] `[A5 · #6]` `backend/src/security/`: scrypt, limitador, bloqueo progresivo, validación estricta, cabeceras OWASP y errores genéricos — `security.test.js` (18).
- [x] `[A6 · #7]` `backend/src/audit/`: bitácora encadenada SHA-256 y métricas locales — `audit.test.js` (17).
- [x] `[A7 · #8]` `backend/src/heuristics/`: Isolation Forest propio y detector explicable (p95 < 15 ms) — `heuristics.test.js` (9); spraying real: riesgo 100 CRITICAL.
- [x] `[A8 · #9]` `backend/src/core/qr/`: QR propio (ISO/IEC 18004 + Reed-Solomon) en SVG — `qr.test.js` (11).
- [x] `[A9 · #17]` `backend/src/application/use-cases/`: enrolar, activar, verificar, validar, resync, recuperación, revocación y consola RBAC — `casos.test.js`.
- [x] `[A10 · #18]` `npm start`, `npm run env`, `npm run certs`, `npm run seed`, `npm run rotar-llave-maestra` y `deploy/servicio-totp.service` — ejecutados en la verificación del 26-11-2026 (salvo la unidad `systemd`).

---

## FASE 2 — ÁREA B (Contratos, Clientes, SDK, Attack Lab y Entrega — Issues #10 a #15)
- [x] `[B1 · #10]` `contracts/`: `openapi.yaml` alineado al servidor real, `schema.sqlite.sql` y mocks oficiales.
- [x] `[B2 · #11]` `authenticator-app/`: PWA offline propia en `/app/`, Web Crypto SHA-256/512, PIN + almacenamiento cifrado, alta por enlace/URI/clave — `authenticator-app/tests/*.test.mjs` (26).
  - [x] Alta por **cámara**: `Permissions-Policy: camera=(self)` solo en `/app/` (`backend/src/security/cabeceras.js`); el DAST lo verifica en vivo.
- [x] `[B3 · #12]` `admin-console/`: consola RBAC propia en `/consola/`, validada contra el backend real.
  - [x] Gestión completa: registrar apps y regenerar su secreto, suspender/reactivar/revocar enrolamientos, búsqueda por cédula, crear y deshabilitar cuentas de administración — `admin-gestion.test.js`, `admin-consola.test.js`.
- [x] `[B4 · #13]` `sdk/` y `demo-portal-tramites/`: SDK sin dependencias, guía `sdk/INTEGRACION_RETO3.md` y Portal con *step-up* — `sdk/tests/*.test.js` (28), `portal.test.js` (16, ingreso por cédula); flujo real del portal comprobado de punta a punta.
- [x] `[B5 · #14]` `attack-lab/`: 11 escenarios de ataque y caos + DAST — `npm test` (28); `ejecutar-todo.js` con reinicio 11/11 y 116/116 (`docs/evidencias/attack-lab-informe-2026-11-26.*`).
- [x] `[B6 · #15]` `README.md` final con los 6 apartados oficiales, participantes y roles, instalación probada paso a paso; SBOM CycloneDX 1.5 regenerado.

---

## Entregables documentales (26-11-2026)
- [x] `README.md` — 6 apartados del instructivo de GitLab en orden; variables de entorno reales del backend y del portal; pasos 1–11 ejecutados en una copia limpia.
- [x] `LICENSE` — texto oficial completo de la GNU AGPL-3.0 con cabecera «Copyright (C) 2026 Equipo PSM-Hackaton» (`AGPL-3.0-or-later`).
- [x] `docs/sbom/` — `generar-sbom.js` (propio, sin dependencias, rutas relativas): revisa los 4 `package.json` (0 dependencias), escanea las importaciones (0 externas, solo `node:*`), hashes SHA-256 por componente y por archivo; `sbom.cdx.json` (CycloneDX 1.5), `hashes-sha256.txt`, `README.md`.
- [x] `docs/api/README.md` — guía HTTP de integración con peticiones y respuestas reales (`curl --cacert`); enlaza `sdk/INTEGRACION_RETO3.md`.
- [x] `docs/cumplimiento/matriz-cumplimiento.{html,pdf}` — cada requisito citado de los TdR y del enunciado, y cada criterio con su peso, con código y prueba.
- [x] `docs/manual/manual-usuario.{html,pdf}` — ciudadano (app y portal) y administrador (consola).
- [x] `docs/presentacion/guion-demo.{html,pdf}` — guion de 5–7 min con plan B (consolida `docs/GUION_DEMO.md`, que ahora apunta al PDF).
- [x] `docs/evidencias/` — informe HTML/JSON del laboratorio de ataques de la verificación.
- [x] `docs/escalabilidad/` — `escalabilidad.{html,pdf}`, mediciones reproducibles en `medicion/` y datos en `datos/`.

---

## Pendientes detectados en la verificación
- [x] Cámara en la PWA (ver B2).
- [x] Consola: registrar apps, crear Operador/Auditor, revocar (ver B3).
- [x] `PORTAL_STEPUP_MINUTOS` retirada (se leía sin efecto).
- [x] `sdk/package.json` con `"license": "AGPL-3.0-or-later"`.
- [x] `npm run certs` solo emite para `localhost`; el README §6 (Paso 6) y `deploy/instalar.sh` cubren el certificado con la IP de la red local.
- [x] `[C6 · #24]` Escaneo dinámico OWASP propio (`attack-lab/escenarios/dast.js` + `dast.test.js`): 12/12 verificaciones en vivo sobre las 31 rutas del contrato con sesión de administración (`docs/evidencias/dast-informe-2026-11-26.{html,json}`).
- [x] `[C7 · #25]` Prueba de despliegue institucional `systemd` (`deploy/verificar-despliegue.js` + `docs/evidencias/prueba-despliegue-systemd.md`): 10/10 controles OK (`systemd-analyze verify`, `security: 3.0 OK`, TLS 1.3, `VACUUM INTO`, `SIGTERM` 5 ms; `--puerto` si 18443 está ocupado).
- [x] `[C8 · #26]` Pasada final: cifras vigentes en todos los documentos y PDF, matriz re-evaluada, código sin uso retirado, instalador sin el literal de carpetas personales (preparar-entrega sin `--permitidos`), SBOM regenerado y lista de entrega `docs/entrega/lista-entrega.md`.
- [x] `[D1 · #27]` `contracts/openapi.yaml` sin claves duplicadas ni `$ref` rotas; documentos raíz sin `USER_PEPPER`/`DAILY_IP_PEPPER`/`Hexagonal`; `sdk/INTEGRACION_RETO3.md` con `clientIp`.
- [x] `[D3 · #29]` Prueba automatizada de formato Key URI en `authenticator-app/tests/otpauth.test.mjs` + matriz `docs/evidencias/compatibilidad-clientes-totp.md`.
- [x] `[D4 · #30]` `README.md` conforme a los 6 apartados del instructivo sin cédulas y con cifras/cobertura verificadas.
- [x] `[D5 · #31]` CI sin dependencias (`scripts/verificar-todo.js`, `.gitlab-ci.yml`, `.github/workflows/pruebas.yml`) + cobertura real en `docs/evidencias/cobertura-2026-11-26.txt` (309/309 pruebas; backend 93,7 % de líneas, que incluye el SDK cargado por una prueba).
- [x] `[D7/F3 · #33/#50]` Auditoría WCAG 2.1 AA en `docs/evidencias/accesibilidad.md`.
- [x] `[M0/M1/M2/M3/M4 · #39–#43]` ADR-004 en `ARCHITECTURE.md` + `mobile-android/` (`ve.psmhackaton.totpsoberano`: `README.md` con flujo de cédula V/E y compilación OpenJDK+Gradle, `AndroidManifest.xml`, `TotpEngine.kt`, `CedulaValidator.kt`, `OtpAuthParser.kt`, `KeystoreVault.kt`, `PinManager.kt` y `TotpEngineTest.kt`).
- [x] `[L1 · #58]` Paquete Android renombrado a `ve.psmhackaton.totpsoberano` (sin dominios gubernamentales reales), guía de compilación OpenJDK+Gradle en `mobile-android/README.md`, estado «en desarrollo» en `docs/cumplimiento/matriz-cumplimiento.html` y rama `laya` actualizada desde `staging` (pendiente `sh scripts/instalar-hooks.sh` tras fusionar PR `#59`).
- [x] `[F1/F2/F4/F5/F6 · #48/#49/#51/#52/#53]` `sitio-publico/` montado en el backend (`/`, `/instalar-certificado`, `/estado`, `/sitio/*`) con pruebas en `api.test.js`, Centro de ayuda `/ayuda` en `demo-portal-tramites/` con pruebas en `portal.test.js` y `scripts/capturas.js`.
- [x] `[F7 · #54 (base)]` Guion y plantilla de observación de usabilidad en `docs/evidencias/guion-usabilidad.md` (pendiente sesión presencial con 3 personas).

---

## FASE 3 — INTEGRACIÓN Y ENTREGA (Issue #16 C1)
- [x] `[C1 · #16]` Integración de `origin/diego` + `laya` verificada con todas las suites en verde y prueba E2E real contra el servidor HTTPS TLS 1.3.
- [ ] `[C1 · #16]` Pull Request `laya` → `staging` → `main` y ensayo de demo con el equipo del Reto 3.
- [ ] Hoja de ruta: modo sistema de `deploy/instalar.sh` como root en un servidor institucional real, app Android nativa completa (`mobile-android/`), sesión de usabilidad con 3 personas, HSM/TPM para la llave maestra.
- [ ] `[LEAD]` Solo bajo orden explícita `/push gitlab final`: sincronizar la entrega final en GitLab (`avance` y `terminado`).
