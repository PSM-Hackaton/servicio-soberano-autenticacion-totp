# TASKS.md — Pizarrón Vivo (`servicio-soberano-autenticacion-totp`)

> **Regla de Oro:** solo se marca `[x]` con evidencia real en verde. Prohibido tocar `main`.
> **Remotos:** pushes **EXCLUSIVAMENTE a GitHub (`origin`)**. **GitLab BLOQUEADO** hasta `/push gitlab final`.
> **Última verificación:** 26-11-2026, `cd backend && npm test` → **156 pruebas, 0 fallos**.

---

## FASE 0 & FASE 1: Sincronización con `main`, Estructura y Contratos
- [x] `[LEAD]` Lectura de `docs/reto/`, `docs/analisis/analisis-tecnico.html` (`origin/main`) e `instructivo_gitlab.pdf`.
- [x] `[LEAD]` Estructura oficial (`backend/`, `authenticator-app/`, `admin-console/`, `sdk/`, `demo-portal-tramites/`, `attack-lab/`, `deploy/`, `contracts/`).
- [x] `[LEAD]` Guías al unísono (`AGENTS.md`, `ARCHITECTURE.md`, `ANALISIS_FASE0.md`, `SYSTEM_GRAPH.md`, `CONTRIBUTING.md`, `TASKS.md`, `.env.example`, `.gitignore`).
- [x] `[LEAD]` Contratos alineados con el código (26-11-2026): `contracts/openapi.yaml` (22 operaciones, YAML validado), `contracts/schema.sqlite.sql` (copia exacta de la migración), `contracts/schema.sql` (referencia PostgreSQL, no usada) y `contracts/mocks/` regenerados con respuestas reales del servicio.
- [x] `[LEAD]` Rama `laya` comparada contra `origin/main`, `origin/staging` y `origin/diego`, y publicada en GitHub (`origin/laya`).
- [ ] `[LEAD]` Emitir prompts oficiales de 8 secciones para cada compañero y guía de integración para el sub-equipo de Reto 1.

---

## FASE 2: Ejecución Paralela (Plan Jueves 26 – Viernes 27)

### Track A — Backend y Criptografía (verificado con `npm test` en `backend/`)
- [x] `[BACKEND]` `core/totp/`: motor RFC 4226/6238 propio (SHA-256 32 B / SHA-512 64 B / SHA-1 20 B opcional, truncado dinámico, deriva, resync ±10, URI otpauth) con vectores del Apéndice B — **10 pruebas**.
- [x] `[BACKEND]` `core/vault/`: AES-256-GCM con AAD (`enrollment_id:key_version`), llavero versionado, recifrado, HMAC con pepper y pepper diario — **12 pruebas**.
- [x] `[BACKEND]` `core/tokens/`: Ed25519, JWT EdDSA, JWKS, `kid` por huella, rechazo de `alg` ajenos — **16 pruebas**.
- [x] `[BACKEND]` `core/qr/`: codificador QR propio (Reed-Solomon, versiones 1-40) y SVG — **11 pruebas**.
- [x] `[BACKEND]` `infrastructure/persistence/` + `migrations/001_esquema.sql`: SQLite WAL (`node:sqlite`), 8 tablas, repositorios y anti replay atómico — **10 pruebas**.
- [x] `[BACKEND]` `infrastructure/config/`: parser `.env` propio, validación de configuración y claves de firma (`firmas.js`) — **11 pruebas**.
- [x] `[BACKEND]` `api/`: servidor `node:https` (TLS 1.3), 22 rutas de `contracts/openapi.yaml`, CORS, sesiones admin con CSRF, estáticos, salud y métricas — **21 pruebas**.
- [x] `[BACKEND]` `application/use-cases/`: enrolar, activar, verificar, validar token, resync, recuperación, revocación, JWKS y consola con RBAC e idempotencia — **22 pruebas**.
- [x] `[BACKEND]` Arranque (`main.js`) y scripts (`npm run env`, `npm run certs`, `npm run seed`): verificado de punta a punta el 26-11-2026 levantando el servicio en un entorno temporal y ejecutando el flujo completo (respuestas guardadas en `contracts/mocks/`).

### Track B — Frontend y UX
- [ ] `[FRONTEND]` `authenticator-app/`: PWA HTML/CSS/JS propios, offline, PIN y semillas cifradas en el dispositivo, alta QR + clave manual, SHA-256/SHA-512 (6/8 dígitos) — *en curso*.
- [ ] `[FRONTEND]` `admin-console/`: login con TOTP propio, RBAC (`Administrador`/`Operador`/`Auditor`), apps y políticas, enrolamientos, rotación de llaves, alertas y verificador de cadena `audit_log` — *en curso*.
- [ ] `[FRONTEND]` `demo-portal-tramites/`: flujo ciudadano completo (usuario + clave → desafío TOTP → JWT validado con `sdk/`) — *en curso*.

### Track C — Seguridad, Detector Local, Auditoría e Integración
- [x] `[SECURITY]` `security/`: autenticación de apps (`client_id`/`client_secret` con scrypt), límites de tasa, bloqueo progresivo (30 s, 2 min, 10 min, 1 h), validación cerrada, errores genéricos y cabeceras OWASP — **17 pruebas**.
- [x] `[AI]` `heuristics/`: detector local (Isolation Forest propio + reglas explicables sobre `attempts`, sin telemetría externa) con respuesta adaptativa — **9 pruebas**.
- [x] `[AUDIT]` `audit/`: bitácora encadenada (`prev_hash` → `hash`), verificación de integridad y métricas — **17 pruebas**.
- [ ] `[LEAD]` `sdk/`: SDK JavaScript para `demo-portal-tramites/` y el sub-equipo del **Reto 1** — *en curso*.
- [ ] `[QA]` `attack-lab/`: escenarios de ataque simulado (replay, fuerza bruta, fuerza bruta distribuida, spraying, inundación, JWT, entradas, caos) con métricas de detección y latencia — *en curso*.
- [ ] `[INFRA]` `deploy/`: unidad `systemd` de ejemplo y guía de despliegue institucional sin Docker (`deploy/README.md`) — redactada, pendiente de probar en el servidor institucional.
- [ ] `[DOCS]` SBOM en `docs/sbom/`, `docs/api/` y `README.md` final — *en curso*.

---

## FASE 3: Integración, Demo y Entrega
- [ ] `[LEAD]` Integración completa en GitHub + prueba de punta a punta con el sub-equipo Reto 1.
- [ ] `[LEAD]` **CODE FREEZE** + `README.md` final con los 6 apartados oficiales + ensayo de demo en vivo.
- [ ] `[LEAD]` Solo bajo orden explícita `/push gitlab final`: sincronizar la entrega final en GitLab (`avance` y `terminado`).
