# TASKS.md — Pizarrón Vivo (`servicio-soberano-autenticacion-totp`)

> **Regla de Oro:** Solo se marca `[x]` con evidencia real en verde. Prohibido tocar `main`.
> **Remotos:** Pushes **EXCLUSIVAMENTE a GitHub (`origin`)**. **GitLab BLOQUEADO** hasta `/push gitlab final`.

---

## FASE 0 & FASE 1: Sincronización con `main`, Estructura y Contratos Congelados (`feat/lead-arquitectura-totp`)
- [x] `[LEAD]` Lectura de `docs/reto/`, `docs/analisis/analisis-tecnico.html` (`origin/main`) e `instructivo_gitlab.pdf`.
- [x] `[LEAD]` Alineación de estructura oficial de `main` + Puertos Hexagonales (`backend/`, `authenticator-app/`, `admin-console/`, `sdk/`, `demo-portal-tramites/`, `attack-lab/`, `deploy/`, `contracts/`).
- [x] `[LEAD]` Creación de guías al unísono (`AGENTS.md`, `ARCHITECTURE.md`, `ANALISIS_FASE0.md`, `SYSTEM_GRAPH.md`, `CONTRIBUTING.md`, `TASKS.md`, `.env.example`, `.gitignore`).
- [x] `[LEAD]` Contratos congelados (`contracts/openapi.yaml`, `contracts/schema.sql` PostgreSQL 16, `contracts/schema.sqlite.sql` fallback sin Docker, `contracts/mocks/*.json`).
- [ ] `[LEAD]` Subir rama `feat/lead-arquitectura-totp` a GitHub (`origin`) tras habilitación de permiso *Write* para `lya0509` en `PSM-Hackaton`.
- [ ] `[LEAD]` Emitir prompts oficiales de 8 secciones para cada compañero y guía de integración para el sub-equipo de Reto 1.

---

## FASE 2: Ejecución Paralela (Alineada al Plan Jueves 26 – Viernes 27)

### Track A — Backend & Criptografía (`feat/backend-*`)
- [ ] `[BACKEND]` `backend/src/core/totp/`: Motor RFC 6238 propio (`node:crypto`, SHA-256 32B / SHA-512 64B, truncado RFC 4226, drift + resync ±10) + tests contra vectores oficiales Apéndice B en verde.
- [ ] `[BACKEND]` `backend/src/core/vault/`: AES-256-GCM con AAD (`enrollment_id:key_version`), llave maestra versionada y rotación en lote.
- [ ] `[BACKEND]` `backend/src/core/tokens/`: JWT Ed25519 (`EdDSA`), `/.well-known/jwks.json`, `jti` único en `consumed_jti`, rotación `kid`.
- [ ] `[BACKEND]` `backend/src/infrastructure/persistence/` + `backend/migrations/`: Adaptadores PostgreSQL 16 y fallback SQLite WAL para las 8 tablas oficiales.
- [ ] `[BACKEND]` `backend/src/api/`: Endpoints completos de `contracts/openapi.yaml` (`enrollments`, `activate`, `verify`, `tokens/validate`, `resync`, `recovery`, `DELETE`, `/admin/api/*`).

### Track B — Frontend & UX (`feat/frontend-*`)
- [ ] `[FRONTEND]` `authenticator-app/`: PWA offline (React + Vite), bloqueo con PIN y semillas cifradas en dispositivo, alta QR + clave manual, SHA-256/SHA-512 (6/8 dígitos), anillo 30s y copia con un toque.
- [ ] `[FRONTEND]` `admin-console/`: Login RBAC (`Administrador`/`Operador`/`Auditor`) protegido con TOTP propio, gestión de `apps` y políticas, estados de enrolamiento, rotación de llaves 1-clic, alertas IA y verificador de integridad de cadena `audit_log`.
- [ ] `[FRONTEND]` `demo-portal-tramites/`: Flujo ciudadano completo (usuario+clave → desafío TOTP → JWT validado con `sdk/`).

### Track C — Seguridad, Infra, IA Local & Integración Reto 1 (`feat/security-*` / `feat/lead-*`)
- [ ] `[SECURITY]` `backend/src/security/`: Auth de apps (`client_id`/`client_secret`), rate limit, bloqueos progresivos (30s, 2m, 10m, 1h), cabeceras OWASP, cookies `HttpOnly; Secure; SameSite=Strict` + CSRF.
- [ ] `[AI]` `backend/src/heuristics/`: Detector local de anomalías (Isolation Forest / scoring conductual sobre `attempts`, 0 telemetría externa) + respuesta adaptativa.
- [ ] `[AUDIT]` `backend/src/audit/`: Bitácora encadenada (`prev_hash` → `hash`) + endpoint verificador de integridad + métricas anonimizadas.
- [ ] `[LEAD]` `sdk/`: SDK TypeScript para `demo-portal-tramites/` y el sub-equipo del **Reto 1**.
- [ ] `[QA]` `attack-lab/`: Scripts de ataque simulado (replay, fuerza bruta lenta/distribuida, password spraying, time-drift) con métricas de detección y latencia.
- [ ] `[INFRA]` `deploy/`: `docker-compose.yml` (PostgreSQL 16 + Caddy TLS 1.3) + `Caddyfile` (`tls internal`) + SBOM CycloneDX en `docs/sbom/` y `npm audit`.

---

## FASE 3: Integración, Demo y Entrega
- [ ] `[LEAD]` Integración completa en GitHub + prueba end-to-end con sub-equipo Reto 1.
- [ ] `[LEAD]` **CODE FREEZE** + `README.md` final con los 6 apartados oficiales + ensayo de demo en vivo.
- [ ] `[LEAD]` Solo bajo orden explícita `/push gitlab final`: sincronizar entrega final en GitLab (`avance` y `terminado`).
