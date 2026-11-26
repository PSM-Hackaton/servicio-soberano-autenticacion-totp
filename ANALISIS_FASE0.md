# FASE 0 — Auditoría de Problemática, Sincronización con `main` y Factibilidad Real

- **Reto:** Servicio Soberano de Autenticación Multifactorial basado en Tiempo (TOTP)
- **Repositorio GitHub:** `https://github.com/PSM-Hackaton/servicio-soberano-autenticacion-totp`
- **Base alineada:** `docs/analisis/analisis-tecnico.html` (commit `95c0fbd` en `main`, Diego Landaeta) + patrón **Hexagonal (Ports & Adapters)** + integración con sub-equipo de **Reto 1**.
- **Política de Remotos:** Trabajo y pushes **exclusivamente en GitHub (`origin`)**. **GitLab BLOQUEADO** hasta orden literal `/push gitlab final`. Nunca tocar `main`.

---

## 1. Radiografía y Convergencia Técnica

El análisis de `docs/analisis/analisis-tecnico.html` y nuestra auditoría coinciden en el 95% de las decisiones clave:
- **Stack unificado:** Node.js 22 + TypeScript + Fastify + `node:crypto` nativo (sin librerías OTP externas) + React/Vite.
- **Criptografía soberana:** RFC 6238 propio verificado con vectores oficiales del Apéndice B (`HMAC-SHA256` y `HMAC-SHA512`, 6 u 8 dígitos), AES-256-GCM con AAD (`enrollment_id + key_version`), Ed25519 JWT/JWKS con `jti` de un solo uso y rotación `kid`, 10 códigos de recuperación (`scrypt`), anonimización con pepper y bitácora encadenada por hashes (`prev_hash -> hash`).
- **Flujo completo:** Enrolamiento pendiente (`POST /api/v1/enrollments`) → Activación (`POST /api/v1/enrollments/{id}/activate`) → Verificación (`POST /api/v1/verify`) → Validación de token (`POST /api/v1/tokens/validate`) + resincronización con 2 códigos (`resync`) + recuperación (`recovery`).

### Hallazgo crítico de hardware en la estación del hackatón
- `docs/analisis/analisis-tecnico.html` propone **Docker Compose + PostgreSQL 16 + Caddy**.
- En la estación Ubuntu verificada del hackatón (**12 cores, 14 GB RAM, Node 22, Python 3.14**) **NO está instalado Docker (`docker: orden no encontrada`)**.
- **Resolución sin fricción (Puertos Hexagonales):** Mantener `deploy/docker-compose.yml` + `contracts/schema.sql` (PostgreSQL 16) para el despliegue oficial / equipos con Docker, **Y** añadir un adaptador de persistencia `SQLite WAL` (`contracts/schema.sqlite.sql`) + TLS nativo de Node para desarrollo y pruebas locales en estaciones sin Docker.

### Decisiones abiertas registradas para cerrar en equipo (Sección 13 de `main`)
1. Dígitos por defecto: **6 dígitos** (recomendado para UX ágil, con política configurable a **8 dígitos** + SHA-512 para demostrar superioridad frente a apps comerciales).
2. Ventana de deriva por defecto: **±1 paso (±30s)** con seguimiento automático de `drift_steps` y resincronización amplia (±10 pasos con 2 códigos consecutivos).
3. Modo compatibilidad SHA-1: **desactivado por defecto**, habilitable por política por app con advertencia explícita de seguridad.

---

## 2. Prueba de Estrés Real (Defensa ante Jurado)

- **Fuerza bruta y DDoS en `/api/v1/verify`:** Con 6 dígitos y ventana ±1 hay 3/1,000,000 códigos válidos (~0.0015% por ciclo de 5 intentos). Se mitiga en capas: rate limit en borde (Caddy/Fastify, <2 ms, `429`), bloqueo progresivo exponencial (30 s → 2 min → 10 min → 1 h), anti-replay atómico (`T > last_step`) y detector local de anomalías (fuerza bruta distribuida / *spraying*).
- **Sostenibilidad económica:** **\$0 operativo**, 100% software libre (FOSS), 0 llamadas a Internet.
- **Plan B de demo en vivo:** Alta por clave manual además de QR (si la cámara móvil rechaza CA interna HTTPS), modo dual Docker/Sin-Docker y `attack-lab/` automatizado que demuestra ante el jurado en tiempo real cómo se bloquean *replay*, fuerza bruta distribuida y *spraying* mientras se verifica la cadena de hashes en `admin-console/`.

---

## 3. Corte Quirúrgico (Jue 26 → Vie 27) y Prioridades

1. **Prioridad P0 (Jue tarde–noche):** Motor RFC 6238 con vectores oficiales en verde → Vault AES-256-GCM (AAD) → Esquema BD → Endpoints `enrollments`, `activate`, `verify`, `tokens/validate`, `jwks.json` → Anti-replay + deriva + rate limit → PWA mostrando códigos (QR + manual).
2. **Prioridad P1 (Vie mañana):** Consola admin (RBAC + TOTP propio, políticas, revocación, rotación de llaves, verificador de cadena `audit_log`) → `sdk/` + `demo-portal-tramites/` + integración con Reto 1 → `heuristics/` (detector local) + `attack-lab/`.
3. **Prioridad P2 (Vie tarde — Code Freeze):** Caddy TLS 1.3 / Docker Compose, SBOM CycloneDX + `npm audit`, `README.md` final (6 apartados) y ensayo de demo.
