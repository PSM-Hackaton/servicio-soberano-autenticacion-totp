# FASE 0 — Auditoría de Problemática, Sincronización con `main` y Factibilidad Real

- **Reto:** Servicio Soberano de Autenticación Multifactorial basado en Tiempo (TOTP)
- **Repositorio GitHub:** `https://github.com/PSM-Hackaton/servicio-soberano-autenticacion-totp`
- **Base:** `docs/analisis/analisis-tecnico.html` (commit `95c0fbd` en `main`, Diego Landaeta) + integración con el sub-equipo de **Reto 1**.
- **Política de remotos:** trabajo y pushes **exclusivamente en GitHub (`origin`)**. **GitLab BLOQUEADO** hasta la orden literal `/push gitlab final`. Nunca tocar `main`.
- **Actualizado el 26-11-2026** para reflejar el stack realmente implementado (ver `ARCHITECTURE.md`).

---

## 1. Radiografía y Convergencia Técnica

El análisis de `docs/analisis/analisis-tecnico.html` y la auditoría coinciden en las decisiones de seguridad; el stack se simplificó para que todo corra en las estaciones sin instalar nada:
- **Stack implementado:** Node.js 22 + JavaScript ESM sin dependencias npm: `node:https` (servidor y enrutador propios), `node:crypto`, `node:sqlite` y `node:test`. Frontends en HTML, CSS y JavaScript propios.
- **Criptografía soberana:** RFC 6238 propio verificado con los vectores del Apéndice B (HMAC-SHA-256 y HMAC-SHA-512, 6 u 8 dígitos), AES-256-GCM con AAD (`enrollment_id:key_version`), JWT Ed25519/JWKS con `jti` de un solo uso y rotación de `kid`, 10 códigos de recuperación (scrypt), anonimización con pepper y bitácora encadenada por hashes (`prev_hash -> hash`).
- **Flujo completo:** enrolamiento pendiente (`POST /api/v1/enrollments`) → activación (`POST /api/v1/enrollments/{id}/activate`) → verificación (`POST /api/v1/verify`) → validación del token (`POST /api/v1/tokens/validate`) + resincronización con 2 códigos (`resync`) + recuperación (`recovery`) + revocación (`DELETE`).

### Hallazgo de hardware en la estación del hackatón
- `docs/analisis/analisis-tecnico.html` proponía Docker Compose + PostgreSQL 16 + Caddy.
- En la estación Ubuntu verificada (**12 núcleos, 14 GB de RAM, Node 22**) **no está instalado Docker** (`docker: orden no encontrada`).
- **Resolución adoptada (26-11-2026):** se descartan Docker, PostgreSQL y Caddy. Persistencia en SQLite WAL con `node:sqlite` (`backend/migrations/001_esquema.sql`, copiada en `contracts/schema.sqlite.sql`) y TLS 1.3 nativo de Node (`TLS_MODE=node`). `contracts/schema.sql` queda solo como referencia PostgreSQL para despliegues futuros. El despliegue institucional se hace con una unidad `systemd` (`deploy/`).

### Decisiones abiertas cerradas
1. Dígitos por defecto: **6** (política por app configurable a **8**, con SHA-512 disponible).
2. Ventana por defecto: **±1 paso (±30 s)** con seguimiento de `drift_steps` y resincronización amplia (±10 pasos con 2 códigos consecutivos).
3. SHA-1: **desactivado por defecto**, habilitable por app (`permitir_sha1`).

---

## 2. Prueba de Estrés Real (Defensa ante Jurado)

- **Fuerza bruta y DDoS en `/api/v1/verify`:** con 6 dígitos y ventana ±1 hay 3/1 000 000 códigos válidos (~0,0015 % por ciclo de 5 intentos). Se mitiga en capas: límite global por IP en el propio servidor (300/min, antes de cualquier operación costosa, `429`), límite por app (600/min), bloqueo progresivo (30 s → 2 min → 10 min → 1 h), anti replay atómico (`T > last_step`) y detector local de anomalías (fuerza bruta distribuida, *spraying*) con bloqueo adaptativo de 300 s.
- **Sostenibilidad económica:** **\$0 operativo**, sin dependencias de terceros, 0 llamadas a Internet.
- **Plan B de demo en vivo:** alta con clave manual además del QR (si la cámara rechaza la CA interna), `HEURISTICS_MODE=mock` para clientes en paralelo y `attack-lab/` automatizado que demuestra en tiempo real el bloqueo de *replay*, fuerza bruta distribuida y *spraying* mientras se verifica la cadena de hashes en `admin-console/`.

---

## 3. Corte Quirúrgico (Jue 26 → Vie 27) y Prioridades

1. **P0 (Jue tarde–noche):** motor RFC 6238 con vectores oficiales en verde → bóveda AES-256-GCM (AAD) → esquema SQLite → endpoints `enrollments`, `activate`, `verify`, `tokens/validate`, `jwks.json` → anti replay + deriva + límites → PWA mostrando códigos (QR + manual). *Backend completado y probado (156 pruebas).*
2. **P1 (Vie mañana):** consola admin (RBAC + TOTP propio, políticas, rotación de llaves, verificador de cadena) → `sdk/` + `demo-portal-tramites/` + integración con Reto 1 → `attack-lab/`.
3. **P2 (Vie tarde — Code Freeze):** guía de despliegue institucional (`deploy/`), SBOM, `README.md` final (6 apartados) y ensayo de demo.
