# AGENTS.md — Guía Maestra al Unísono (`servicio-soberano-autenticacion-totp`)

> **LECTURA OBLIGATORIA:** Todo agente de IA (de J Laya, Diego, Giovani, Javier o cualquier compañero, sin importar modelo o IDE) **DEBE leer este archivo, `docs/analisis/analisis-tecnico.html`, `ARCHITECTURE.md`, `SYSTEM_GRAPH.md`, `contracts/` y `TASKS.md` antes de crear, modificar o proponer cualquier código.**

---

## 1. Contexto Oficial del Proyecto

- **Repositorio de trabajo (GitHub):** `https://github.com/PSM-Hackaton/servicio-soberano-autenticacion-totp`
- **Documento rector técnico en `main`:** `docs/analisis/analisis-tecnico.html` (autor: Diego Landaeta, v1.0).
- **Reto oficial:** **Servicio Soberano de Autenticación Multifactorial basado en Tiempo (TOTP)** *(ver `docs/reto/AutenticaciónMultifactorial_TerminosEspecificaciones.pdf`)*.
- **Integración con Reto 1:** El sub-equipo del **Reto 1 (Agente Evaluador de Propuestas de Servicios)** se integra como una `app` cliente más en nuestra tabla `apps` (`client_id` + `client_secret`) usando nuestro `sdk/`, exactamente igual que `demo-portal-tramites/`.
- **Soberanía y costo operativo:** **\$0 en APIs externas**, **100% local / sin llamadas a Internet**, cero librerías OTP externas (motor RFC 6238 propio sobre `node:crypto`), cero dependencia de Google Authenticator Cloud, Auth0 o nubes extranjeras.

---

## 2. Reglas Inquebrantables de Git, GitHub y GitLab

1. **PROHIBIDO tocar `main`:** Nunca hagas `commit` ni `push` directo a `main`.
2. **POLÍTICA DE REMOTOS (ORDEN ESTRICTA DE J LAYA):**
   - **GitHub (`origin`):** **EXCLUSIVO para todas las subidas, PRs y trabajo diario del equipo.**
   - **GitLab (`gitlab`):** **BLOQUEADO.** Prohibido ejecutar `git push` hacia GitLab hasta que J Laya dé la orden literal **`/push gitlab final`**.
3. **Flujo de ramas en GitHub:**
   - Ramas activas del equipo en GitHub: **`laya`** (J Laya), **`diego`** (Diego Landaeta), más ramas `feat/<rol>-<modulo>` si se requiere subdividir.
   - Integración en GitHub: Pull Request hacia **`staging`** (revisado antes de pasar a `main`). Prohibido commit/push directo a `main`.
   - Solo al recibir `/push gitlab final`, se sincroniza la entrega oficial en GitLab (`avance` y `terminado`) con el `README.md` obligatorio de 6 apartados.
4. **Contratos congelados (`contracts/`):** Fuente única de verdad alineada a la Sección 6 y 7 de `docs/analisis/analisis-tecnico.html`. Prohibido inventar campos o renombrar rutas sin actualizar `contracts/openapi.yaml` y `SYSTEM_GRAPH.md`.
5. **Cero secretos en Git:** Nunca commitear `.env`, llaves maestras, `*.pem`, `*.key`, `*.crt`, `*.db` ni secretos reales.
6. **Protocolo Graphy (`SYSTEM_GRAPH.md`):** Leer antes de escribir código; agregar nodos nuevos y podar nodos obsoletos en cada avance.

---

## 3. Estructura Oficial del Repositorio (Alineada 100% con `main` + Puertos Hexagonales)

```text
servicio-soberano-autenticacion-totp/
├── AGENTS.md                        # Guía maestra al unísono para todos los agentes
├── ARCHITECTURE.md                  # ADR, arquitectura hexagonal+modular, dual DB (PG16 / SQLite fallback)
├── ANALISIS_FASE0.md                # Auditoría Fase 0, estrés hardware (con y sin Docker) y cronograma
├── SYSTEM_GRAPH.md                  # Grafo vivo de conexiones (Protocolo Graphy)
├── CONTRIBUTING.md                  # Reglas GitHub, bloqueo GitLab y Code Freeze
├── TASKS.md                         # Pizarrón vivo de tareas verificadas
├── .env.example                     # Variables de entorno sin secretos
├── contracts/                       # Contratos congelados (OpenAPI v1, SQL Postgres + SQLite, Mocks JSON)
│   ├── openapi.yaml
│   ├── schema.sql                   # PostgreSQL 16 (producción / Docker Compose)
│   ├── schema.sqlite.sql            # Fallback SQLite WAL (nodos sin Docker)
│   └── mocks/
├── backend/                         # API Fastify + TypeScript (Node.js 22)
│   ├── src/
│   │   ├── core/totp/               # Motor RFC 6238 propio (CSPRNG, HMAC-SHA256/512, drift, tests RFC)
│   │   ├── core/vault/              # AES-256-GCM con AAD (enrollment_id+key_version), llave maestra versionada
│   │   ├── core/tokens/             # JWT Ed25519 (EdDSA), JWKS, jti un solo uso, rotación kid
│   │   ├── application/             # Puertos Hexagonales (ports/in, ports/out) y casos de uso
│   │   ├── security/                # Rate limit, bloqueos progresivos, validación estricta, auth apps
│   │   ├── heuristics/              # Detector local de anomalías (Isolation Forest / scoring <15ms)
│   │   ├── audit/                   # Bitácora encadenada por hashes (prev_hash -> hash) y métricas anon
│   │   ├── api/                     # Rutas /api/v1/*, /.well-known/jwks.json y /admin/api/*
│   │   └── infrastructure/          # Adaptadores persistence (PostgreSQL + SQLite fallback) y config DI/TLS
│   └── migrations/                  # Migraciones SQL PostgreSQL
├── authenticator-app/               # PWA autenticadora soberana (React + Vite, offline, PIN, SHA256/512)
├── admin-console/                   # Consola administrativa (React + Vite, RBAC + TOTP propio, métricas)
├── sdk/                             # SDK TypeScript para integradores (Portal de Trámites y Reto 1)
├── demo-portal-tramites/            # Sistema institucional de ejemplo conectado al SDK
├── attack-lab/                      # Scripts de ataque simulado (replay, fuerza bruta, spraying, drift)
├── deploy/                          # docker-compose.yml (PostgreSQL 16 + Caddy TLS 1.3) y Caddyfile
└── docs/                            # reto/, analisis/ (analisis-tecnico.html/pdf), api/, sbom/
```

---

## 4. Invariantes Criptográficas y de Seguridad (Obligatorias)

1. **Motor TOTP Propio (RFC 6238 sin librerías OTP externas):** Sobre `node:crypto` únicamente; semillas de 32 bytes (SHA-256) y 64 bytes (SHA-512) vía CSPRNG; truncado dinámico RFC 4226; comparación en tiempo constante (`timingSafeEqual`); tests obligatorios contra vectores del Apéndice B del RFC 6238; compensación de *time-drift* y flujo de resincronización con 2 códigos consecutivos (±10 pasos).
2. **AES-256-GCM con AAD:** Nonce aleatorio de 96 bits + AAD = `enrollment_id + ":" + key_version` para que un cifrado no pueda copiarse a otra fila. Llave maestra fuera de BD y versionada para rotación en lote.
3. **Anti-Replay Atómico y `jti` de un solo uso:** Guardar `last_step` aceptado y exigir estrictamente `T > last_step`; marcar cada `jti` en `consumed_jti` al validarlo en `/api/v1/tokens/validate`.
4. **10 Códigos de Recuperación:** Generados al activar (`/enrollments/{id}/activate`), mostrados una sola vez y guardados con hash `scrypt`.
5. **Anonimización con Pepper:** `user_ref_hash = HMAC-SHA256(user_ref, USER_PEPPER)` (nunca nombres ni correos en BD) e `ip_hash = HMAC-SHA256(ip, DAILY_IP_PEPPER)` con pepper rotativo diario.
6. **Bitácora Encadenada (`audit_log`):** Cada registro guarda `prev_hash` y `hash = SHA-256(prev_hash || payload)` verificable desde la consola admin.
7. **OWASP Top 10 & Anti-DDoS:** Esquemas JSON cerrados (`additionalProperties: false`), respuestas de error genéricas (sin enumeración de usuarios), sesiones admin con cookies `HttpOnly; Secure; SameSite=Strict` + CSRF + TOTP propio, *rate limiting* + bloqueo progresivo (30s, 2m, 10m, 1h), TLS 1.3 (Caddy en Docker o Node HTTPS en modo sin Docker) y **SBOM CycloneDX + `npm audit`**.
8. **IA Local (10% del baremo):** Detector local (sin telemetría externa) sobre `attempts` (fallos/cuenta, IPs distintas/cuenta, cuentas/IP, ritmo entre intentos, hora inusual) con respuesta adaptativa (permitir, espera extra, bloqueo temporal, alerta) demostrado en vivo con `attack-lab/`.

---

## 5. Nota Operativa de Hardware (Docker vs. Sin Docker)

- En entornos **con Docker** (`deploy/docker-compose.yml`): levanta PostgreSQL 16 + Caddy TLS 1.3 + API + Frontends en 1 comando.
- En estaciones del hackatón **sin Docker** (verificado en este nodo Ubuntu): gracias a los **Puertos Hexagonales** en `backend/src/application/ports/out/`, el backend debe soportar `DB_DRIVER=sqlite` (con `contracts/schema.sqlite.sql`) y `TLS_MODE=node` para desarrollar y probar localmente sin bloqueo alguno.

---

## 6. Protocolo de Entrega de Cualquier Agente

Al cerrar una tarea en tu rama `feat/<rol>-<modulo>`:
1. Verificar que **no** modificaste `main` ni carpetas ajenas.
2. Ejecutar y adjuntar evidencia real de tests/build (`npm test`, vectores RFC 6238, `npm run build`).
3. Actualizar `TASKS.md` y `SYSTEM_GRAPH.md`.
4. Hacer `push` **exclusivamente a GitHub (`origin`)**; jamás a GitLab sin `/push gitlab final`.
