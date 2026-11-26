# AGENTS.md — Guía Maestra al Unísono (`servicio-soberano-autenticacion-totp`)

> **LECTURA OBLIGATORIA:** toda persona o herramienta automatizada que contribuya al repositorio (de J Laya, Diego, Giovani, Javier o cualquier compañero, sin importar el IDE) **DEBE leer este archivo, `docs/analisis/analisis-tecnico.html`, `ARCHITECTURE.md`, `SYSTEM_GRAPH.md`, `contracts/` y `TASKS.md` antes de crear, modificar o proponer cualquier código.**
>
> **Alineado con el código el 26-11-2026.** Cuando un documento y el código discrepen, manda el código de `backend/` y se corrige el documento.

---

## 1. Contexto Oficial del Proyecto

- **Repositorio de trabajo (GitHub):** `https://github.com/PSM-Hackaton/servicio-soberano-autenticacion-totp`
- **Documento rector técnico en `main`:** `docs/analisis/analisis-tecnico.html` (autor: Diego Landaeta, v1.0). Sus propuestas de Docker Compose, PostgreSQL y Caddy fueron sustituidas por la decisión del 26-11-2026 (ADR-002 de `ARCHITECTURE.md`).
- **Reto oficial:** **Servicio Soberano de Autenticación Multifactorial basado en Tiempo (TOTP)** *(ver `docs/reto/AutenticaciónMultifactorial_TerminosEspecificaciones.pdf`)*.
- **Integración con Reto 1:** el sub-equipo del **Reto 1 (Agente Evaluador de Propuestas de Servicios)** se integra como una `app` cliente más en la tabla `apps` (`client_id` + `client_secret`) usando `sdk/`, igual que `demo-portal-tramites/`.
- **Soberanía y costo operativo:** **\$0 en APIs externas**, **100 % local / sin llamadas a Internet**, cero dependencias npm, cero librerías OTP externas (motor RFC 6238 propio sobre `node:crypto`), sin servicios en nubes extranjeras.

---

## 2. Reglas Inquebrantables de Git, GitHub y GitLab

1. **PROHIBIDO tocar `main`:** nunca hagas `commit` ni `push` directo a `main`.
2. **POLÍTICA DE REMOTOS (ORDEN ESTRICTA DE J LAYA):**
   - **GitHub (`origin`):** **EXCLUSIVO para todas las subidas, PRs y trabajo diario del equipo.**
   - **GitLab (`gitlab`):** **BLOQUEADO.** Prohibido ejecutar `git push` hacia GitLab hasta que J Laya dé la orden literal **`/push gitlab final`**.
3. **Flujo de ramas en GitHub:**
   - Ramas activas del equipo en GitHub: **`laya`** (J Laya), **`diego`** (Diego Landaeta), más ramas `feat/<rol>-<modulo>` si se requiere subdividir.
   - Integración en GitHub: Pull Request hacia **`staging`** (revisado antes de pasar a `main`). Prohibido commit/push directo a `main`.
   - Solo al recibir `/push gitlab final`, se sincroniza la entrega oficial en GitLab (`avance` y `terminado`) con el `README.md` obligatorio de 6 apartados.
4. **Contratos (`contracts/`):** reflejan lo implementado (`openapi.yaml`, `schema.sqlite.sql` copia de `backend/migrations/001_esquema.sql`, `mocks/` con respuestas reales). Prohibido inventar campos o renombrar rutas sin cambiar a la vez el código, `contracts/openapi.yaml` y `SYSTEM_GRAPH.md`.
5. **Cero secretos en Git:** nunca commitear `.env`, llaves maestras, `*.pem`, `*.key`, `*.crt`, `*.db` ni secretos reales (ver `.gitignore`).
6. **Protocolo Graphy (`SYSTEM_GRAPH.md`):** leer antes de escribir código; agregar nodos nuevos y podar nodos obsoletos en cada avance.

---

## 3. Estructura Real del Repositorio

```text
servicio-soberano-autenticacion-totp/
├── AGENTS.md                        # Esta guía
├── ARCHITECTURE.md                  # ADR y módulos reales
├── ANALISIS_FASE0.md                # Auditoría Fase 0 y factibilidad en estaciones sin Docker
├── SYSTEM_GRAPH.md                  # Grafo vivo de conexiones (Protocolo Graphy)
├── CONTRIBUTING.md                  # Reglas GitHub, bloqueo GitLab y Code Freeze
├── TASKS.md                         # Pizarrón de tareas verificadas
├── .env.example                     # Variables que lee el backend (plantilla de `npm run env`)
├── contracts/
│   ├── openapi.yaml                 # API v1, consola y sistema (OpenAPI 3.1)
│   ├── schema.sqlite.sql            # Esquema en uso (copia de backend/migrations/001_esquema.sql)
│   ├── schema.sql                   # PostgreSQL: referencia para despliegues futuros, no usado
│   └── mocks/                       # Respuestas reales del servicio con secretos ficticios
├── backend/                         # Servicio en JavaScript ESM, Node.js 22, sin dependencias
│   ├── src/
│   │   ├── core/totp/               # RFC 4226/6238 propio, Base32, deriva y resync
│   │   ├── core/vault/              # AES-256-GCM con AAD, llavero versionado, HMAC con pepper
│   │   ├── core/tokens/             # Ed25519, JWT EdDSA, JWKS, kid por huella
│   │   ├── core/qr/                 # Codificador QR propio y salida SVG
│   │   ├── security/                # Validación cerrada, errores genéricos, límites, bloqueos, scrypt
│   │   ├── audit/                   # Bitácora encadenada por hashes y métricas
│   │   ├── heuristics/              # Detector local de anomalías (Isolation Forest + reglas)
│   │   ├── application/use-cases/   # Casos de uso MFA y consola, RBAC, bloqueos, esquemas
│   │   ├── infrastructure/persistence/ # node:sqlite (WAL), migraciones, repositorios
│   │   ├── infrastructure/config/   # .env propio, validación, claves de firma
│   │   ├── api/                     # Servidor node:https, router, CORS, sesiones, estáticos
│   │   └── main.js                  # Ensamblado y arranque
│   ├── migrations/001_esquema.sql   # 8 tablas SQLite
│   └── scripts/                     # generar-env.js, certificados.js, semilla.js
├── authenticator-app/               # PWA HTML/CSS/JS propios (servida en /app/)
├── admin-console/                   # Consola HTML/CSS/JS propios (servida en /consola/)
├── sdk/                             # SDK JavaScript sin dependencias para integradores
├── demo-portal-tramites/            # Portal institucional de ejemplo conectado al SDK
├── attack-lab/                      # Escenarios de ataque simulado y caos
├── deploy/                          # Unidad systemd y guía de despliegue institucional
└── docs/                            # reto/, analisis/, api/, sbom/
```

---

## 4. Invariantes Criptográficas y de Seguridad (Obligatorias)

1. **Motor TOTP propio (RFC 6238 sin librerías OTP externas):** solo `node:crypto`; semillas CSPRNG de 32 bytes (SHA-256), 64 bytes (SHA-512) y 20 bytes (SHA-1, solo si la app lo permite); truncado dinámico RFC 4226; comparación en tiempo constante; pruebas contra los vectores del Apéndice B del RFC 6238; compensación de deriva y resincronización con 2 códigos consecutivos (±10 pasos).
2. **AES-256-GCM con AAD:** nonce aleatorio de 96 bits + AAD = `enrollment_id + ":" + key_version`, para que un cifrado no pueda copiarse a otra fila. Llave maestra fuera de la base (`MASTER_KEY_<VERSION>_HEX`) y versionada para rotación en lote.
3. **Anti replay atómico y `jti` de un solo uso:** guardar `last_step` aceptado y exigir `T > last_step` en el mismo `UPDATE`; marcar cada `jti` en `consumed_jti` al validarlo en `/api/v1/tokens/validate`.
4. **10 códigos de recuperación:** generados al activar (`/enrollments/{id}/activate`), mostrados una sola vez y guardados con scrypt. Usar uno revoca el enrolamiento (obliga a re-enrolar).
5. **Anonimización con pepper:** `user_ref_hash = HMAC-SHA256(user_ref, USER_REF_PEPPER)` (nunca nombres ni correos en la base) e `ip_hash = HMAC-SHA256(ip, pepper diario)` derivado de `DAILY_IP_PEPPER_SEED`.
6. **Bitácora encadenada (`audit_log`):** cada registro guarda `prev_hash` y `hash = SHA-256(prev_hash + "|" + JSON canónico)`, verificable desde la consola (`/admin/api/audit/verify-chain`).
7. **OWASP Top 10 y anti DDoS:** esquemas JSON cerrados (`additionalProperties: false`), errores genéricos (sin enumeración de usuarios), sesiones admin con cookie `sst_admin` `HttpOnly; Secure; SameSite=Strict` + `X-CSRF-Token` + TOTP propio, límites de tasa + bloqueo progresivo (30 s, 2 min, 10 min, 1 h), TLS 1.3 con `node:https`, falla cerrado (503) y cero dependencias de terceros (SBOM trivial).
8. **Detector local de anomalías (10 % del baremo):** sin telemetría externa, sobre `attempts` (cuentas por IP, IPs por cuenta, ritmo entre intentos, proporción de fallos, hora inusual) más Isolation Forest propio, con respuesta adaptativa (permitir, alerta, espera extra, bloqueo temporal) demostrada en vivo con `attack-lab/`.

---

## 5. Nota Operativa (estaciones sin Docker)

- El servicio se ejecuta con **Node.js 22 sin instalar nada**: `node:sqlite` (SQLite WAL) y `node:https` (`TLS_MODE=node`). No se usan Docker, PostgreSQL ni Caddy.
- Arranque local: `cd backend && npm run env && npm run certs && npm run seed && npm start` (ver `ARCHITECTURE.md`, sección 6).
- Despliegue institucional: unidad `systemd` de `deploy/` (ver `deploy/README.md`).

---

## 6. Protocolo de Entrega

Al cerrar una tarea en tu rama:
1. Verificar que **no** modificaste `main` ni carpetas ajenas.
2. Ejecutar y adjuntar evidencia real de pruebas (`cd backend && npm test`, `cd sdk && npm test`, etc.).
3. Actualizar `TASKS.md` y `SYSTEM_GRAPH.md`.
4. Hacer `push` **exclusivamente a GitHub (`origin`)**; jamás a GitLab sin `/push gitlab final`.
