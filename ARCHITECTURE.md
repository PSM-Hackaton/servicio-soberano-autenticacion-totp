# ARCHITECTURE.md — Servicio Soberano de Autenticación TOTP

> **Alineado con el código el 26-11-2026.** La fuente de verdad es la implementación de `backend/`.
> Contratos: `contracts/openapi.yaml` (API), `contracts/schema.sqlite.sql` (base de datos, copia de
> `backend/migrations/001_esquema.sql`) y `contracts/mocks/` (respuestas reales con secretos ficticios).

---

## 1. Decisiones Arquitectónicas (ADR)

### ADR-001: Monolito modular con inyección de dependencias por funciones fábrica
- **Decisión:** un único proceso Node.js con módulos separados por responsabilidad dentro de `backend/src/`. Cada módulo expone funciones puras o fábricas (`crearVault`, `crearRepositorios`, `crearFirmas`, `crearCasosDeUso`, `crearServidor`, ...) que reciben sus dependencias como parámetros. `backend/src/main.js` las ensambla en este orden: configuración → base de datos → repositorios → bóveda → firmas → detector → bitácora → métricas → casos de uso → servidor HTTPS.
- **Sin capa de puertos formal:** no hay interfaces `ports/in` / `ports/out`; el desacople se logra pasando objetos (repositorios, bóveda, detector, reloj) a las fábricas. Las carpetas vacías `backend/src/application/ports/{in,out}` no se usan.
- **Beneficio:** el núcleo (`core/totp`, `core/vault`, `core/tokens`, `core/qr`) es puro y se prueba sin base de datos; los casos de uso se prueban con SQLite en memoria y reloj inyectado.

### ADR-002: Stack 100 % propio y autoejecutable (decisión del 26-11-2026)
- **Regla:** cero dependencias npm en ejecución y en pruebas. Solo módulos nativos de Node.js 22 (>= 22.5 por `node:sqlite`).
- **Lenguaje:** JavaScript ESM (`"type": "module"`) con JSDoc para tipos. Sin TypeScript ni paso de compilación.
- **Backend:** `node:https` (servidor y enrutador propios), `node:crypto` (TOTP, AES-256-GCM, Ed25519, scrypt, HMAC), JWT EdDSA propio, `node:sqlite` (SQLite en modo WAL), `node:test` (pruebas).
- **Base de datos:** solo SQLite. `contracts/schema.sql` (PostgreSQL) es referencia para despliegues futuros y no se usa.
- **TLS:** HTTPS nativo de Node con TLS 1.3 mínimo (`TLS_MODE=node`). Certificados de desarrollo con `npm run certs` (openssl del sistema); en producción, certificados institucionales.
- **Frontends:** HTML + CSS + JavaScript propios, sin frameworks, empaquetadores ni CDN. El servidor sirve `authenticator-app/` en `/app/` y `admin-console/` en `/consola/`.
- **Código QR:** codificador propio (`core/qr`, Reed-Solomon incluido); alternativa: alta manual con la clave Base32.
- **Despliegue:** servicio `systemd` en servidor institucional sin contenedores (ver `deploy/README.md`).

### ADR-003: Controles criptográficos y de integridad
- **AES-256-GCM con AAD:** semillas con `AAD = enrollment_id + ":" + key_version`; claves privadas de firma con contexto `signing:<kid>`. Llave maestra fuera de la base (`MASTER_KEY_<VERSION>_HEX`), versionada; `vault.reencrypt` permite recifrar en lote.
- **Anti replay atómico:** `UPDATE enrollments SET last_step = ?, drift_steps = ? ... WHERE id = ? AND last_step < ?`. El `jti` del JWT se consume una sola vez (`consumed_jti`).
- **Anonimización:** `user_ref_hash = HMAC-SHA256(user_ref, USER_REF_PEPPER)` e `ip_hash = HMAC-SHA256(ip, pepper diario derivado de DAILY_IP_PEPPER_SEED)`. Ni nombres, ni correos, ni IP en claro en la base.
- **Bitácora encadenada (`audit_log`):** `hash = SHA-256(prev_hash + "|" + JSON canónico de {ts, actor, accion, objetivo, detalle})`, con génesis de 64 ceros y filtrado de campos sensibles; verificable en `GET /admin/api/audit/verify-chain`.
- **Secretos:** `client_secret`, contraseñas de administradores y códigos de recuperación con scrypt (N=16384, r=8, p=1). Comparaciones en tiempo constante.

---

## 2. Módulos del backend (`backend/src/`)

| Módulo | Responsabilidad | Pruebas |
| :--- | :--- | :--- |
| `core/totp/` | RFC 4226/6238 propio (`generateHotp`, `generateTotp`, `verifyTotpWithDrift`, `resyncTwoConsecutiveCodes`, `buildOtpauthUri`), Base32 | 10 |
| `core/vault/` | Semillas CSPRNG, AES-256-GCM con AAD, llavero versionado, `hashPepper`, `pepperDiario` | 12 |
| `core/tokens/` | Pares Ed25519, `kid` por huella, JWT EdDSA (`signMfaJwt`, `verifyMfaJwt`), JWKS | 16 |
| `core/qr/` | Codificador QR propio (versiones 1-40, niveles L/M/Q/H) y salida SVG | 11 |
| `security/` | Validación de esquemas cerrados, errores genéricos, limitador de tasa, bloqueo progresivo (30 s, 2 min, 10 min, 1 h), scrypt, códigos de recuperación, cabeceras de seguridad | 17 |
| `audit/` | Bitácora encadenada y métricas en memoria (JSON y texto estilo Prometheus) | 17 |
| `heuristics/` | Detector local de anomalías: Isolation Forest propio + reglas explicables (cuentas por IP, IPs por cuenta, ritmo, proporción de fallos, hora inusual) | 9 |
| `application/use-cases/` | Casos de uso MFA y de consola, RBAC, bloqueos, idempotencia, esquemas de entrada | 22 |
| `infrastructure/persistence/` | Apertura de SQLite (WAL, claves foráneas), migraciones y repositorios de las 8 tablas | 10 |
| `infrastructure/config/` | Parser propio de `.env`, validación de configuración y gestión de claves de firma (`firmas.js`) | 11 |
| `api/` | Servidor HTTPS, enrutador, CORS, sesiones admin con CSRF, estáticos, salud y métricas | 21 |
| `main.js` | Arranque, tareas periódicas (salud cada 30 s, purga cada hora, desfase de reloj cada 10 min) y apagado ordenado | — |

Total: **156 pruebas** en verde (`cd backend && npm test`).

Scripts (`backend/scripts/`): `npm run env` (crea `backend/.env` desde `.env.example` con secretos aleatorios), `npm run certs` (CA y certificado locales), `npm run seed` (apps "Portal de Trámites" y "Reto 1" y administrador inicial con TOTP).

## 3. Otros componentes del repositorio

| Carpeta | Qué es |
| :--- | :--- |
| `authenticator-app/` | Autenticador PWA en HTML/CSS/JS propios (manifest, service worker, almacenamiento cifrado en el dispositivo), servido en `/app/`. |
| `admin-console/` | Consola administrativa en HTML/CSS/JS propios (login con TOTP, apps, enrolamientos, auditoría, anomalías, métricas), servida en `/consola/`. |
| `sdk/` | SDK JavaScript sin dependencias para integradores: cliente de la API v1, verificación local del JWT con caché de JWKS y servicio falso para pruebas. |
| `demo-portal-tramites/` | Portal institucional de ejemplo (servidor Node propio, puerto 8444) que usa el SDK de servidor a servidor. |
| `attack-lab/` | Escenarios de ataque simulado (replay, fuerza bruta, fuerza bruta distribuida, spraying, inundación, JWT, entradas inválidas) y pruebas de caos. |
| `deploy/` | Unidad `systemd` de ejemplo y guía de despliegue en servidor institucional. |
| `contracts/` | OpenAPI, esquema SQLite (y referencia PostgreSQL) y mocks reales. |

## 4. Flujo de integración (Portal de Trámites y Reto 1)

```text
[App integradora: Portal de Trámites / Reto 1]   (X-Client-Id + X-Client-Secret sobre TLS 1.3)
    |
    +--> 1. POST /api/v1/enrollments              -> enrollment_id + otpauth:// + QR SVG (pendiente 10 min)
    +--> 2. POST /api/v1/enrollments/{id}/activate -> activo + 10 códigos de recuperación (una sola vez)
    +--> 3. POST /api/v1/verify                   -> { user_ref, code }: bloqueo progresivo -> detector local
    |                                                -> RFC 6238 + deriva + anti replay -> JWT Ed25519 (300 s, jti único, amr ["otp"])
    +--> 4. POST /api/v1/tokens/validate          -> valida y consume el jti (o validación local con /.well-known/jwks.json)
    +--> (opcional) /resync, /recovery, DELETE /api/v1/enrollments/{id}
```

Consola: `POST /admin/api/login` (contraseña + TOTP) emite la cookie `sst_admin` (`HttpOnly; Secure; SameSite=Strict; Path=/admin`, 30 min deslizantes, tope 8 h) y un `csrf_token` que se envía en `X-CSRF-Token` en cada petición que modifica. RBAC: `Administrador` (todo), `Operador` (apps, enrolamientos, anomalías, métricas), `Auditor` (auditoría, verificación de cadena, anomalías, métricas).

## 5. Áreas de trabajo

| Área | Responsable | Rama | Carpetas |
| :--- | :--- | :--- | :--- |
| **A — Núcleo y API** | Diego | `diego` | `backend/` |
| **B — Clientes, contratos e integración** | Laya | `laya` | `contracts/`, `sdk/`, `authenticator-app/`, `admin-console/`, `demo-portal-tramites/`, `attack-lab/`, `deploy/`, documentos raíz |

**Punto de unión:** `contracts/openapi.yaml` y `contracts/mocks/`. Integración por Pull Request hacia `staging`; nunca commit directo a `main`.

| Track / Rol | Carpetas propias | Rama sugerida |
| :--- | :--- | :--- |
| **Lead / Arquitectura / Contratos / SDK** (J Laya) | Raíz (`AGENTS.md`, `ARCHITECTURE.md`, `SYSTEM_GRAPH.md`, `TASKS.md`, `CONTRIBUTING.md`), `contracts/`, `sdk/` | `feat/lead-*` |
| **Backend y criptografía** | `backend/src/core/`, `backend/src/application/`, `backend/src/api/`, `backend/src/infrastructure/`, `backend/migrations/` | `feat/backend-*` |
| **Frontend y UX** | `authenticator-app/`, `admin-console/`, `demo-portal-tramites/` | `feat/frontend-*` |
| **Seguridad, infraestructura, detector local y attack-lab** | `backend/src/security/`, `backend/src/heuristics/`, `backend/src/audit/`, `attack-lab/`, `deploy/`, `docs/sbom/` | `feat/security-*` / `feat/ai-*` |
| **Solo lectura** | `docs/reto/`, `docs/analisis/` | — |

## 6. Comandos de arranque (Node 22, sin instalar nada)

```bash
cd backend
npm run env      # crea backend/.env con secretos aleatorios (no sobrescribe)
npm run certs    # CA local + certificado para localhost en backend/certs/
npm run seed     # apps de demo y administrador inicial (los secretos se muestran una vez)
npm test         # 156 pruebas
npm start        # https://localhost:8443

# Comprobaciones
curl --cacert certs/ca.crt https://localhost:8443/health
curl --cacert certs/ca.crt https://localhost:8443/health/ready
curl --cacert certs/ca.crt https://localhost:8443/.well-known/jwks.json
```
