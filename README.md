# Servicio Soberano de Autenticación Multifactorial basado en Tiempo (TOTP)

> **Hackatón Venezuela INNOVA 2026** · **Reto Grupal 3** (con puente SDK hacia el Reto 1) · **Equipo PSM-Hackaton**

---

## 1. Nombre del proyecto

**Servicio Soberano de Autenticación Multifactorial basado en Tiempo (TOTP)**
*(Repositorio: `servicio-soberano-autenticacion-totp`)*

Licencia: **GNU AGPL-3.0 o posterior** ([`LICENSE`](LICENSE)). Código abierto y auditable: cualquier
institución puede revisarlo, desplegarlo y mejorarlo, y las versiones modificadas que se ofrezcan como
servicio deben seguir siendo abiertas.

---

## 2. Participantes

- Juan Laya — Líder técnico: arquitectura, contratos e integración
- Diego Landaeta — Backend, criptografía y seguridad
- Javier Rodríguez — Frontend y experiencia de usuario
- Giovani Marcano — Seguridad, pruebas y laboratorio de ataques
- Enggel Rodríguez — Inteligencia artificial local, documentación y presentación

El equipo del **Reto 1** consume el servicio como aplicación cliente (`Reto 1`) mediante el SDK
([`sdk/INTEGRACION_RETO1.md`](sdk/INTEGRACION_RETO1.md)).

---

## 3. Descripción del proyecto

**Problema.** Las instituciones públicas suelen depender de autenticadores comerciales y servicios MFA en
nubes extranjeras, cediendo la custodia de las semillas, limitándose en la práctica a SHA-1 y dependiendo
de tiendas de aplicaciones y de la conectividad a Internet.

**Propósito.** Un segundo factor de autenticación (TOTP, RFC 6238) **100 % soberano, auditable y
autoejecutable, con cero dependencias npm**: las semillas se generan con el CSPRNG del sistema y se guardan
cifradas con AES-256-GCM en el servidor de la institución; el motor criptográfico, el servidor HTTPS, el
codificador QR, la app autenticadora, la consola y el SDK son código propio; no hay CDN, telemetría ni
llamadas a servicios de terceros.

**Funcionamiento general.**

```text
 Ciudadano                     Sistema institucional                 Servicio Soberano TOTP (este repositorio)
 ─────────                     (Portal de Trámites / Reto 1)          ─────────────────────────────────────────
 usuario + contraseña  ──────► 1.er factor propio
                               POST /api/v1/enrollments  ──────────► semilla CSPRNG → AES-256-GCM → SQLite
 QR / enlace / clave   ◄────── QR + otpauth:// (SHA-256/512)          (user_ref solo como HMAC-SHA256)
 App autenticadora (PWA)
 código de 6–8 dígitos ──────► POST /api/v1/verify       ──────────► bloqueo progresivo → detector local
                                                                       → RFC 6238 + deriva + anti replay
                               ◄──────────────────────────────────── JWT EdDSA (Ed25519, 300 s, jti único)
                               firma comprobada con la JWKS (sin red) +
                               POST /api/v1/tokens/validate (consume el jti) → sesión
 Administrador ──────────────────────────────────────────────────►  /consola/: políticas, enrolamientos,
                                                                       llaves, anomalías y auditoría encadenada
```

- **Motor criptográfico y backend propio ([`backend/`](backend/)):** solo módulos nativos de Node.js 22 (`node:https`, `node:crypto`, `node:sqlite`, `node:test`). RFC 6238 / RFC 4226 con **HMAC-SHA256 y HMAC-SHA512** (6 u 8 dígitos; SHA-1 solo si la política de la app lo permite), semillas CSPRNG cifradas con **AES-256-GCM + AAD**, **JWT Ed25519 (EdDSA)** con `/.well-known/jwks.json` y rotación de `kid`, **QR SVG propio (ISO/IEC 18004 + Reed-Solomon)**, anti replay atómico, `jti` de un solo uso, bitácora encadenada por SHA-256 (`audit_log`), métricas locales estilo Prometheus y **detector local de anomalías (Isolation Forest propio + reglas explicables)** sin telemetría externa.
- **App autenticadora PWA propia ([`authenticator-app/`](authenticator-app/)):** servida por la institución en `/app/`, funciona **sin conexión** (Service Worker + Web Crypto), cifra las semillas en el dispositivo con un **PIN (PBKDF2 + AES-GCM)**, SHA-1/256/512 con 6 u 8 dígitos; alta por enlace del portal, URI `otpauth://` pegada, clave manual Base32 o cámara; respaldo cifrado y comprobación de la hora.
- **Consola administrativa con RBAC ([`admin-console/`](admin-console/)):** servida en `/consola/`, inicio de sesión con contraseña + **TOTP propio**, cookie `HttpOnly; Secure; SameSite=Strict` + CSRF, roles `Administrador`, `Operador` y `Auditor`. Políticas por app, enrolamientos por estado, alertas del detector, rotación de llaves Ed25519 con un botón y verificación de la cadena `audit_log`.
- **SDK y Portal de demostración ([`sdk/`](sdk/), [`demo-portal-tramites/`](demo-portal-tramites/)):** SDK ESM sin dependencias con tiempo de espera de 3 s, un reintento idempotente (`Idempotency-Key`), política estricta de **falla cerrado** y **validación local del JWT con caché JWKS**; Portal de Trámites del Estado (ficticio) con enrolamiento, códigos de recuperación y *step-up* en trámites sensibles.
- **Laboratorio de ataques, DAST y caos ([`attack-lab/`](attack-lab/)):** 12 escenarios (replay con carrera paralela, JWT alterados, entradas malformadas, **escáner DAST propio**, deriva de reloj, origen compartido, fuerza bruta local y distribuida, spraying, inundación, proxy TCP de caos con latencia y cortes, reinicio del backend) con informes autocontenidos.

### Estructura del repositorio

```text
backend/                API HTTPS, motor TOTP, bóveda, JWT, QR, seguridad, detector, auditoría (+ scripts/ y migrations/)
authenticator-app/      App autenticadora PWA (servida en /app/)
admin-console/          Consola administrativa (servida en /consola/)
sdk/                    SDK para integradores + servicio falso de pruebas + guía Reto 1
demo-portal-tramites/   Portal de Trámites de demostración (puerto 8444)
attack-lab/             Ataques simulados y pruebas de caos
contracts/              OpenAPI 3.1, esquema SQLite y respuestas reales de ejemplo
deploy/                 Unidad systemd y guía de despliegue institucional
docs/                   Reto, análisis, API, SBOM, cumplimiento, manual, presentación, escalabilidad, evidencias
```

### Documentación

| Documento | Contenido |
| :--- | :--- |
| [`docs/analisis/analisis-tecnico.pdf`](docs/analisis/analisis-tecnico.pdf) | Análisis técnico: soberanía, TOTP, arquitectura, modelo de amenazas, API, datos, IA y UX. |
| [`docs/cumplimiento/matriz-cumplimiento.pdf`](docs/cumplimiento/matriz-cumplimiento.pdf) | Cada requisito de los Términos de Referencia y del enunciado, y cada criterio de evaluación con su peso, con el código y la prueba que lo demuestran. |
| [`docs/api/README.md`](docs/api/README.md) · [PDF](docs/api/guia-integracion.pdf) | Guía de integración HTTP para sistemas institucionales, con ejemplos reales de petición y respuesta. |
| [`sdk/INTEGRACION_RETO1.md`](sdk/INTEGRACION_RETO1.md) · [`sdk/README.md`](sdk/README.md) | Integración con el SDK (equipo del Reto 1) y referencia del SDK. |
| [`docs/manual/manual-usuario.pdf`](docs/manual/manual-usuario.pdf) | Manual del ciudadano (app y portal) y del administrador (consola). |
| [`docs/presentacion/guion-demo.pdf`](docs/presentacion/guion-demo.pdf) | Guion de la demostración ante el jurado (5–7 min) con plan B. |
| [`docs/escalabilidad/`](docs/escalabilidad/) | Escalabilidad y viabilidad del despliegue institucional. |
| [`docs/sbom/`](docs/sbom/) | SBOM CycloneDX 1.5, hashes SHA-256 de todos los archivos propios y su generador. |
| [`docs/evidencias/attack-lab-informe-2026-11-26.pdf`](docs/evidencias/attack-lab-informe-2026-11-26.pdf) | Informe del laboratorio de ataques de la verificación de la entrega (también en HTML y JSON). |
| [`docs/reto/`](docs/reto/) | Enunciado y Términos de Referencia oficiales. |
| [`contracts/openapi.yaml`](contracts/openapi.yaml) · [`deploy/README.md`](deploy/README.md) | Contrato de la API y guía de despliegue en producción. |
| [`ARCHITECTURE.md`](ARCHITECTURE.md) · [`SECURITY.md`](SECURITY.md) · [`CONTRIBUTING.md`](CONTRIBUTING.md) · [`TASKS.md`](TASKS.md) | Arquitectura, política de seguridad, flujo de ramas y estado del trabajo. |

---

## 4. Alcance

### Funcionalidades cubiertas en esta versión

- **Motor criptográfico propio** (RFC 4226/6238): HMAC-SHA256 y HMAC-SHA512, 6 u 8 dígitos, periodo de 15 a 60 s, ventana configurable (0–3 pasos), compensación de deriva, resincronización con dos códigos consecutivos (±10 pasos) y anti replay atómico. Probado con los vectores oficiales del RFC 6238 (Apéndice B) y del RFC 4226 (Apéndice D).
- **Semillas CSPRNG** (32 bytes para SHA-256, 64 para SHA-512) cifradas con **AES-256-GCM** y datos asociados `enrollment_id:versión`; llave maestra versionada fuera de la base y rotación con recifrado en lote (`npm run rotar-llave-maestra`).
- **API v1 de integración** ([`contracts/openapi.yaml`](contracts/openapi.yaml), 22 operaciones): enrolamiento con QR SVG y URI `otpauth://`, activación con 10 códigos de recuperación, verificación, validación de token con consumo del `jti`, resincronización, recuperación y revocación; idempotencia con `Idempotency-Key`.
- **Tokens firmados**: JWT EdDSA (Ed25519) con `sub` seudónimo, `aud` = app, `amr: ["otp"]`, `jti` de un solo uso y 300 s de vida; JWKS pública y rotación sin invalidar tokens emitidos.
- **Seguridad**: TLS 1.3 mínimo, esquemas de entrada cerrados, errores genéricos sin enumeración de usuarios, límites de tasa global, por app y por origen, bloqueo progresivo por cuenta (30 s, 2 min, 10 min, 1 h), límites de tamaño y tiempo de cuerpo, cabeceras OWASP, CORS por lista blanca y sesión de consola con CSRF y caducidad (30 min deslizantes, 8 h máximo).
- **Detector local de anomalías** (sin telemetría): Isolation Forest implementado desde cero + reglas explicables; modos `local`, `monitorizacion` y `mock`; respuesta adaptativa (`ANOMALY_BLOCKED`) según la política de cada app.
- **Anonimización**: `user_ref` solo como HMAC-SHA256 con *pepper*; IP solo como HMAC con *pepper* diario; la bitácora filtra campos sensibles.
- **Auditoría y métricas** locales: bitácora encadenada verificable desde la consola; métricas JSON y formato de texto estilo Prometheus.
- **Clientes propios** (HTML + CSS + JS, sin frameworks, empaquetadores ni CDN): app autenticadora, consola y Portal de Trámites; **SDK** y **laboratorio de ataques y caos**.
- **Pruebas automatizadas y cobertura (CI sin dependencias):** **287 pruebas** con `node:test` (backend 193 con **98,2 %** de cobertura de líneas, app 26 con **83,3 %**, SDK 26 con **96,2 %**, portal 14 con **93,1 %**, laboratorio + DAST 28 con **87,4 %**), todas en verde el 26-11-2026 ([`docs/evidencias/cobertura-2026-11-26.txt`](docs/evidencias/cobertura-2026-11-26.txt)); automatizadas en `.gitlab-ci.yml` y `.github/workflows/pruebas.yml` mediante `node scripts/verificar-todo.js` (0 `npm install`).
- **Compatibilidad abierta y app móvil:** formato Key URI (`otpauth://`) verificado por pruebas automatizadas para clientes libres ([`docs/evidencias/compatibilidad-clientes-totp.md`](docs/evidencias/compatibilidad-clientes-totp.md)); decisión arquitectónica ADR-004 y base Kotlin nativa en [`mobile-android/`](mobile-android/); páginas ciudadanas de inicio, certificado y estado en [`sitio-publico/`](sitio-publico/).

### Límites de la entrega

- **Contenedores Docker y PostgreSQL** quedan fuera (ADR-002): ejecución nativa con `systemd` + SQLite WAL en un nodo. `contracts/schema.sql` (PostgreSQL) es referencia para crecer; ver [`docs/escalabilidad/`](docs/escalabilidad/).
- **Consola**: no registra apps nuevas ni crea cuentas `Operador`/`Auditor` desde la interfaz (las apps se registran con `npm run seed` o `POST /admin/api/apps`; la semilla crea solo el Administrador). La **revocación** de un enrolamiento la ejecuta la app integradora (`DELETE /api/v1/enrollments/{id}`); la consola la muestra y la audita.
- **Cámara en la app**: usa `BarcodeDetector` del navegador (no todos lo implementan). El servidor envía `Permissions-Policy: camera=(self)` solo en `/app/`; la API y la consola siguen con `camera=()`. Sin `BarcodeDetector`, el alta funciona por enlace del portal, URI pegada o clave manual.
- **Certificados**: `npm run certs` emite certificados de desarrollo solo para `localhost`, `127.0.0.1` y `::1`. Para un teléfono en la red local, ver el Paso 6; en producción, CA institucional ([`deploy/README.md`](deploy/README.md)).
- **HSM/TPM**: la llave maestra vive en el `.env` (permisos 600); `core/vault` la aísla y versiona para conectarla a un HSM o TPM institucional en el futuro.
- **Canales SMS o correo de terceros**: excluidos por soberanía.
- TOTP no protege contra el *phishing* en tiempo real (límite del estándar); se mitiga con JWT ligado a la app (`aud`), vida corta y alertas del detector.

---

## 5. Requerimientos del sistema

| Requisito | Detalle |
| :--- | :--- |
| Sistema operativo | Linux (probado; unidad `systemd` en `deploy/`). Otros sistemas con Node.js 22.5+ no se han probado. |
| Lenguaje | JavaScript ESM con JSDoc; HTML y CSS propios. Sin TypeScript ni compilación. |
| Runtime | **Node.js ≥ 22.5** (por `node:sqlite`); probado con **v22.22.1**. |
| Dependencias npm | **0 (cero)** en ejecución, construcción y pruebas; no hace falta `npm install` ([`docs/sbom/`](docs/sbom/)). |
| Base de datos | **SQLite** integrada en Node.js (`node:sqlite`, modo WAL; esquema en [`contracts/schema.sqlite.sql`](contracts/schema.sqlite.sql)). No requiere servidor de base de datos. |
| Herramientas del sistema | `openssl` (solo para `npm run certs`); `chrony` contra el NTP institucional en producción (TOTP depende de la hora). |
| Navegador | Navegador moderno con Web Crypto, IndexedDB y Service Worker para la app, la consola y el portal. |
| Red | Sin Internet en ejecución. Puertos: 8443 (API, `/app/`, `/consola/`) y 8444 (portal de demostración). |

### Variables de entorno del servicio (`backend/.env`)

`npm run env` crea `backend/.env` desde [`.env.example`](.env.example) con secretos aleatorios del CSPRNG
(permisos 600, nunca sobrescribe). Las variables del proceso tienen prioridad; un valor con `CHANGE_ME`
impide arrancar. Las rutas relativas se resuelven respecto a `backend/`.

| Variable | Por defecto | Descripción |
| :--- | :--- | :--- |
| `ENV_FILE` | `backend/.env` | Archivo de configuración alternativo (p. ej. `/etc/servicio-totp/servicio-totp.env`). |
| `NODE_ENV` | `development` | `production` prohíbe `TLS_MODE=off` y orígenes CORS `http://`. |
| `HOST` / `PORT` | `0.0.0.0` / `8443` | Dirección y puerto de escucha. |
| `TLS_MODE` | `node` | `node` = HTTPS nativo con TLS 1.3 mínimo; `off` = HTTP solo para pruebas locales. |
| `TLS_CERT_PATH` / `TLS_KEY_PATH` | `./certs/localhost.crt` / `.key` | Certificado y llave del servidor. |
| `DB_DRIVER` | `sqlite` | Único controlador disponible. |
| `SQLITE_DB_PATH` | `./data/totp_soberano.db` | Archivo de la base de datos. |
| `MASTER_KEY_VERSION` | `v1` | Versión activa de la llave maestra. |
| `MASTER_KEY_<VERSIÓN>_HEX` | obligatoria | Llave AES-256 de cada versión (64 hex), p. ej. `MASTER_KEY_V1_HEX`. |
| `USER_REF_PEPPER` | obligatoria (≥ 32 caracteres) | *Pepper* del seudónimo `user_ref_hash`. No se rota en caliente. |
| `DAILY_IP_PEPPER_SEED` | obligatoria (≥ 32 caracteres) | Semilla del *pepper* diario de `ip_hash`. |
| `TOTP_ISSUER` | `ServicioSoberanoTOTP` | Emisor mostrado en la app (URI `otpauth://`). |
| `JWT_ISSUER` | `https://totp.soberano.local` | Emisor (`iss`) del JWT. |
| `JWT_TTL_SECONDS` | `300` | Vida del JWT (30 a 3600 s). |
| `ADMIN_SEED_USER` | `admin_seguridad` | Usuario del administrador inicial (`npm run seed`). |
| `ADMIN_QR_PATH` | `data/admin-qr.svg` (junto a la base) | Dónde deja la semilla el QR del administrador. |
| `HEURISTICS_MODE` | `local` | `local` (Isolation Forest + reglas), `monitorizacion` (solo alerta) o `mock` (desarrollo). |
| `CORS_ALLOWED_ORIGINS` | vacío | Orígenes permitidos separados por comas; vacío = solo mismo origen. |
| `CLOCK_REFERENCE_URL` | vacío | URL http(s) **institucional** de referencia horaria; mide el desfase cada 10 min. |
| `RATE_LIMIT_GLOBAL_POR_MIN` | `6000` | Límite anti-DDoS por IP TCP, previo a la autenticación. |
| `RATE_LIMIT_APP_POR_MIN` | `3000` | Límite por aplicación integradora. |
| `RATE_LIMIT_ORIGEN_POR_MIN` | `60` | Límite por (aplicación, origen del usuario final). |
| `BLOQUEO_INEXISTENTES_VENTANA_MIN` | `1440` | Ventana (min) para contar fallos de usuarios sin enrolamiento activo. |

### Variables del Portal de Trámites (`demo-portal-tramites/.env`)

| Variable | Por defecto | Descripción |
| :--- | :--- | :--- |
| `PORTAL_HOST` / `PORTAL_PUERTO` | `127.0.0.1` / `8444` | Dirección y puerto del portal. |
| `PORTAL_TLS_CERT` / `PORTAL_TLS_KEY` | `../backend/certs/localhost.crt` / `.key` | Si existen, HTTPS; si no, HTTP solo en localhost. |
| `TOTP_BASE_URL` | `https://localhost:8443` | URL del servicio TOTP. |
| `TOTP_CLIENT_ID` / `TOTP_CLIENT_SECRET` | — | Credenciales de la app "Portal de Trámites" que imprime `npm run seed`. |
| `TOTP_CA_PATH` | `../backend/certs/ca.crt` | CA del servicio; vacío = CAs del sistema. |
| `TOTP_ISSUER` / `TOTP_AUDIENCE` | `https://totp.soberano.local` / `client_id` | `iss` y `aud` esperados en el JWT. |
| `TOTP_TIMEOUT_MS` | `3000` | Tiempo de espera total por intento. |
| `AUTENTICADOR_URL` | `https://localhost:8443/app/` | Destino del botón «Abrir en el Autenticador Soberano». |
| `PORTAL_ETIQUETA_CUENTA` | `Portal de Trámites` | Etiqueta de la cuenta en la app. |
| `PORTAL_TRAZAS` | `1` | Muestra el panel «Lo que ocurre por dentro». |
| `PORTAL_SESION_MINUTOS` | `15` | Inactividad máxima de la sesión. |
| `PORTAL_STEPUP_MINUTOS` | `0` | Reservada: se lee pero no tiene efecto; el *step-up* se pide siempre. |
| `PORTAL_USUARIOS` | `datos/usuarios.json` | Archivo de ciudadanos ficticios. |
| `PORTAL_CONFIAR_X_FORWARDED_FOR` | `0` | `1` solo si hay un proxy inverso propio delante del portal: la IP del ciudadano (que se envía al servicio como `client_ip`) se toma de `X-Forwarded-For`. |

El laboratorio acepta `ATTACK_URL`, `ATTACK_CLIENT_ID`, `ATTACK_CLIENT_SECRET`, `ATTACK_CLIENT_ID_2`,
`ATTACK_CLIENT_SECRET_2`, `ATTACK_CREDENCIALES`, `ATTACK_CA`, `ATTACK_TIMEOUT_MS`, `ATTACK_PERMITIR_HOST` y
`ATTACK_INSEGURO` ([`attack-lab/README.md`](attack-lab/README.md)).

---

## 6. Instalación y despliegue

Pasos ejecutados y comprobados el 26-11-2026 en una copia limpia del repositorio (Linux, Node.js 22.22.1).
No necesitan Internet después de clonar. Node.js 22 imprime `ExperimentalWarning: SQLite is an
experimental feature`: es un aviso informativo de `node:sqlite`, no un error.

### Despliegue como servicio (un solo comando)

Para dejar el sistema instalado y funcionando como servicio `systemd`, accesible desde la red local
(servicio, PWA y consola en `https://<IP>:8443`, portal en `https://<IP>:8444`), tras clonar (Paso 1):

```bash
sh deploy/instalar.sh          # como root: modo sistema (/opt, /etc, /var/lib); sin root: modo usuario (systemctl --user)
```

Genera secretos, CA propia y certificado con las IP del equipo, ejecuta la semilla (credenciales en un
archivo 0600), arranca servicio y portal, programa el respaldo diario cifrado e imprime las URL. Opción
`--datos-demo` para poblar la consola. Operación, respaldos, actualización y desinstalación:
[`deploy/README.md`](deploy/README.md). Los pasos siguientes describen la ejecución manual para desarrollo.

### Paso 1 — Clonar el repositorio

```bash
git clone <URL_DEL_PROYECTO> servicio-soberano-autenticacion-totp   # GitLab del hackatón o servidor Git institucional
cd servicio-soberano-autenticacion-totp
node --version                                                      # v22.5.0 o superior
```

### Paso 2 — Instalar dependencias

No hay nada que instalar: **cero dependencias npm** (no ejecute `npm install`).

### Paso 3 — Configurar variables de entorno, certificados y datos iniciales

```bash
cd backend
npm run env      # crea backend/.env con llave maestra AES-256 y peppers del CSPRNG (permisos 600)
npm run certs    # crea la CA local y el certificado TLS de localhost en backend/certs/
npm run seed     # apps "Portal de Trámites" y "Reto 1" + administrador inicial
```

`npm run seed` imprime **una sola vez** (cópielo en ese momento):

- `client_id` (`app_…`) y `client_secret` de **"Portal de Trámites"** y **"Reto 1"**;
- usuario `admin_seguridad`, contraseña aleatoria, rol `Administrador`, URI TOTP del administrador, ruta del QR (`backend/data/admin-qr.svg`) y 10 códigos de recuperación;
- la nota «el código del paso actual ya se consumió al activar; espere al siguiente para iniciar sesión».

### Paso 4 — Ejecutar el servicio

```bash
npm start        # en backend/ → «Servicio escuchando en https://0.0.0.0:8443 (22 rutas API)»
```

Comprobación desde otra terminal, en `backend/`:

```bash
curl --cacert certs/ca.crt https://localhost:8443/health          # {"status":"ok",...,"heuristicsMode":"local"}
curl --cacert certs/ca.crt https://localhost:8443/health/ready    # {"status":"ok",...,"database":"ok"}
curl --cacert certs/ca.crt https://localhost:8443/.well-known/jwks.json
```

- App autenticadora: **https://localhost:8443/app/** (la raíz `/` redirige a `/app/`).
- Consola administrativa: **https://localhost:8443/consola/**.

### Paso 5 — Confiar en la CA local y entrar en la consola

Importe `backend/certs/ca.crt` como autoridad de certificación (solo desarrollo y demo):

- **Firefox**: Ajustes → Privacidad y seguridad → Certificados → Ver certificados → Autoridades → Importar → «Confiar en esta CA para identificar sitios web».
- **Chromium / Chrome**: Configuración → Privacidad y seguridad → Seguridad → Gestionar certificados → Autoridades → Importar.
- **Todo el sistema (Linux)**: `sudo cp backend/certs/ca.crt /usr/local/share/ca-certificates/totp-local.crt && sudo update-ca-certificates`.

En la app: crear el PIN → **Agregar cuenta** → pestaña **Pegar** → pegar la URI TOTP del administrador →
**Revisar cuenta** → **Guardar cuenta**. Con un código nuevo, entre en `/consola/` con usuario, contraseña y
código. Borre después `backend/data/admin-qr.svg`.

### Paso 6 — Teléfono en la red local (opcional)

El certificado de `npm run certs` solo vale para `localhost`. Para abrir la app desde un teléfono, emita con
la CA local un certificado con la IP del servidor (ejemplo `192.168.1.50`) y arranque con él (comprobado):

```bash
cd backend
IP=192.168.1.50
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out certs/servidor-lan.key
openssl req -new -key certs/servidor-lan.key -subj "/O=Servicio Soberano TOTP/CN=$IP" -out certs/servidor-lan.csr
printf "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1,IP:$IP\n" > certs/servidor-lan.ext
openssl x509 -req -in certs/servidor-lan.csr -CA certs/ca.crt -CAkey certs/ca.key -CAcreateserial \
  -days 825 -sha256 -extfile certs/servidor-lan.ext -out certs/servidor-lan.crt
TLS_CERT_PATH=./certs/servidor-lan.crt TLS_KEY_PATH=./certs/servidor-lan.key npm start
```

Instale `ca.crt` en el teléfono — **Android**: Ajustes → Seguridad → Cifrado y credenciales → Instalar un
certificado → Certificado de CA; **iOS**: abrir el archivo, instalar el perfil y activarlo en Ajustes →
General → Información → Ajustes de confianza de certificados. Abra `https://<IP>:8443/app/` y use
«Añadir a pantalla de inicio».

### Paso 7 — Portal de Trámites (sistema integrador de ejemplo)

```bash
cd demo-portal-tramites
cp .env.example .env   # TOTP_CLIENT_ID y TOTP_CLIENT_SECRET de "Portal de Trámites" (Paso 3)
npm run usuarios       # ana.rivera, bruno.mendez, carla.ortiz (clave Tramites-Demo-2026), sin segundo factor
npm start              # «Portal de Trámites del Estado en https://localhost:8444 (HTTPS)»
```

En **https://localhost:8444**: usuario y contraseña → vincular el autenticador (QR, clave manual o
«Abrir en el Autenticador Soberano») → primer código → códigos de recuperación → código nuevo → panel.
Comprobado de punta a punta contra el backend real.

### Paso 8 — Pruebas automatizadas

```bash
cd backend && npm test && cd ..                            # 171
node --test authenticator-app/tests/*.test.mjs             # 25
cd sdk && npm test && cd ..                                # 23
cd demo-portal-tramites && npm test && cd ..               # 12
cd attack-lab && npm test && cd ..                         # 25
```

Resultado el 26-11-2026: **256 pruebas, 0 fallos**.

### Paso 9 — Laboratorio de ataques y caos contra el servicio real

Desde la raíz, con el servicio en marcha:

```bash
export ATTACK_CLIENT_ID=app_...   ATTACK_CLIENT_SECRET=...     # "Portal de Trámites"
export ATTACK_CLIENT_ID_2=app_... ATTACK_CLIENT_SECRET_2=...   # "Reto 1" (prueba de otra audiencia)
node attack-lab/ejecutar-todo.js --rapido
#   → 8/8 escenarios OK · 85/85 verificaciones · 0 hallazgos; informe HTML y JSON en attack-lab/resultados/
node attack-lab/caos/reinicio.js --comando "node src/main.js" --cwd backend --pid <PID del backend>
#   → listo de nuevo en 0,33 s; el bloqueo de la cuenta sobrevive al reinicio
```

Informe de la ejecución de verificación: [`docs/evidencias/`](docs/evidencias/).

### Paso 10 — Inventario de software (SBOM)

```bash
node docs/sbom/generar-sbom.js --comprobar    # regenera docs/sbom/; falla si aparece una dependencia externa
sha256sum -c docs/sbom/hashes-sha256.txt      # integridad de los archivos propios
```

### Paso 11 — Despliegue en un servidor institucional

Para producción (usuario dedicado, `systemd`, certificados de la CA institucional, NTP institucional con
`chrony`, copias cifradas y rotación de llaves) siga [`deploy/README.md`](deploy/README.md). En resumen:
`node scripts/generar-env.js --salida /etc/servicio-totp/servicio-totp.env` (en `backend/`),
`NODE_ENV=production`, `ENV_FILE=… node scripts/semilla.js` y `systemctl enable --now servicio-totp`.
