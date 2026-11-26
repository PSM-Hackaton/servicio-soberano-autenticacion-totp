# Grafo de Arquitectura y Red del Sistema — Servicio Soberano TOTP

> Mapa vivo de módulos, interfaces, flujos y dependencias del proyecto.
> **Estado actual:** Integración completa ADR-002 (Node.js 22.5+ nativo, 0 dependencias npm, SQLite WAL, TLS 1.3, DAST propio y verificación institucional `systemd`).

## 1. Mapa de Conexiones (Red del Sistema)

```mermaid
flowchart TD
    %% Clientes y Laboratorio (HTML/CSS/JS y Node 22 nativo, 0 dependencias npm)
    PWA["authenticator-app/\n(Servida en /app/: SW offline, Web Crypto, PIN+IndexedDB, QR/URI/Manual)"]
    ADMIN["admin-console/\n(Servida en /consola/: RBAC + TOTP + Apps + Llaves + Auditoría + Anomalías)"]
    DEMO["demo-portal-tramites/\n(Servidor HTTPS/HTTP propio, cookies __Host-, Step-Up MFA)"]
    RETO3["Reto 3: Evaluador de Propuestas\n(Integración vía sdk/INTEGRACION_RETO3.md)"]
    ATK["attack-lab/\n(11 escenarios + DAST: Replay, JWT, Entradas, Deriva, Fuerza bruta, Distribuida, Spraying, Origen compartido, Inundación, Caos, Reinicio)"]
    SDK["sdk/\n(crearClienteTotp, verificarTokenLocal, crearCacheJwks, servicio-falso.js)"]

    %% Contratos y Despliegue
    CONTRACTS["contracts/\n(openapi.yaml, schema.sqlite.sql 8 tablas, mocks/)"]
    DEPLOY["deploy/\n(servicio-totp.service systemd + verificar-despliegue.js)"]

    %% Backend Soberano (Node.js 22.5+ nativo, 0 deps npm)
    API["backend/src/api/\n(servidor.js TLS 1.3 + router.js: /api/v1/*, /admin/api/*, /health/ready, /metrics, /, /instalar-certificado, /estado, /sitio/, /app/, /consola/)"]
    SEC["backend/src/security/\n(secretos scrypt, limitador, bloqueo progresivo, validacion estricta, cabeceras, errores, recuperacion)"]
    UC["backend/src/application/use-cases/\n(mfa.js, admin.js, consultas.js, bloqueos.js, rbac.js, esquemas.js)"]
    TOTP["backend/src/core/totp/\n(totp.js + base32.js: RFC 6238/4226)"]
    VAULT["backend/src/core/vault/\n(vault.js: AES-256-GCM con AAD + llave maestra versionada)"]
    TOKENS["backend/src/core/tokens/\n(tokens.js: JWT Ed25519 EdDSA + JWKS + rotación kid)"]
    QR["backend/src/core/qr/\n(qr.js + reedSolomon.js: ISO/IEC 18004 SVG propio)"]
    HEUR["backend/src/heuristics/\n(isolationForest.js + detector.js + caracteristicas.js: IA local explicable)"]
    AUDIT["backend/src/audit/\n(cadena.js SHA-256 + metricas.js Prometheus/JSON)"]
    CFG["backend/src/infrastructure/config/\n(config.js + firmas.js) + scripts/{generar-env,certificados,semilla,rotar-llave-maestra}.js"]
    DB[("SQLite WAL Nativo (node:sqlite)\nrepositorios.js + rotacionLlaveMaestra.js\n8 Tablas Oficiales (001_esquema.sql)")]

    %% Conexiones
    PWA -->|"Código 6/8d + QR/otpauth"| DEMO
    PWA -->|"Código 6/8d"| RETO3
    DEMO --> SDK
    RETO3 --> SDK
    SDK -->|"HTTPS TLS 1.3 + Idempotency-Key"| API
    ADMIN -->|"HTTPS + Cookie HttpOnly + CSRF + TOTP"| API
    ATK -->|"Ataques + DAST + Proxy Caos TCP"| API
    DEPLOY -.->|"Ejecuta y verifica"| API
    CONTRACTS -.->|"Contrato único"| API
    CONTRACTS -.->|"Contrato y mocks"| SDK

    API --> SEC
    API --> CFG
    API --> PWA
    API --> ADMIN
    SEC --> UC
    UC --> TOTP
    UC --> VAULT
    UC --> TOKENS
    UC --> QR
    UC --> HEUR
    UC --> AUDIT
    UC --> DB
    HEUR --> DB
    AUDIT --> DB
```

## 2. Catálogo de Interfaces y Módulos

| Módulo | Archivos / Funciones Clave | Entradas / Salidas | Conexiones |
| :--- | :--- | :--- | :--- |
| `contracts/` | `openapi.yaml`, `schema.sqlite.sql` (8 tablas + índices), `mocks/*` | Contrato API v1 + Admin + Resiliencia (`/health/ready`, `/metrics`, `Idempotency-Key`, `503`) | Todos los módulos |
| `backend/src/core/` | `totp/totp.js`, `vault/vault.js`, `tokens/tokens.js`, `qr/qr.js` | Criptografía pura RFC 6238, AES-256-GCM+AAD, JWT Ed25519/JWKS, QR SVG ISO 18004 | `application/use-cases`, `attack-lab` |
| `backend/src/infrastructure/` | `persistence/{db,repositorios,rotacionLlaveMaestra}.js`, `config/{config,firmas}.js` | SQLite WAL `node:sqlite`, anti-replay atómico, `consumed_jti`, gestión de llaves Ed25519 | `application/use-cases`, `api/servidor.js` |
| `backend/src/security/` | `secretos.js`, `limitador.js`, `bloqueo.js`, `validacion.js`, `cabeceras.js`, `errores.js`, `recuperacion.js` | Auth apps scrypt, rate limit, bloqueo progresivo, JSON estricto, errores genéricos | `api/servidor.js`, `use-cases/` |
| `backend/src/heuristics/` | `isolationForest.js`, `caracteristicas.js`, `detector.js` | Features conductuales locales -> score 0–100, nivel, acción adaptativa y razones explicables | `use-cases/mfa.js`, `/admin/api/anomalies` |
| `backend/src/audit/` | `cadena.js`, `metricas.js` | Bitácora encadenada `prev_hash -> hash` + métricas locales Prometheus (`/metrics`) y JSON (`/admin/api/metrics`) | `use-cases/`, `api/servidor.js` |
| `backend/src/api/` | `servidor.js`, `router.js`, `src/main.js` | Servidor HTTPS TLS 1.3 propio + rutas v1/admin + páginas públicas `/`, `/instalar-certificado`, `/estado` y estáticos `/sitio/`, `/app/`, `/consola/` | `sdk/`, `admin-console/`, `authenticator-app/`, `sitio-publico/`, `attack-lab/` |
| `authenticator-app/` | `index.html`, `sw.js`, `manifest.json`, `js/{app,totp,cripto,boveda,almacen,otpauth,escaner}.js` | PWA offline con PIN, IndexedDB cifrado, SHA-256/512 (6/8d) y alta por enlace/URI/Base32/cámara | Usuario final, `demo-portal-tramites/` |
| `admin-console/` | `index.html`, `js/{api,app,rbac,cadena,graficos,mock}.js`, `js/vistas/*.js` | Consola RBAC + TOTP contra `/admin/api/*` (con modo mock de respaldo) | `backend/src/api` |
| `sdk/` | `src/{index,cliente,http,jwks,jwt,local,errores}.js`, `testing/servicio-falso.js`, `INTEGRACION_RETO3.md` | `crearClienteTotp`, `verificarTokenLocal` offline, timeout 3 s + 1 reintento idempotente | `demo-portal-tramites/`, Reto 3 |
| `demo-portal-tramites/` | `server.js`, `src/{cedula,portal,sesiones,tramites,usuarios,vistas}.js`, `scripts/crear-usuarios.js` | Portal institucional demo con cédula (V/E), enrolamiento, verificación, step-up MFA, centro de ayuda `/ayuda` y panel de traza | `sdk/`, `authenticator-app/` |
| `attack-lab/` | `ejecutar-todo.js`, `escenarios/*.js` (incl. `dast.js`), `caos/{proxy-caos,escenario-caos,reinicio}.js` | Ataques reales, escáner DAST propio y proxy TCP de caos -> informes JSON/HTML autocontenidos | `backend/src/api`, `backend/src/core/` |
| `deploy/` & `docs/` | `deploy/servicio-totp.service`, `deploy/verificar-despliegue.js`, `docs/sbom/`, `docs/cumplimiento/`, `docs/evidencias/` | Unidad `systemd` verificada, inventario CycloneDX 1.5 (0 deps npm), matriz de cumplimiento y evidencias | Entrega / Producción |
| `sitio-publico/` | `index.html`, `instalar-certificado.html`, `estado.html`, `css/sitio.css`, `js/{sitio,certificado,estado}.js`, `img/*.svg` | Inicio ciudadano (`/`), guía de certificado (`/instalar-certificado`, `/ca.crt` con huella SHA-256) y página `/estado` (cada 30 s) montados en `backend/src/main.js` con CSP estricta | `backend/src/api` (`/health/ready`, `/ca.crt`, `/sitio/`, `/app/`, `/consola/`) |
| `mobile-android/` | `README.md`, `AndroidManifest.xml`, `core/{TotpEngine,CedulaValidator,OtpAuthParser}.kt`, `security/{KeystoreVault,PinManager}.kt`, `TotpEngineTest.kt` | ADR-004 Android nativo Kotlin sin librerías de terceros (RFC 6238/4226, cédula V/E, parser `otpauth://`, Keystore AES-256-GCM StrongBox/TEE, PIN PBKDF2 + bloqueo progresivo, `allowBackup="false"`) | Portal institucional y `backend/src/api` |
| `scripts/` & CI | `scripts/verificar-todo.js`, `scripts/capturas.js`, `.gitlab-ci.yml`, `.github/workflows/pruebas.yml` | CI sin dependencias (OpenAPI estricto, 5 suites con cobertura, SBOM, higiene) y capturas headless Chromium | Todo el repositorio |

## 3. Bitácora de Evolución Arquitectónica

| Fecha | Acción (Alta / Poda / Refactor) | Módulos Afectados |
| :--- | :--- | :--- |
| 2026-11-26 | Alta inicial de estructura modular y contratos | `contracts/`, estructura base y documentos raíz |
| 2026-11-26 | Adopción de ADR-002 (Node.js 22 nativo, 0 dependencias npm, SQLite WAL) | Poda de PostgreSQL/Docker/Fastify/React; alta completa de `backend/`, `authenticator-app/`, `admin-console/`, `sdk/`, `demo-portal-tramites/`, `attack-lab/`, `deploy/` |
| 2026-11-26 | Alta de DAST propio (`#24`), verificación `systemd` (`#25`) y limpieza final (`#26`) | `attack-lab/escenarios/dast.js`, `attack-lab/tests/dast.test.js`, `deploy/verificar-despliegue.js`, `docs/evidencias/`, `docs/sbom/` |
| 2026-11-26 | Alta de CI sin dependencias (`#31`), compatibilidad Key URI (`#29`), limpieza README (`#30`), ADR-004 + `mobile-android/` (`#39`–`#41`), `sitio-publico/` (`#48`, `#49`, `#52`), capturas (`#51`) y accesibilidad (`#33`, `#50`) | `scripts/verificar-todo.js`, `.gitlab-ci.yml`, `.github/workflows/pruebas.yml`, `mobile-android/`, `sitio-publico/`, `scripts/capturas.js`, `docs/evidencias/` |
| 2026-11-26 | Montaje de `sitio-publico/` en backend (`#48`, `#49`, `#52`), centro de ayuda `/ayuda` en portal demo (`#53`) y expansión de `mobile-android/` con cédula V/E, KeystoreVault, PinManager y OtpAuthParser (`#40`–`#43`) | `backend/src/api/servidor.js`, `backend/src/main.js`, `sitio-publico/`, `demo-portal-tramites/`, `mobile-android/` |
