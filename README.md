# Servicio Soberano de Autenticación Multifactorial basado en Tiempo (TOTP)

> **Hackatón Venezuela INNOVA 2026** · **Reto Grupal 3** (con puente SDK hacia Reto 1) · **Equipo PSM-Hackaton**

---

## 1. Nombre del proyecto

**Servicio Soberano de Autenticación Multifactorial basado en Tiempo (TOTP)**  
*(Repositorio: `servicio-soberano-autenticacion-totp`)*

---

## 2. Participantes

| Integrante | Rol Principal | Área de Responsabilidad |
| :--- | :--- | :--- |
| **J Laya** | Analista, Arquitecto, Tech Lead & Área B | Contratos (`contracts/`), PWA Autenticadora (`authenticator-app/`), Consola Admin RBAC (`admin-console/`), SDK + Portal Demo (`sdk/`, `demo-portal-tramites/`), Attack Lab & Caos (`attack-lab/`), SBOM y Documentación |
| **Diego Landaeta** | Arquitecto de Criptografía, Seguridad & Área A | Análisis Técnico (`docs/analisis/`), Motor TOTP RFC 6238, Vault AES-256-GCM, Tokens JWT Ed25519/JWKS, QR ISO/IEC 18004, Persistencia SQLite nativa, Seguridad, Auditoría encadenada, Heurística IA local y API HTTPS (`backend/`) |
| **Equipo Integrador Reto 1** | Consumidor externo vía `sdk/` | Integración del *Agente Evaluador de Propuestas de Servicios* como aplicación cliente (`reto1-evaluador`) |

---

## 3. Descripción del proyecto

Las instituciones públicas dependen con frecuencia de autenticadores y servicios MFA controlados por proveedores extranjeros (Google Authenticator, Microsoft Authenticator, Authy o nubes comerciales), lo que implica pérdida de custodia sobre semillas criptográficas, telemetría externa, dependencia de tiendas de aplicaciones y vulnerabilidad ante bloqueos o caídas de Internet.

Este proyecto entrega una **plataforma completa de autenticación de segundo factor (MFA/TOTP) 100 % soberana, auditable y autoejecutable sin dependencias npm externas**:

- **Criptografía estándar propia (`node:crypto`):** Motor RFC 6238 / RFC 4226 con **HMAC-SHA256 y HMAC-SHA512** (6 u 8 dígitos), semillas CSPRNG cifradas con **AES-256-GCM + AAD**, JWT firmados con **Ed25519 (EdDSA)** + `/.well-known/jwks.json` con rotación por `kid`, anti-replay atómico y `jti` de un solo uso.
- **App Autenticadora PWA propia (`authenticator-app/`):** Funciona **100 % sin conexión** (Service Worker + Web Crypto), soporta SHA-256 y SHA-512 (6/8 dígitos), protege las semillas en IndexedDB cifradas con **PBKDF2-SHA256 + AES-256-GCM** bajo PIN del usuario, alta por clave manual Base32, URI `otpauth://` y cámara QR.
- **Consola Administrativa con RBAC (`admin-console/`):** Login con roles (`Administrador`, `Operador`, `Auditor`) + TOTP propio, gestión de aplicaciones y políticas, revocación de enrolamientos, rotación de llaves Ed25519 en 1 clic, métricas Prometheus locales, alertas del detector local de anomalías (IA sin telemetría) y **verificador criptográfico de la bitácora encadenada (`audit_log`)**.
- **Integración institucional (`sdk/` y `demo-portal-tramites/`):** SDK JavaScript ESM sin dependencias con timeout de 3 s, 1 reintento idempotente (`Idempotency-Key`), política estricta *fail-closed* y validación **offline de JWT vía caché JWKS**; incluye Portal de Trámites demo y guía directa para el **Reto 1**.
- **Verificación de seguridad y resiliencia (`attack-lab/`):** Laboratorio reproducible de ataques simulados (replay, fuerza bruta distribuida, spraying, deriva de reloj) y pruebas de caos (caída de SQLite, corte de red, latencia artificial) verificando **0 accesos indebidos**.

---

## 4. Alcance

### Funcionalidades cubiertas en esta versión
- **Contratos congelados (`contracts/`):** OpenAPI 3.1 (`openapi.yaml`) con endpoints MFA v1, Admin, `/health`, `/health/ready`, `/metrics`, cabecera `Idempotency-Key` y respuestas `503` (*fail-closed*); esquema único SQLite WAL (`schema.sqlite.sql`, 8 tablas); mocks completos (`contracts/mocks/`).
- **Núcleo backend (`backend/`):** Motor TOTP RFC 6238 (vectores Apéndice B en verde), Vault AES-256-GCM con AAD, Tokens Ed25519 + JWKS, QR SVG propio (ISO/IEC 18004 + Reed-Solomon), persistencia `node:sqlite` (8 tablas + anti-replay atómico), seguridad (scrypt, rate limit, bloqueos progresivos), auditoría encadenada SHA-256, métricas Prometheus, IA local y API `node:https`.
- **Clientes 100 % propios (HTML + CSS + JS sin React/Vite/CDNs):** PWA Autenticadora offline (`authenticator-app/`), Consola Administrativa RBAC (`admin-console/`) y Portal Institucional de Trámites demo (`demo-portal-tramites/`).
- **SDK y puente Reto 1 (`sdk/`):** Cliente JS nativo con caché JWKS offline + guía `sdk/INTEGRACION_RETO1.md`.
- **Attack Lab, Caos y Trazabilidad (`attack-lab/`, `docs/`):** Suite automatizada de 7 escenarios con informe en JSON/Markdown, inventario **SBOM CycloneDX 1.5** (`docs/sbom/sbom.cdx.json`) y guion de demostración (`docs/GUION_DEMO.md`).

### Límites de la entrega (fuera del alcance de 48 h)
- Despliegue en clúster multi-nodo, PostgreSQL externo y contenedores Docker (reemplazados por **ADR-002**: Node.js 22 + `node:sqlite` WAL + TLS nativo de Node por restricción de estaciones del hackatón sin Docker).
- Integración física con HSM/TPM hardware (el diseño ya aísla el vault con llave maestra versionada para conectarlo en producción).
- Envío de notificaciones por SMS/correo (excluido deliberadamente por soberanía y costo operativo \$0).

---

## 5. Requerimientos del sistema

- **Sistema operativo:** Linux (probado en Ubuntu), macOS o Windows.
- **Runtime:** **Node.js 22+** (probado en `v22.22.1`) con soporte nativo para ESM, `node:crypto`, `node:https`, `node:sqlite` y `node:test`.
- **Dependencias npm externas:** **0 (cero)** en ejecución y en pruebas (ver `docs/sbom/sbom.cdx.json`).
- **Base de datos:** SQLite integrada en Node.js 22 (`node:sqlite`, modo WAL, esquema `contracts/schema.sqlite.sql`).
- **TLS local:** `openssl` del sistema para certificados locales en desarrollo (`TLS_MODE=node`).
- **Navegador web:** Cualquier navegador moderno con Web Crypto API e IndexedDB (Chromium, Firefox, Safari) para la PWA, Consola Admin y Portal Demo.
- **Variables de entorno:** Documentadas sin secretos en `.env.example` (`PORT`, `TLS_MODE`, `SQLITE_DB_PATH`, `MASTER_KEY_V1_HEX`, `USER_REF_PEPPER`, `DAILY_IP_PEPPER_SEED`, `TOTP_ISSUER`, `JWT_ISSUER`).

---

## 6. Instalación y despliegue

### Paso 1 — Clonar el repositorio
```bash
git clone https://github.com/PSM-Hackaton/servicio-soberano-autenticacion-totp.git
cd servicio-soberano-autenticacion-totp
```

### Paso 2 — Configurar variables de entorno (sin instalar paquetes)
```bash
cp .env.example backend/.env
# Editar backend/.env y asignar valores aleatorios (CSPRNG) para MASTER_KEY_V1_HEX y peppers:
# node -e "console.log(require('node:crypto').randomBytes(32).toString('hex'))"
```

### Paso 3 — Ejecutar las suites de pruebas automatizadas (0 dependencias npm)
```bash
# Pruebas de la PWA Autenticadora (vectores RFC 6238 SHA-1/256/512 + bóveda PBKDF2/AES-GCM)
node --test authenticator-app/totp-core.test.js

# Pruebas de la Consola Administrativa (RBAC, parser Prometheus y verificador de cadena audit_log)
node --test admin-console/admin-api.test.js

# Pruebas del SDK (timeout, reintento idempotente, rotación kid y JWKS offline)
node --test sdk/sdk.test.js

# Pruebas del Portal Institucional de Trámites demo (flujo ciudadano completo)
node --test demo-portal-tramites/portal.test.js

# Suite completa de Attack Lab y Pruebas de Caos (genera attack-lab/REPORTE_DEMO.md)
node attack-lab/run-all.js
```

### Paso 4 — Levantar la demo interactiva en local
```bash
# Levanta en 1 comando el Portal de Trámites, la PWA Autenticadora y la Consola Admin:
node demo-portal-tramites/server.js

# URLs locales (100 % sin Internet):
#   · Portal de Trámites Demo:  http://127.0.0.1:3000/
#   · PWA Autenticadora Offline: http://127.0.0.1:3000/authenticator/
#   · Consola Administrativa:    http://127.0.0.1:3000/admin/
```

> Para conectar el Portal de Trámites al servidor HTTPS del backend una vez integrado en `staging`:
> ```bash
> TOTP_API_URL=https://localhost:8443 TOTP_CLIENT_ID=portal-tramites TOTP_CLIENT_SECRET=<secreto> node demo-portal-tramites/server.js
> ```

### Documentación complementaria
- [`ARCHITECTURE.md`](./ARCHITECTURE.md) — ADRs, stack ADR-002 cero dependencias y áreas de trabajo.
- [`contracts/openapi.yaml`](./contracts/openapi.yaml) — Contrato OpenAPI 3.1 oficial.
- [`sdk/INTEGRACION_RETO1.md`](./sdk/INTEGRACION_RETO1.md) — Guía de integración en 4 llamadas para el Reto 1.
- [`docs/GUION_DEMO.md`](./docs/GUION_DEMO.md) — Guion paso a paso de la presentación y demo en vivo ante el jurado.
- [`docs/sbom/sbom.cdx.json`](./docs/sbom/sbom.cdx.json) — Inventario CycloneDX 1.5 (0 dependencias npm de terceros).
