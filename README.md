# Servicio Soberano de Autenticación Multifactorial basado en Tiempo (TOTP)

> **Hackatón Venezuela INNOVA 2026** · **Reto Grupal 3** (con puente SDK hacia Reto 1) · **Equipo PSM-Hackaton**

---

## 1. Nombre del proyecto

**Servicio Soberano de Autenticación Multifactorial basado en Tiempo (TOTP)**  
*(Repositorio: `servicio-soberano-autenticacion-totp`)*

---

## 2. Participantes

| Integrante | Rol Principal | Responsabilidades |
| :--- | :--- | :--- |
| **J Laya** | Analista, Arquitecto y Tech Lead | Arquitectura hexagonal, contratos congelados (`contracts/`), coordinación de ramas/integración, guía Reto 1 (`sdk/INTEGRACION_RETO1.md`), SBOM CycloneDX (`docs/sbom/`), guion de demo y documentación oficial |
| **Diego Landaeta** | Arquitecto de Criptografía, Backend y Seguridad | Análisis técnico (`docs/analisis/`), motor TOTP RFC 6238, vault AES-256-GCM, JWT Ed25519/JWKS, QR ISO/IEC 18004, persistencia SQLite nativa, seguridad, auditoría encadenada, Isolation Forest local, API HTTPS TLS 1.3, clientes integrados y `attack-lab/` |
| **Equipo Integrador Reto 1** | Consumidor externo vía `sdk/` | Integración del *Agente Evaluador de Propuestas de Servicios* como aplicación cliente (`Reto 1`) |

---

## 3. Descripción del proyecto

Las instituciones públicas suelen depender de autenticadores comerciales y servicios MFA en nubes extranjeras (Google Authenticator, Microsoft Authenticator, Authy o proveedores SaaS), cediendo la custodia de las semillas, limitándose a SHA-1 y dependiendo de tiendas de aplicaciones y conectividad a Internet.

Este proyecto entrega un **sistema completo de autenticación de segundo factor (TOTP, RFC 6238) 100 % soberano, auditable y autoejecutable con cero dependencias npm externas**:

- **Motor criptográfico y backend propio (`backend/`):** implementado únicamente con módulos nativos de Node.js 22 (`node:https`, `node:crypto`, `node:sqlite`, `node:test`). Incluye RFC 6238 / RFC 4226 con **HMAC-SHA256 y HMAC-SHA512** (6 u 8 dígitos), semillas CSPRNG cifradas en reposo con **AES-256-GCM + AAD**, tokens **JWT Ed25519 (`EdDSA`)** con `/.well-known/jwks.json` y rotación de `kid`, generador de **QR SVG propio (ISO/IEC 18004 + Reed-Solomon)**, anti-replay atómico, `jti` de un solo uso, bitácora encadenada por hashes SHA-256 (`audit_log`), métricas Prometheus locales y un **detector local de anomalías (Isolation Forest propio)** con inferencia en milisegundos y 0 telemetría externa.
- **App Autenticadora PWA propia (`authenticator-app/`):** servida directamente por la institución (`/app/`), funciona **100 % sin conexión** (Service Worker + Web Crypto), cifra las semillas en IndexedDB con **PIN (PBKDF2 + AES-GCM)** y soporta SHA-256/512 (6/8 dígitos) con alta por enlace directo, URI `otpauth://`, clave manual Base32 o cámara QR.
- **Consola Administrativa con RBAC (`admin-console/`):** servida en `/consola/`, protegida con cookies `HttpOnly; Secure; SameSite=Strict` + CSRF + **TOTP propio** y roles `Administrador`, `Operador` y `Auditor`. Permite gestionar apps/políticas, revocar enrolamientos, rotar llaves Ed25519 en 1 clic, inspeccionar alertas de IA y verificar criptográficamente la cadena `audit_log`.
- **SDK institucional y Portal Demo (`sdk/`, `demo-portal-tramites/`):** SDK ESM sin dependencias con timeout de 3 s, 1 reintento idempotente (`Idempotency-Key`), política estricta *fail-closed* y **validación offline de JWT con caché JWKS**. Incluye un Portal Institucional de Trámites con step-up MFA y guía directa para integrar el **Reto 1**.
- **Laboratorio de ataques y caos (`attack-lab/`):** 9 escenarios automatizados (replay + carrera paralela, JWT alterados, entradas malformadas, fuerza bruta local y distribuida, spraying, inundación, proxy TCP de caos con latencia/cortes y reinicio del backend) con generación de informes autocontenidos.

---

## 4. Alcance

### Funcionalidades cubiertas en esta versión
- **Backend soberano (`backend/`):** API HTTPS TLS 1.3 completa (`contracts/openapi.yaml`), 8 tablas en SQLite WAL (`contracts/schema.sqlite.sql`), scripts operativos (`generar-env.js`, `certificados.js`, `semilla.js`, `rotar-llave-maestra.js`) y suite completa de pruebas unitarias e integración.
- **Clientes propios (HTML + CSS + JS sin React, Vite ni CDNs):** PWA Autenticadora (`/app/`), Consola Administrativa RBAC (`/consola/`) y Portal Institucional de Trámites (`demo-portal-tramites/`).
- **SDK e integración Reto 1 (`sdk/`):** cliente Node 22 nativo, verificador JWKS offline, servicio falso para pruebas y guía [`sdk/INTEGRACION_RETO1.md`](./sdk/INTEGRACION_RETO1.md).
- **Seguridad, Caos, Despliegue y Trazabilidad (`attack-lab/`, `deploy/`, `docs/`):** 9 escenarios de ataque y caos, unidad `systemd` endurecida ([`deploy/servicio-totp.service`](./deploy/servicio-totp.service)), inventario **SBOM CycloneDX 1.5** ([`docs/sbom/sbom.cdx.json`](./docs/sbom/sbom.cdx.json)) y guion de demo ([`docs/GUION_DEMO.md`](./docs/GUION_DEMO.md)).

### Límites de la entrega (fuera del alcance de 48 h)
- Contenedores Docker y clúster PostgreSQL externo (descartados por **ADR-002** para garantizar ejecución nativa en las estaciones del hackatón y despliegue institucional ligero con `systemd` + SQLite WAL).
- Integración física con HSM/TPM hardware (el módulo `core/vault` ya aísla la llave maestra versionada para facilitar su conexión futura).
- Canales externos de SMS/correo (excluidos intencionalmente por soberanía y costo operativo \$0).

---

## 5. Requerimientos del sistema

- **Sistema operativo:** Linux (probado en Ubuntu, con unidad `systemd` lista en `deploy/`), macOS o Windows.
- **Runtime:** **Node.js 22.5+** (probado en `v22.22.1`) con módulos nativos `node:https`, `node:crypto`, `node:sqlite` y `node:test`.
- **Dependencias npm externas:** **0 (cero)** en ejecución, construcción y pruebas (certificado en [`docs/sbom/sbom.cdx.json`](./docs/sbom/sbom.cdx.json)).
- **Base de datos:** SQLite integrada en Node.js (`node:sqlite`, modo WAL, esquema oficial [`contracts/schema.sqlite.sql`](./contracts/schema.sqlite.sql)).
- **Herramientas del sistema:** `openssl` (para generar certificados TLS 1.3 locales de prueba con `npm run certs`); `chrony` recomendado en servidores de producción para sincronización NTP institucional.
- **Navegador web:** cualquier navegador moderno con Web Crypto API e IndexedDB para la PWA, la Consola Admin y el Portal Demo.
- **Variables de entorno:** documentadas sin secretos en [`.env.example`](./.env.example) y generables automáticamente con `cd backend && npm run env`.

---

## 6. Instalación y despliegue

### Paso 1 — Clonar el repositorio
```bash
git clone https://github.com/PSM-Hackaton/servicio-soberano-autenticacion-totp.git
cd servicio-soberano-autenticacion-totp
```

### Paso 2 — Configurar, generar certificados TLS 1.3 y datos semilla (sin `npm install`)
```bash
cd backend
npm run env      # crea backend/.env con llave maestra AES-256 y peppers CSPRNG
npm run certs    # crea CA local y certificado TLS 1.3 en backend/certs/
npm run seed     # crea apps "Portal de Trámites" y "Reto 1" + admin inicial (anotar credenciales)
```

### Paso 3 — Ejecutar todas las suites de pruebas automatizadas
```bash
# Backend completo (TOTP RFC 6238, Vault, Tokens, QR, SQLite, Seguridad, Auditoría, IA, Casos de Uso y API HTTPS)
cd backend && npm test && cd ..

# PWA Autenticadora (Web Crypto, Base32, otpauth://, cifrado PBKDF2/AES-GCM)
node --test authenticator-app/tests/*.test.mjs

# SDK e integración del Portal de Trámites Demo
node --test sdk/tests/sdk.test.js demo-portal-tramites/tests/portal.test.js

# Pruebas unitarias del Attack Lab y proxy de caos
cd attack-lab && npm test && cd ..
```

### Paso 4 — Arrancar los servicios en local (100 % sin Internet)
```bash
# Terminal 1 — Backend Soberano HTTPS (API v1 + /app/ PWA + /consola/ Admin)
cd backend && npm start
# → API: https://localhost:8443/health/ready
# → PWA Autenticadora: https://localhost:8443/app/
# → Consola Admin RBAC: https://localhost:8443/consola/

# Terminal 2 — Portal Institucional de Trámites Demo
cd demo-portal-tramites
cp .env.example .env   # colocar TOTP_CLIENT_ID y TOTP_CLIENT_SECRET impresos en Paso 2
node scripts/crear-usuarios.js
node server.js         # → https://localhost:8444

# Terminal 3 — Attack Lab y Pruebas de Caos contra el backend real
export ATTACK_CLIENT_ID=<client_id> ATTACK_CLIENT_SECRET=<client_secret>
node attack-lab/ejecutar-todo.js
```

> Para despliegue institucional en producción Linux con `systemd` (sin contenedores), consultar [`deploy/README.md`](./deploy/README.md).
