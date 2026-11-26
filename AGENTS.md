# AGENTS.md — Guía Maestra al Unísono (`servicio-soberano-autenticacion-totp`)

> **LECTURA OBLIGATORIA:** Todo agente de IA (sin importar modelo o IDE) **DEBE leer este archivo, `docs/analisis/analisis-tecnico.html`, `ARCHITECTURE.md`, `SYSTEM_GRAPH.md`, `contracts/openapi.yaml` y `TASKS.md` antes de crear, modificar o proponer cualquier código.**

---

## 1. Contexto Oficial del Proyecto (ADR-002)

- **Repositorio de trabajo (GitHub):** `https://github.com/PSM-Hackaton/servicio-soberano-autenticacion-totp`
- **Documento rector técnico:** `docs/analisis/analisis-tecnico.html` (v1.2, Diego Landaeta) + `ARCHITECTURE.md` (**ADR-002**, 26-11-2026).
- **Reto oficial:** **Servicio Soberano de Autenticación Multifactorial basado en Tiempo (TOTP)** *(ver `docs/reto/AutenticaciónMultifactorial_TerminosEspecificaciones.pdf`)*.
- **Stack 100 % propio y autoejecutable (ADR-002):**
  - **Cero dependencias npm** en ejecución y pruebas. Solo módulos nativos de **Node.js 22.5+** (`node:https`, `node:http`, `node:net`, `node:crypto`, `node:sqlite`, `node:test`).
  - **Lenguaje:** JavaScript moderno (ESM, `"type": "module"`) con comentarios JSDoc.
  - **Base de datos oficial única:** **SQLite WAL nativa** (`contracts/schema.sqlite.sql` y `backend/migrations/001_esquema.sql`). PostgreSQL y Docker quedan fuera del alcance del hackatón.
  - **Frontends (`authenticator-app/`, `admin-console/`, `demo-portal-tramites/`):** HTML + CSS + JavaScript propios servidos localmente sin React, Vite ni CDNs. El backend sirve directamente `/app/` (PWA) y `/consola/` (Consola Admin).
- **Integración con Reto 1:** `npm run seed` registra la app cliente `Reto 1`, que se integra mediante `sdk/` siguiendo `sdk/INTEGRACION_RETO1.md`.
- **Soberanía y costo operativo:** **\$0 en APIs externas**, **100 % local / sin llamadas a Internet**, cero librerías OTP externas.

---

## 2. Reglas Inquebrantables de Git, GitHub y GitLab

1. **PROHIBIDO tocar `main`:** Nunca hagas `commit` ni `push` directo a `main`.
2. **POLÍTICA DE REMOTOS (ORDEN ESTRICTA DE J LAYA):**
   - **GitHub (`origin`):** **EXCLUSIVO para todas las subidas, PRs y trabajo diario del equipo.**
   - **GitLab (`gitlab`):** **BLOQUEADO.** Prohibido ejecutar `git push` hacia GitLab hasta que J Laya dé la orden literal **`/push gitlab final`**.
3. **Flujo de ramas en GitHub:**
   - Ramas del equipo: `diego` y `laya` → Pull Request hacia **`staging`** → validación conjunta (Issue #16 C1) → PR `staging` → `main`.
4. **Contratos congelados (`contracts/`):** `contracts/openapi.yaml`, `contracts/schema.sqlite.sql` y `contracts/mocks/` reflejan exactamente las rutas y respuestas reales del servidor.
5. **Cero secretos en Git:** Nunca commitear `.env`, llaves maestras, `*.pem`, `*.key`, `*.crt`, `*.db` ni informes con credenciales reales.
6. **Protocolo Graphy (`SYSTEM_GRAPH.md`):** Leer antes de escribir código; agregar nodos nuevos y podar nodos obsoletos en cada avance.

---

## 3. Estructura Oficial del Repositorio (Unificada)

```text
servicio-soberano-autenticacion-totp/
├── AGENTS.md                        # Guía maestra al unísono (ADR-002)
├── ARCHITECTURE.md                  # ADRs, stack cero dependencias y comandos reales
├── ANALISIS_FASE0.md                # Auditoría Fase 0
├── SYSTEM_GRAPH.md                  # Grafo vivo de conexiones (Protocolo Graphy)
├── CONTRIBUTING.md                  # Reglas GitHub, bloqueo GitLab y Code Freeze
├── SECURITY.md                      # Política de seguridad y principios
├── TASKS.md                         # Pizarrón vivo de tareas verificadas
├── README.md                        # Documentación oficial de entrega (6 apartados)
├── .env.example                     # Variables de entorno sin secretos
├── contracts/                       # OpenAPI 3.1, schema.sqlite.sql (8 tablas) y mocks/
├── backend/                         # API HTTPS TLS 1.3 + motor TOTP + vault + tokens + QR + SQLite + seguridad + auditoría + IA + scripts/
├── authenticator-app/               # PWA offline propia (servida en /app/) + tests/
├── admin-console/                   # Consola administrativa RBAC propia (servida en /consola/)
├── sdk/                             # SDK Node 22 nativo (src/, testing/, tests/, INTEGRACION_RETO1.md)
├── demo-portal-tramites/            # Portal institucional demo con step-up MFA + tests/
├── attack-lab/                      # 9 escenarios de ataque y caos + proxy-caos.js + tests/
├── deploy/                          # servicio-totp.service (systemd) + README.md
└── docs/                            # reto/, analisis/, sbom/ (CycloneDX 1.5), GUION_DEMO.md
```

---

## 4. Invariantes Criptográficas, de Seguridad y Resiliencia

1. **Motor TOTP Propio (RFC 6238/4226):** `node:crypto` y Web Crypto únicamente; SHA-256 (32 B) y SHA-512 (64 B); vectores Apéndice B en verde; compensación de deriva y resync con 2 códigos consecutivos (±10 pasos).
2. **AES-256-GCM con AAD:** Nonce 96 bits + `AAD = enrollment_id + ":" + key_version`; llave maestra versionada + script de rotación (`npm run rotar-llave-maestra`). En la PWA: bóveda cifrada con PIN en IndexedDB.
3. **Anti-Replay Atómico y `jti` de un solo uso:** `UPDATE enrollments SET last_step = ? ... WHERE last_step < ?` y registro único de `jti` en `consumed_jti` (incluso `consume_jti: false` rechaza `jti` ya usados).
4. **Resiliencia *Fail-Closed*:** Si SQLite falla, `/health/ready` y `/api/v1/*` responden `503` (0 accesos indebidos). El SDK aplica timeout de `3000 ms`, `1` reintento con la misma `Idempotency-Key` y validación offline de JWT vía caché JWKS.
5. **Anonimización con Pepper:** `user_ref_hash = HMAC-SHA256(user_ref, USER_PEPPER)` e `ip_hash = HMAC-SHA256(ip, DAILY_IP_PEPPER)`.
6. **Bitácora Encadenada (`audit_log`):** `hash = SHA-256(prev_hash || payload)` verificable desde `/admin/api/audit/verify-chain` y la Consola Admin.
7. **Trazabilidad:** SBOM CycloneDX 1.5 en `docs/sbom/sbom.cdx.json` con **0 dependencias npm externas**.
