# AGENTS.md — Guía Maestra al Unísono (`servicio-soberano-autenticacion-totp`)

> **LECTURA OBLIGATORIA:** Todo agente de IA (de J Laya, Diego o cualquier compañero, sin importar modelo o IDE) **DEBE leer este archivo, `docs/analisis/analisis-tecnico.html`, `ARCHITECTURE.md`, `SYSTEM_GRAPH.md`, `contracts/openapi.yaml` y `TASKS.md` antes de crear, modificar o proponer cualquier código.**

---

## 1. Contexto Oficial del Proyecto (Alineado a ADR-002)

- **Repositorio de trabajo (GitHub):** `https://github.com/PSM-Hackaton/servicio-soberano-autenticacion-totp`
- **Documento rector técnico:** `docs/analisis/analisis-tecnico.html` (v1.2, Diego Landaeta) + `ARCHITECTURE.md` (**ADR-002**, 26-11-2026).
- **Reto oficial:** **Servicio Soberano de Autenticación Multifactorial basado en Tiempo (TOTP)** *(ver `docs/reto/AutenticaciónMultifactorial_TerminosEspecificaciones.pdf`)*.
- **Stack 100 % propio y autoejecutable (ADR-002):**
  - **Cero dependencias npm** en ejecución y pruebas. Solo módulos nativos de **Node.js 22+** (`node:https`, `node:crypto`, `node:sqlite`, `node:test`).
  - **Lenguaje:** JavaScript moderno (ESM, `"type": "module"`) con comentarios JSDoc.
  - **Base de datos oficial única:** **SQLite WAL nativa** (`contracts/schema.sqlite.sql`). PostgreSQL y Docker quedan fuera del alcance del hackatón.
  - **Frontends (`authenticator-app/`, `admin-console/`, `demo-portal-tramites/`):** HTML + CSS + JavaScript propios sin React, Vite ni CDNs.
- **Integración con Reto 1:** El sub-equipo del **Reto 1** se integra como una `app` cliente más (`reto1-evaluador`) usando `sdk/` (ver `sdk/INTEGRACION_RETO1.md`).
- **Soberanía y costo operativo:** **\$0 en APIs externas**, **100 % local / sin llamadas a Internet**, cero librerías OTP externas.

---

## 2. Reglas Inquebrantables de Git, GitHub y GitLab

1. **PROHIBIDO tocar `main`:** Nunca hagas `commit` ni `push` directo a `main`.
2. **POLÍTICA DE REMOTOS (ORDEN ESTRICTA DE J LAYA):**
   - **GitHub (`origin`):** **EXCLUSIVO para todas las subidas, PRs y trabajo diario del equipo.**
   - **GitLab (`gitlab`):** **BLOQUEADO.** Prohibido ejecutar `git push` hacia GitLab hasta que J Laya dé la orden literal **`/push gitlab final`**.
3. **Áreas de trabajo y ramas (cero conflictos al unir en `staging`):**
   - **Área A — Núcleo y API (Diego, rama `diego`):** `backend/`.
   - **Área B — Clientes, contratos e integración (J Laya, rama `laya`):** `contracts/`, `sdk/`, `authenticator-app/`, `admin-console/`, `demo-portal-tramites/`, `attack-lab/`, `docs/sbom/`, `docs/GUION_DEMO.md`, documentos raíz.
   - Integración en GitHub: PR hacia **`staging`**, luego prueba end-to-end (Issue #16 C1) y PR `staging` → `main`.
4. **Contratos congelados (`contracts/`):** `contracts/openapi.yaml`, `contracts/schema.sqlite.sql` y `contracts/mocks/` son el punto de unión entre Área A y Área B.
5. **Cero secretos en Git:** Nunca commitear `.env`, llaves maestras, `*.pem`, `*.key`, `*.crt`, `*.db` ni secretos reales.
6. **Protocolo Graphy (`SYSTEM_GRAPH.md`):** Leer antes de escribir código; agregar nodos nuevos y podar nodos obsoletos en cada avance.

---

## 3. Estructura Oficial del Repositorio (ADR-002)

```text
servicio-soberano-autenticacion-totp/
├── AGENTS.md                        # Guía maestra al unísono (ADR-002)
├── ARCHITECTURE.md                  # ADRs, stack cero dependencias y áreas Diego/Laya
├── ANALISIS_FASE0.md                # Auditoría Fase 0 y prioridades
├── SYSTEM_GRAPH.md                  # Grafo vivo de conexiones (Protocolo Graphy)
├── CONTRIBUTING.md                  # Reglas GitHub, bloqueo GitLab y Code Freeze
├── TASKS.md                         # Pizarrón vivo de tareas verificadas
├── README.md                        # Documentación oficial de entrega (6 apartados)
├── .env.example                     # Variables de entorno sin secretos (SQLite + Node TLS)
├── contracts/                       # Contratos congelados (OpenAPI 3.1, SQLite única, Mocks)
│   ├── openapi.yaml                 # Incluye /health/ready, /metrics, Idempotency-Key y 503
│   ├── schema.sqlite.sql            # Esquema oficial único (8 tablas, node:sqlite WAL)
│   └── mocks/                       # Mocks alineados 100 % al contrato
├── backend/                         # Área A (Diego): Node 22 nativo, 0 deps npm
│   ├── src/core/{totp,vault,tokens,qr}/
│   ├── src/infrastructure/persistence/
│   ├── src/application/use-cases/
│   ├── src/security/
│   ├── src/heuristics/
│   ├── src/audit/
│   └── src/api/
├── authenticator-app/               # Área B (Laya): PWA offline (Web Crypto, IndexedDB+PIN, SW)
├── admin-console/                   # Área B (Laya): Consola RBAC + TOTP + cadena audit_log + IA
├── sdk/                             # Área B (Laya): SDK JS nativo + caché JWKS offline + Guía Reto 1
├── demo-portal-tramites/            # Área B (Laya): Portal demo + servidor local 0 deps
├── attack-lab/                      # Área B (Laya): Ataques simulados + pruebas de caos + informe
└── docs/                            # reto/, analisis/, sbom/ (CycloneDX 1.5), GUION_DEMO.md
```

---

## 4. Invariantes Criptográficas, de Seguridad y Resiliencia (Obligatorias)

1. **Motor TOTP Propio (RFC 6238):** `node:crypto` / Web Crypto únicamente; SHA-256 (32 B) y SHA-512 (64 B); truncado dinámico RFC 4226; comparación en tiempo constante; vectores Apéndice B en verde; deriva y resincronización con 2 códigos consecutivos (±10 pasos).
2. **AES-256-GCM con AAD:** Nonce 96 bits + `AAD = enrollment_id + ":" + key_version`; llave maestra versionada fuera de BD. En la PWA, semillas cifradas en IndexedDB con PBKDF2-SHA256 + AES-256-GCM.
3. **Anti-Replay Atómico y `jti` de un solo uso:** `UPDATE enrollments SET last_step = ? ... WHERE last_step < ?` + consumo único de `jti` en `consumed_jti`.
4. **Resiliencia *Fail-Closed*:** Si SQLite cae, `/health/ready` y `/api/v1/*` responden `503` (jamás se concede acceso). El SDK aplica timeout de `3000 ms`, `1` reintento con la misma `Idempotency-Key` y valida JWT ya emitidos sin red vía caché JWKS.
5. **Anonimización con Pepper:** `user_ref_hash = HMAC-SHA256(user_ref, USER_PEPPER)` e `ip_hash = HMAC-SHA256(ip, DAILY_IP_PEPPER)`.
6. **Bitácora Encadenada (`audit_log`):** `hash = SHA-256(prev_hash || payload)` verificable desde `admin-console/`.
7. **Trazabilidad y Cero Dependencias:** SBOM CycloneDX 1.5 en `docs/sbom/sbom.cdx.json` reflejando 0 dependencias npm de terceros.
