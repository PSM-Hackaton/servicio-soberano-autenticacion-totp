# ARCHITECTURE.md — Servicio Soberano de Autenticación Multifactorial (TOTP)

> **Estado:** Fase 1 (Estructura Hexagonal y Contratos Congelados — listo para ejecución paralela).
> **Referencia de diseño:** Adapta el patrón **Arquitectura Hexagonal (Ports & Adapters)** + pistas paralelas + `MockAdapter` + seguridad prioritaria en **Node.js + TypeScript**, enfocado al 100% en las especificaciones oficiales de `docs/reto/AutenticaciónMultifactorial_TerminosEspecificaciones.pdf`.

---

## 1. Decisiones Arquitectónicas (ADR)

### ADR-001: Arquitectura Hexagonal (Ports & Adapters)
- **Decisión:** Aislar completamente el núcleo criptográfico TOTP (`domain/`) y los casos de uso (`application/`) de HTTP, SQLite, criptografía del SO e IA local (`infrastructure/`).
- **Por qué:**
  1. Permite que Backend, Frontend, IA/Cripto y el equipo del **Reto 1** trabajen en paralelo usando `contracts/` y `MockAnomalyAdapter` sin bloquearse.
  2. Permite cambiar **SQLite WAL** (hackathon sin Docker) por **PostgreSQL** en producción cambiando únicamente el adaptador en `infrastructure/adapters/out/persistence/`, sin tocar el dominio.
  3. Permite evolucionar `LocalAnomalyAdapter` (heurística + scoring estadístico local) a un modelo ONNX/ML más complejo sin tocar `VerifyTotpService`.

### ADR-002: Stack Aprobado — Node.js 22 + TypeScript + Fastify + SQLite WAL + React/Vite
- **Backend (`backend/`):** Node.js 22 LTS, TypeScript estricto, Fastify (validación de esquemas JSON nativa + rendimiento alto anti-DDoS), `node:crypto` nativo (CSPRNG, HMAC-SHA256/512, AES-256-GCM, Ed25519, `timingSafeEqual`), `jose` (JWT EdDSA + JWKS), `better-sqlite3` (modo WAL, 0 Docker, 0 GPU), `@fastify/helmet`, `@fastify/rate-limit`, `qrcode`.
- **Frontend (`frontend/`):** React + Vite + TypeScript + Tailwind CSS (3 módulos claros o SPA con 3 vistas bien diferenciadas: **Consola Admin**, **Cliente Autenticador PWA Soberano** y **Portal Institucional Demo**).
- **SDK (`sdk/`):** Módulo TypeScript/ESM sin dependencias pesadas (usa `jose` o `fetch` nativo) para que el **Reto 1** integre MFA en <10 minutos.
- **Justificación frente al entorno real:** El nodo del hackatón tiene 12 cores, 14 GB RAM, Node 22 preinstalado, **sin Docker** y **sin GPU**. Este stack arranca en segundos, cuesta **\$0**, funciona **100% offline** y genera SBOM auditable con herramientas nativas (`npm sbom`).

### ADR-003: Seguridad por Diseño (Cifrado en Reposo y Tránsito + Soberanía)
- **En tránsito:** TLS 1.2/1.3 en el servidor Fastify (`HTTPS` con certificado autofirmado generado localmente en `certs/` excluido de Git; configurable vía `TLS_CERT_PATH` y `TLS_KEY_PATH`).
- **En reposo:** Cifrado **AES-256-GCM** con clave maestra `AES_MASTER_KEY_HEX` (32 bytes en `.env`) y nonce único por registro para:
  - Semillas TOTP (`secret_ciphertext`, `secret_iv`, `secret_auth_tag`).
  - Claves privadas Ed25519 (`private_key_ciphertext`, `private_key_iv`, `private_key_auth_tag`).
- **Anonimización:** Las direcciones IP se transforman en `HMAC-SHA256(ip, IP_ANON_SALT)` antes de persistirse o mostrarse en la Consola Admin.
- **Anti-Replay + Anti-DDoS:**
  - Capa 1 (borde HTTP): `@fastify/rate-limit` por IP anonimizada + ventana deslizante en memoria (<2 ms).
  - Capa 2 (dominio/aplicación): `ReplayGuardPort` bloquea cualquier `(enrollmentId, timeStep)` ya consumido durante `stepSeconds * (driftWindow + 2)` segundos.
  - Capa 3 (bloqueo progresivo + IA local): `LocalAnomalyAdapter` evalúa velocidad de fallos, dispersión de IPs/cuentas y deriva temporal, elevando `riskScore` (0–100) y aplicando bloqueo adaptativo temporal sin telemetría externa.

---

## 2. Diagrama de Flujo Principal (Enrolamiento, Verificación e Integración Reto 1)

```text
[Cliente PWA Soberano] <---(QR / otpauth://)--- [POST /api/v1/enroll] <--- [Portal Demo / Reto 1]
         |                                                |
   (Código 6/8 dig                                 (Semilla CSPRNG ->
    HMAC-SHA256/512)                                AES-256-GCM -> SQLite)
         |
         v
[Portal Demo / Reto 1] ---(POST /api/v1/verify)---> [Fastify TLS 1.3 + RateLimit + OWASP]
                                                            |
                                          1) LocalAnomalyAdapter (riesgo <15ms)
                                          2) ReplayGuardPort (anti-replay)
                                          3) TotpGenerator (RFC 6238 + time-drift)
                                          4) NodeCryptoVault (firma JWT Ed25519)
                                                            |
                                                            v
[Portal Demo / Reto 1] <---(mfaToken JWT + riskScore + driftSteps)--- [Respuesta 200]
         |
         +---(Verifica JWT offline vía GET /.well-known/jwks.json o POST /api/v1/token/validate)
```

---

## 3. Corte Quirúrgico: MVP (29h) vs. Producción

| Capacidad | MVP Hackathon (29h — Implementado) | Producción (Documentado) |
| :--- | :--- | :--- |
| **Motor TOTP** | RFC 6238 puro (`HMAC-SHA256`, `HMAC-SHA512`, `HMAC-SHA1` opcional), CSPRNG 256 bits, ventana *time-drift* configurable, `timingSafeEqual`. | HSM físico (PKCS#11) + WebAuthn/FIDO2 complementario. |
| **Criptografía & BD** | SQLite WAL + AES-256-GCM por campo sensible + Ed25519 JWT/JWKS + rotación `kid` + TLS 1.2/1.3 local. | PostgreSQL con TDE + KMS institucional (HashiCorp Vault) + Redis Cluster para anti-replay multi-nodo. |
| **IA Local (10%)** | Detector local en memoria (`LocalAnomalyAdapter`: scoring conductual + Z-Score/entropía de ráfagas distribuidas + explicación + bloqueo adaptativo). | Reentrenamiento periódico offline con histórico SIEM. |
| **Clientes & UI** | Consola Admin (políticas, revocación, rotación de llaves, alertas IA, auditoría anonimizada) + Cliente PWA Soberano (QR + generador offline) + Portal Demo. | Apps móviles nativas compiladas (Android/iOS) con enclave seguro. |
| **Integración & QA** | `sdk/` conectado a Reto 1 + simulador de ataques en vivo (replay, fuerza bruta, drift) + **SBOM CycloneDX/npm**. | Pipeline CI/CD institucional con escaneo SAST/DAST automatizado. |

---

## 4. Propiedad Estricta de Carpetas (Sub-Equipo de 3)

| Carpeta | Dueño | Rama | Regla |
| :--- | :--- | :--- | :--- |
| Raíz (`*.md`, `.env.example`, `.gitignore`), `contracts/`, `sdk/`, `qa/` | **J Laya (Lead/QA)** | `feat/lead-*` | Única fuente de contratos y auditoría. |
| `backend/` | **Compañero 2 (Backend/Cripto/IA)** | `feat/backend-*` | Debe cumplir `contracts/openapi.yaml` y `contracts/schema.sql` al 100%. |
| `frontend/` | **Compañero 3 (Frontend/PWA)** | `feat/frontend-*` | Arranca con `contracts/mocks/` y luego conecta al backend real. |
| `docs/reto/` | Solo lectura | — | No modificar. |

---

## 5. Comandos Estándar de Arranque y Smoke-Test (Objetivo Fase 2)

```bash
# 1. Backend (desde backend/)
cp ../.env.example .env
npm install
npm run dev              # Levanta API HTTPS/TLS en https://localhost:8443
npm test                 # Tests unitarios RFC 6238, AES-256-GCM, Ed25519, Anti-Replay e IA local
npm sbom --sbom-format=cyclonedx > ../qa/sbom-backend.json

# 2. Frontend (desde frontend/)
npm install
npm run dev              # Levanta Consola Admin + Cliente PWA + Portal Demo

# 3. Smoke-Test rápido (desde raíz)
curl -k https://localhost:8443/health
curl -k https://localhost:8443/.well-known/jwks.json
```
