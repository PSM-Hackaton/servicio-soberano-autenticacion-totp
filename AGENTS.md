# AGENTS.md — Guía Maestra al Unísono (`servicio-soberano-autenticacion-totp`)

> **LECTURA OBLIGATORIA:** Todo agente de IA (de J Laya o de cualquiera de los compañeros del equipo, sin importar el modelo o IDE) **DEBE leer este archivo, `ARCHITECTURE.md`, `SYSTEM_GRAPH.md`, `contracts/` y `TASKS.md` antes de crear, modificar o proponer cualquier código.**

---

## 1. Contexto Oficial del Proyecto

- **Repositorio de trabajo (GitHub):** `https://github.com/PSM-Hackaton/servicio-soberano-autenticacion-totp`
- **Evento:** Hackatón Venezuela INNOVA 2026 (26–27 de noviembre de 2026).
- **Reto oficial:** **Servicio Soberano de Autenticación Multifactorial basado en Tiempo (TOTP)** *(ver `docs/reto/AutenticaciónMultifactorial_TerminosEspecificaciones.pdf`)*.
- **Sub-equipo asignado (3 personas):** J Laya (Tech Lead / Arquitecto / QA & Integración) + Compañero 2 (Backend / Criptografía / IA Local) + Compañero 3 (Frontend / PWA / Consola).
- **Integración estratégica con Reto 1:** Otro sub-equipo desarrolla el **Reto 1 (Agente Evaluador de Propuestas de Servicios)**. Nuestro servicio TOTP debe operar:
  1. **100% autónomo (standalone)** para la defensa de 100 pts del Reto 2.
  2. **Integrable vía API REST + JWKS (`/.well-known/jwks.json`)** como factor MFA obligatorio en el login del Reto 1 mediante nuestro `sdk/`, sin compartir base de datos ni acoplar código interno.
- **Soberanía y costo operativo:** **\$0 en APIs externas**, **100% local / offline-capable**, cero dependencias de Google Authenticator Cloud, Auth0, Cloudflare u otros servicios privativos.
- **Entorno real verificado del nodo:** Ubuntu, 12 cores CPU, 14 GiB RAM, **sin GPU**, **sin Docker**. Disponibles: `Node.js 22`, `npm`, `Python 3.14`, `uv`, `git`.

---

## 2. Reglas Inquebrantables de Git, GitHub y GitLab

1. **PROHIBIDO tocar `main`:** Nunca hagas `commit` ni `push` directo a `main`.
2. **POLÍTICA DE REMOTOS (ORDEN ESTRICTA DE J LAYA):**
   - **GitHub (`origin`):** **EXCLUSIVO para todas las subidas, PRs y trabajo en equipo.**
   - **GitLab (`gitlab`):** **BLOQUEADO.** Prohibido ejecutar cualquier `git push` hacia GitLab hasta que J Laya dé la orden literal **`/push gitlab final`**.
3. **Flujo de ramas en GitHub:**
   - Cada integrante trabaja únicamente en su rama `feat/<rol>-<modulo>` (ej. `feat/lead-arquitectura-totp`, `feat/backend-totp-core`, `feat/frontend-console-pwa`).
   - Integración en GitHub: Pull Request hacia `avance` (revisado por J Laya).
   - Solo al recibir `/push gitlab final`, el Lead sincroniza hacia el GitLab oficial (`avance` y `terminado`) con el `README.md` obligatorio de 6 apartados.
4. **Propiedad estricta de carpetas:** Nadie edita carpetas ajenas sin visto bueno del Lead.
5. **Contratos congelados (`contracts/`):** Son la única fuente de verdad. Prohibido inventar campos, renombrar rutas o cambiar DTOs sin actualizar `contracts/openapi.yaml`, `contracts/schema.sql` y `SYSTEM_GRAPH.md`.
6. **Cero secretos en Git:** Nunca commitear `.env`, `*.pem`, `*.key`, `*.crt`, `*.db`, llaves AES ni tokens reales.
7. **Protocolo Graphy (`SYSTEM_GRAPH.md`):** Leer antes de programar; dar de alta nuevos nodos y podar nodos obsoletos en cada avance fuerte.

---

## 3. Rúbrica Oficial de Evaluación (100 pts — Jurado)

| Dimensión | Peso | Requisito para puntaje máximo |
| :--- | :---: | :--- |
| **1. Ejecución Técnica y Funcionalidad** | **25%** | Motor RFC 6238 propio (CSPRNG + `HMAC-SHA256`/`HMAC-SHA512` + *time-drift*), enrolamiento QR, verificación + JWT asimétrico Ed25519 + integración viva con Portal Demo y Reto 1. |
| **2. Buenas Prácticas, Limpieza y Seguridad** | **15%** | Arquitectura Hexagonal pura, AES-256-GCM en reposo, TLS 1.2/1.3 en tránsito, anti-replay estricto, rate limiting/anti-DDoS, OWASP Top 10, anonimización de IP/metadatos y **SBOM** sin vulnerabilidades críticas. |
| **3. Impacto y Viabilidad** | **15%** | 100% soberano, \$0 operativo, corre sin internet ni GPU, SDK integrable en 5 minutos en cualquier portal institucional o en Reto 1. |
| **4. Diseño y UX/UI** | **15%** | Consola Admin (políticas, revocación, rotación de llaves, alertas IA, auditoría) + Cliente Autenticador PWA soberano (QR + temporizador 30s) + Portal Institucional Demo. |
| **5. Uso e Integración de IA** | **10%** | Motor local de detección de anomalías (<15 ms, 0 telemetría externa) para detectar fuerza bruta distribuida y patrones sospechosos con explicabilidad y bloqueo adaptativo. |
| **6. Innovación y Creatividad** | **10%** | Simulador de ataques en vivo (Replay + Fuerza Bruta + *Time-Drift*) y puente MFA/JWKS con Reto 1. |
| **7. Presentación** | **10%** | Demo fluida reproducible en 1 comando y `README.md` completo (6 apartados oficiales). |

---

## 4. Estructura Hexagonal Oficial y Propiedad de Carpetas

Basada en el esqueleto **Hexagonal (Ports & Adapters)** del equipo en **Node.js 22 + TypeScript**:

```text
servicio-soberano-autenticacion-totp/
├── AGENTS.md                        # [LEAD] Guía maestra al unísono para todos los agentes
├── ARCHITECTURE.md                  # [LEAD] ADR, diseño hexagonal, stack y comandos
├── ANALISIS_FASE0.md                # [LEAD] Auditoría Fase 0, prueba de estrés y corte 29h
├── SYSTEM_GRAPH.md                  # [LEAD] Grafo vivo de dependencias (Protocolo Graphy)
├── CONTRIBUTING.md                  # [LEAD] Reglas GitHub, bloqueo GitLab y Code Freeze
├── TASKS.md                         # [LEAD] Pizarrón vivo de tareas verificadas
├── .env.example                     # [LEAD] Variables de entorno sin secretos
├── contracts/                       # [LEAD] Contratos congelados (OpenAPI, SQL, JSON mocks)
│   ├── openapi.yaml
│   ├── schema.sql
│   └── mocks/
├── backend/                         # [COMPAÑERO 2 — BACKEND, CRIPTO E IA LOCAL]
│   └── src/
│       ├── domain/                  # NÚCLEO PURO (0 dependencias de frameworks/HTTP/DB)
│       │   ├── entities/            # UserEnrollment, TotpPolicy, SigningKey, AuditEvent, AnomalyAssessment
│       │   ├── value-objects/       # TotpAlgorithm, EncryptedPayload, AnonymizedIp, RiskLevel
│       │   └── services/            # TotpGenerator (RFC 6238), TimeDriftCalculator
│       ├── application/             # CASOS DE USO Y PUERTOS (Contratos internos)
│       │   ├── ports/in/            # EnrollUserUseCase, VerifyTotpUseCase, ValidateTokenUseCase, AdminGovernanceUseCase
│       │   ├── ports/out/           # EnrollmentRepositoryPort, PolicyRepositoryPort, CryptoVaultPort, ReplayGuardPort, AnomalyDetectorPort, AuditRepositoryPort
│       │   └── use-cases/           # EnrollUserService, VerifyTotpService, ValidateTokenService, AdminGovernanceService
│       └── infrastructure/          # ADAPTADORES INTERCAMBIABLES
│           ├── adapters/in/http/    # Fastify REST, RBAC Admin, Rate Limit, Anti-DDoS, Cabeceras OWASP
│           ├── adapters/out/persistence/ # SQLite WAL (intercambiable por Postgres en prod sin tocar dominio)
│           ├── adapters/out/crypto/ # NodeCryptoVaultAdapter (CSPRNG, AES-256-GCM, Ed25519 JWT/JWKS, HMAC IP)
│           ├── adapters/out/ai/     # LocalAnomalyAdapter + MockAnomalyAdapter (desarrollo paralelo)
│           └── config/              # DependencyInjection.ts + TlsConfig.ts
├── frontend/                        # [COMPAÑERO 3 — FRONTEND & UX]
│   ├── console/                     # Consola Administrativa (políticas, revocación, rotación llaves, alertas IA, auditoría)
│   ├── authenticator-pwa/           # Cliente Autenticador PWA Soberano (QR + generador TOTP offline 30s)
│   └── demo-portal/                 # Mini Portal Institucional Demo (login + MFA + inspector JWT)
├── sdk/                             # [LEAD / INTEGRACIÓN RETO 1] SDK TS/JS para validar MFA + JWKS offline
├── qa/                              # [LEAD / QA] Tests RFC 6238, OWASP, simulador de ataques y SBOM
└── docs/reto/                       # Material oficial del hackatón (solo lectura)
```

---

## 5. Invariantes de Ciberseguridad (Obligatorias)

1. **TOTP RFC 6238:** Semillas ≥256 bits vía `crypto.randomBytes` (CSPRNG); soporte obligatorio de `HMAC-SHA256` y `HMAC-SHA512` (más `HMAC-SHA1` opcional solo para compatibilidad); ventana de *time-drift* configurable (±1 paso por defecto) con comparación en tiempo constante (`crypto.timingSafeEqual`).
2. **Anti-Replay:** Bloqueo inmediato de `(enrollment_id, time_step)` ya validado dentro de su ventana activa (en memoria + tabla `replay_guard`).
3. **Cifrado en Reposo (AES-256-GCM):** Semillas TOTP y claves privadas Ed25519 se cifran con AES-256-GCM (IV aleatorio de 12 bytes + *auth tag* de 16 bytes) antes de persistirse.
4. **Cifrado en Tránsito (TLS 1.2/1.3):** Fastify sobre HTTPS con certificado TLS local (generado por script de bootstrap y excluido de Git).
5. **JWT Asimétrico + JWKS:** Firma con `Ed25519` (`EdDSA`), `kid` rotativo, TTL corto (ej. 300s), `jti` único; clave pública publicada en `GET /.well-known/jwks.json`.
6. **Anonimización:** IPs almacenadas únicamente como `HMAC-SHA256(ip, IP_ANON_SALT)`.
7. **OWASP & Anti-DDoS:** Validación JSON estricta (Fastify/Ajv o Zod), cabeceras seguras (`Helmet`), *rate limiting* en memoria (<2 ms), bloqueo progresivo exponencial y **SBOM** (`npm sbom` / CycloneDX).
8. **IA Local sin Telemetría:** `LocalAnomalyAdapter` calcula riesgo conductual 100% en local (velocidad, tasa de fallos, dispersión de cuentas/IPs anonimizadas, *time-drift* anómalo) sin llamar a ninguna API externa.

---

## 6. Protocolo de Entrega de Cualquier Agente

Al cerrar cada tarea en tu rama `feat/<rol>-<modulo>`:
1. Confirmar que **no** modificaste carpetas ajenas ni hiciste commits en `main`.
2. Adjuntar evidencia real de ejecución (`npm test`, `npm run build`, pruebas HTTP/curl).
3. Actualizar `TASKS.md` (y `SYSTEM_GRAPH.md` si agregaste/podaste interfaces).
4. Subir **únicamente a GitHub (`origin`)**; jamás a GitLab sin `/push gitlab final`.
