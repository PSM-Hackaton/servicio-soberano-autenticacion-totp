# FASE 0 — Auditoría de Problemática y Factibilidad Real

- **Reto:** Servicio Soberano de Autenticación Multifactorial basado en Tiempo (TOTP)
- **Repositorio GitHub:** `https://github.com/PSM-Hackaton/servicio-soberano-autenticacion-totp`
- **Sub-equipo:** 3 personas (J Laya Lead/Arquitecto/QA + Compañero 2 Backend/Cripto/IA + Compañero 3 Frontend/PWA)
- **Integración objetivo:** Standalone (Reto 2) + Conector MFA/JWT vía SDK para el sub-equipo del Reto 1 (*Agente Evaluador de Propuestas de Servicios*)
- **Fecha:** 2026-11-26

---

## 1. Radiografía del Reto y Validación del Esqueleto de Referencia

### Qué exige el enunciado oficial (`docs/reto/`)
1. **Motor Criptográfico TOTP (RFC 6238):** Semillas CSPRNG, `HMAC-SHA256` y `HMAC-SHA512`, ventanas configurables, compensación de *time-drift*, comparación en tiempo constante.
2. **Soberanía y Cifrado:** 100% local/nacional (\$0 en APIs o nubes extranjeras), AES-256-GCM en reposo, TLS 1.2/1.3 en tránsito, anonimización de metadatos (IPs hasheadas).
3. **Resiliencia e IA Local (10% del puntaje):** Anti-replay en ventana activa, rate limiting, bloqueos progresivos anti-fuerza bruta/DDoS, cumplimiento OWASP Top 10 y análisis heurístico/conductual **local** (sin telemetría externa) para anomalías y ataques distribuidos.
4. **APIs, Cliente QR y Consola Admin:** Enrolamiento QR (`otpauth://`), verificación TOTP, JWT asimétrico local (`Ed25519` + `/.well-known/jwks.json`), rotación de claves, revocación, políticas, auditoría anonimizada y SBOM.

### Auditoría del esqueleto de referencia (`Gemini Nueva conversación.txt`)
- **Qué SÍ nos sirve y adoptamos 100%:**
  - **Arquitectura Hexagonal (Ports & Adapters)** (`domain/`, `application/ports/{in,out}`, `application/use-cases/`, `infrastructure/adapters/`).
  - **Node.js 22 + TypeScript** como lenguaje unificado de backend, frontend y SDK.
  - **Ejecución paralela en 3 carriles** usando contratos OpenAPI + SQL + `MockAdapter` desde la Hora 1.
  - **Enfoque híbrido:** núcleo determinista (RFC 6238 + cripto) + módulo IA local explicable.
- **Qué descartamos por no aplicar al reto:**
  - Las tablas de gestión de proyectos (`projects`, `risk_factors_config`, `risk_evaluations`) porque pertenecían a otro problema.
  - Proveedores externos (OpenAI/Gemini API), ya que el Reto 2 prohíbe telemetría hacia nubes extranjeras.
  - PostgreSQL local (la PC del evento no tiene Docker; usamos SQLite WAL + AES-256-GCM con puerto hexagonal intercambiable a PostgreSQL en producción).

---

## 2. Prueba de Estrés Real (Defensa ante Jurado)

- **Concurrencia / Anti-DDoS (500+ req/s en `/verify`):** Rate limiter en memoria (<2 ms, HTTP `429`) + caché anti-replay en memoria con TTL respaldada por SQLite en modo WAL + bloqueo progresivo exponencial por cuenta.
- **Sostenibilidad económica:** **\$0 operativo**, 100% FOSS, sin SMS, sin APIs pagas, sin GPU.
- **Hardware y red reales:** Ubuntu 12 cores / 14 GB RAM / **sin Docker** / **sin GPU** / Node 22 nativo; funciona incluso en red LAN sin internet.
- **Plan B de demo en vivo:** Cliente Autenticador PWA embebido (cero dependencia de teléfonos/red externa) + script `qa/attack-simulator` que reproduce en vivo ante el jurado: (1) enrolamiento + login normal, (2) *replay attack* rechazado, (3) *time-drift* ±30s compensado, (4) ráfaga de fuerza bruta distribuida detectada/bloqueada por la IA local, y (5) validación offline de JWT vía JWKS.

---

## 3. Arquitectura Seleccionada

**Opción A (Aprobada como base estructural):** Monolito Hexagonal en **Node.js 22 + TypeScript + Fastify + `node:crypto` + `jose` + SQLite WAL (AES-256-GCM) + React/Vite**.
*(Detalle completo, ADR y comandos en [ARCHITECTURE.md](./ARCHITECTURE.md)).*

---

## 4. Cronograma Real (Jue 26 → Vie 27) y Política de Remotos

- **Política de Remotos (Orden de J Laya):** Todos los pushes y PRs de desarrollo van **EXCLUSIVAMENTE a GitHub (`origin`)**. **GitLab permanece BLOQUEADO** hasta la orden literal **`/push gitlab final`**. Nunca tocar `main`.
- **H0–H2 (Jue mediodía):** Contratos congelados (`contracts/`), guía `AGENTS.md`, prompts de equipo y entrega del contrato/SDK al sub-equipo de Reto 1.
- **H2–H10 (Jue tarde):** Sprint 1 paralelo — Dominio RFC 6238 + AES-256-GCM + SQLite + `/enroll`/`/verify`/JWKS | Frontend PWA + Enrolamiento QR | QA tests unitarios + SDK.
- **H10–H24 (Vie mañana):** Sprint 2 paralelo — Anti-replay + Rate Limit + IA Local + Rotación llaves + TLS | Consola Admin + Alertas IA + Portal Demo | Integración viva con Reto 1 + Simulador de ataques + SBOM.
- **H24–H29 (Vie tarde):** **Code Freeze**, verificación OWASP/SBOM, `README.md` final (6 apartados), ensayo de pitch y (solo tras orden explícita `/push gitlab final`) entrega final en GitLab.
