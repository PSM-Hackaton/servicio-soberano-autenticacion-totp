# servicio-soberano-autenticacion-totp

**Reto Grupal 3 — Servicio Soberano de Autenticación Multifactorial basado en Tiempo** · Hackatón 2026 · Equipo PSM-Hackaton

Segundo factor de autenticación (TOTP, RFC 6238) que funciona entero en infraestructura propia. Las semillas se generan y se guardan cifradas en nuestro servidor, el motor criptográfico es código propio y el usuario ve sus códigos en una app autenticadora propia. No depende de Google, Microsoft, Authy ni de ninguna nube externa.

## Documentos

| Documento | Contenido |
|---|---|
| [`docs/analisis/analisis-tecnico.pdf`](docs/analisis/analisis-tecnico.pdf) | Análisis técnico: soberanía, funcionamiento de TOTP, arquitectura, seguridad (modelo de amenazas y controles), API, datos, IA, UX y plan de trabajo |
| [`docs/reto/`](docs/reto/) | Enunciado y términos de referencia oficiales del reto |
| [`SECURITY.md`](SECURITY.md) | Política de seguridad del proyecto |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | Flujo de ramas y reglas para contribuir |

## Componentes

- **Motor criptográfico TOTP propio**: HMAC-SHA256 y HMAC-SHA512, semillas CSPRNG, ventanas configurables, compensación de deriva y anti replay.
- **API de integración y SDK**: enrolamiento, verificación y validación de JWT firmados con Ed25519 (JWKS).
- **App autenticadora propia**: PWA instalable desde el servidor de la institución, funciona sin conexión y está protegida con PIN.
- **Seguridad y heurística local**: bloqueos progresivos, límites de tasa, anti-DDoS y detección de anomalías sin telemetría.
- **Almacenamiento cifrado y consola**: AES-256-GCM en reposo, TLS 1.3, metadatos anonimizados, RBAC, rotación de llaves y bitácora encadenada por hashes.

## Estructura prevista

```
backend/                API Fastify + TypeScript (motor TOTP, vault, tokens, seguridad, auditoría)
authenticator-app/      PWA autenticadora
admin-console/          Consola administrativa
sdk/                    SDK para sistemas integradores
demo-portal-tramites/   Sistema institucional de ejemplo
attack-lab/             Ataques simulados para la demo
deploy/                 docker-compose y Caddy (TLS 1.3)
docs/                   Reto, análisis y documentación
```

## Stack

Node.js 22 · TypeScript · Fastify · PostgreSQL 16 · React + Vite · Caddy · Docker Compose
