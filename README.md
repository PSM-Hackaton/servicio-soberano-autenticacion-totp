# servicio-soberano-autenticacion-totp

**Reto Grupal — Servicio Soberano de Autenticación Multifactorial basado en Tiempo** (Hackatón 2026)

Servicio independiente de generación y validación de códigos TOTP (RFC 6238) que opera en infraestructura propia, sin depender de servicios de autenticación extranjeros o privativos.

## Componentes
- **Motor criptográfico TOTP y backend**: semillas generadas con CSPRNG, HMAC-SHA256/SHA512, ventanas configurables y compensación de deriva temporal.
- **APIs de integración**: enrolamiento, verificación TOTP y validación de tokens de sesión (JWT con claves asimétricas locales).
- **Cliente y flujo de enrolamiento**: aprovisionamiento por código QR, compatible con clientes estándar.
- **Seguridad y resiliencia**: protección contra replay y fuerza bruta, rate limiting, bloqueos progresivos, anti-DDoS y heurística local de anomalías.
- **Almacenamiento cifrado y consola admin**: AES-256 en reposo, metadatos anonimizados, auditoría, revocación y rotación de claves.

## Estándares
OWASP (sesiones, validación de entradas, endpoints), cifrado en reposo y en tránsito, trazabilidad e inventario de dependencias (SBOM).

## Estructura
```
backend/   API y motor TOTP
frontend/  Cliente de enrolamiento y consola admin
docs/      Documentación técnica y material del reto (docs/reto/)
```
