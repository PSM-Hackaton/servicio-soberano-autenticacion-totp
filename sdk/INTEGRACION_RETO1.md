# Guía de Integración para el Sub-Equipo del Reto 1 (Agente Evaluador de Propuestas)

El **Servicio Soberano de Autenticación TOTP** se integra con el **Reto 1** como una aplicación cliente más en la tabla `apps` (cero acoplamiento de bases de datos, cero dependencias npm, 100% Node.js 22 nativo).

---

## 1. Requisitos previos

- Node.js **22+** (no requiere `npm install`: el SDK usa exclusivamente `fetch` y `node:crypto`).
- Credenciales de aplicación emitidas desde la consola administrativa o script `seed`:
  - `TOTP_API_URL=https://localhost:8443`
  - `TOTP_CLIENT_ID=reto1-evaluador`
  - `TOTP_CLIENT_SECRET=<secreto_entregado_una_sola_vez>`

> Si el backend usa certificado HTTPS local autofirmado en pruebas de red LAN, exportar `NODE_EXTRA_CA_CERTS=./backend/certs/localhost.crt` (nunca desactivar TLS en producción).

---

## 2. Inicializar el SDK (3 líneas)

```js
import { createTotpClient } from '../sdk/index.js';

export const totpSdk = createTotpClient({
  baseUrl: process.env.TOTP_API_URL || 'https://localhost:8443',
  clientId: process.env.TOTP_CLIENT_ID || 'reto1-evaluador',
  clientSecret: process.env.TOTP_CLIENT_SECRET,
  issuer: 'https://totp.soberano.local',
  audience: 'reto1-evaluador',
  timeoutMs: 3000,   // Fail-closed rápido (3 s)
  maxRetries: 1,     // 1 reintento automático con la misma Idempotency-Key
});
```

---

## 3. Flujo de 4 llamadas

### Paso A — Enrolar evaluador (`POST /api/v1/enrollments`)
```js
const enrollment = await totpSdk.enroll({
  userRef: evaluador.id,              // Se anonimiza con HMAC-SHA256 + pepper en servidor
  accountLabel: evaluador.alias,      // Solo visible en QR/PWA
  algorithm: 'SHA512',                // Política recomendada de alta seguridad
  digits: 8,
  period: 30,
});
// Mostrar al usuario: enrollment.qr_svg y enrollment.otpauth_uri (Plan B manual)
```

### Paso B — Activar factor y entregar códigos de recuperación (`POST /api/v1/enrollments/{id}/activate`)
```js
const activated = await totpSdk.activate(enrollment.enrollment_id, codigoIngresado);
// Mostrar UNA SOLA VEZ: activated.recovery_codes (10 códigos de un solo uso)
```

### Paso C — Verificar código TOTP al iniciar sesión o aprobar propuesta (`POST /api/v1/verify`)
```js
import { TotpServiceError } from '../sdk/index.js';

try {
  const result = await totpSdk.verify({
    userRef: evaluador.id,
    code: codigoTotp,
  });
  // result.verified === true
  // result.token -> JWT Ed25519 (TTL 5 min, amr: ['otp'], jti único)
} catch (err) {
  if (err instanceof TotpServiceError && err.status === 503) {
    // Regla fail-closed: jamás conceder acceso si MFA no responde
    return { status: 503, message: 'Servicio MFA temporalmente no disponible. Intente de nuevo.' };
  }
  return { status: 401, message: 'No se pudo completar la verificación.' };
}
```

### Paso D — Validar el comprobante JWT (en línea o **sin red con caché JWKS**)
```js
// Opción 1: Validación en línea con consumo atómico de jti (un solo uso)
const online = await totpSdk.validateToken(token, { consumeJti: true });

// Opción 2: Validación offline rápida (<1 ms) con caché JWKS Ed25519 (resiste cortes de red)
const offline = await totpSdk.verifyJwtOffline(token);
if (!offline.valid) throw new Error(`JWT inválido: ${offline.reason}`);
```

---

## 4. Política Fail-Closed y Resiliencia

1. **Si `/api/v1/verify` responde `503` o excede `3000 ms`**, el SDK reintenta **una sola vez** con la misma cabecera `Idempotency-Key`. Si persiste el fallo, lanza `TotpServiceError` y el Reto 1 **debe denegar el acceso**.
2. **Los JWT ya emitidos** se siguen validando localmente con `verifyJwtOffline(token)` usando el caché de `/.well-known/jwks.json`, incluso si se corta momentáneamente la conexión con el servicio TOTP.
