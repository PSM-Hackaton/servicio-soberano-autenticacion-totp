# Guía de Integración para el Sub-Equipo del Reto 1 (Agente Evaluador de Propuestas)

El **Servicio Soberano de Autenticación TOTP** se integra con el **Reto 1** como una aplicación cliente más en la tabla `apps` (cero acoplamiento de bases de datos, cero dependencias npm, 100 % Node.js 22 nativo).

---

## 1. Requisitos previos y credenciales

- **Node.js 22.5+** (sin `npm install`: `sdk/src/index.js` usa solo `node:https`, `node:http` y `node:crypto`).
- Al ejecutar `cd backend && npm run seed`, el servicio crea automáticamente la aplicación **`Reto 1`** e imprime **una sola vez** su `client_id` y `client_secret`.
- Variables recomendadas en el proyecto del Reto 1:
  - `TOTP_BASE_URL=https://localhost:8443`
  - `TOTP_CLIENT_ID=<client_id impreso por npm run seed>`
  - `TOTP_CLIENT_SECRET=<client_secret impreso por npm run seed>`
  - `TOTP_CA_PATH=../backend/certs/ca.crt` (CA local generada por `npm run certs` o CA institucional en producción)

---

## 2. Inicializar el SDK (sin dependencias)

```js
import { readFileSync } from 'node:fs';
import { crearClienteTotp, ErrorTotp } from './sdk/src/index.js';

export const totp = crearClienteTotp({
  baseUrl: process.env.TOTP_BASE_URL || 'https://localhost:8443',
  clientId: process.env.TOTP_CLIENT_ID,
  clientSecret: process.env.TOTP_CLIENT_SECRET,
  ca: readFileSync(process.env.TOTP_CA_PATH || 'backend/certs/ca.crt'),
  issuer: 'https://totp.soberano.local', // claim iss esperado (aud = clientId por defecto)
  timeoutMs: 3000,                       // fallo cerrado rápido (3 s)
  reintentos: 1,                         // 1 reintento automático con la misma Idempotency-Key
});
```

---

## 3. Flujo de 4 llamadas

### Paso A — Enrolar evaluador (`POST /api/v1/enrollments`)
```js
const enr = await totp.enrolar(evaluador.idOpaco, {
  etiquetaCuenta: evaluador.alias, // visible solo en QR / PWA
  algoritmo: 'SHA512',             // política de alta seguridad
  digitos: 8,
  periodo: 30,
});
// Mostrar al usuario:
// - enr.qrSvg (renderizar como <img src="data:image/svg+xml;base64,...">, nunca SVG inline sin sanitizar)
// - enr.claveManual y enr.otpauthUri (Plan B / enlace directo al Autenticador Soberano)
```

### Paso B — Activar factor y entregar 10 códigos de recuperación (`POST /api/v1/enrollments/{id}/activate`)
```js
const act = await totp.activar(enr.enrollmentId, codigoIngresado, { clientIp: req.ip });
// act.estado === 'activo'
// Mostrar UNA SOLA VEZ: act.codigosRecuperacion (10 códigos de un solo uso)
```

### Paso C — Verificar código TOTP al iniciar sesión o aprobar propuestas (`POST /api/v1/verify`)
```js
try {
  const { token, jti, kid, riesgo } = await totp.verificar(evaluador.idOpaco, codigoTotp, {
    clientIp: req.ip, // IP del ciudadano/evaluador (se anonimiza con HMAC + pepper diario)
  });

  // Paso D1: Validación local Ed25519 sin red (caché JWKS con soporte de rotación de kid)
  const local = await totp.verificarTokenLocal(token);
  if (!local.valido) throw new Error(`JWT rechazado localmente: ${local.motivo}`);

  // Paso D2: Validación en línea con consumo atómico de jti (un solo uso)
  const remoto = await totp.validarToken(token, { consumirJti: true });
  if (!remoto.valido) throw new Error(`JWT rechazado por el servidor: ${remoto.motivo}`);

  return { ok: true, sub: local.claims.sub, amr: local.claims.amr, riesgo };
} catch (err) {
  if (err instanceof ErrorTotp && err.bloqueado) {
    return { status: 429, retryAfter: err.reintentarEn, message: 'Demasiados intentos. Intente más tarde.' };
  }
  if (err instanceof ErrorTotp && err.servicioNoDisponible) {
    // Regla fail-closed: jamás conceder acceso si el servicio MFA no responde
    return { status: 503, message: 'Servicio MFA temporalmente no disponible. Intente de nuevo.' };
  }
  return { status: 401, message: 'No se pudo completar la verificación.' };
}
```

---

## 4. Pruebas locales sin levantar el backend completo

El SDK incluye un servicio falso con TOTP y JWT Ed25519 reales para que el equipo del Reto 1 pruebe su integración de inmediato:

```bash
node sdk/testing/servicio-falso.js --puerto 8099
# Apuntar TOTP_BASE_URL=http://127.0.0.1:8099 y ejecutar las pruebas del Reto 1
```
