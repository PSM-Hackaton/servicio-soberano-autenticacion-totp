# SDK del Servicio Soberano de Autenticación TOTP

Paquete ESM **sin dependencias** (solo `node:https`, `node:http` y `node:crypto`, Node 22+) para que cualquier sistema institucional integre el segundo factor.

```js
import { readFileSync } from 'node:fs';
import { crearClienteTotp, ErrorTotp } from './sdk/src/index.js';

const totp = crearClienteTotp({
  baseUrl: 'https://localhost:8443',
  clientId: process.env.TOTP_CLIENT_ID,
  clientSecret: process.env.TOTP_CLIENT_SECRET,
  ca: readFileSync('backend/certs/ca.crt'),   // CA local del servicio (PEM)
  issuer: 'https://totp.soberano.local',      // iss esperado en el JWT (aud = clientId por defecto)
  timeoutMs: 3000,
  reintentos: 1,
});

try {
  const { token } = await totp.verificar(userRef, codigo);       // lanza si no se aprueba
  const local = await totp.verificarTokenLocal(token);            // firma EdDSA offline
  const remoto = await totp.validarToken(token);                  // consume el jti
  if (!local.valido || !remoto.valido) throw new Error('denegado');
  // ... crear sesión
} catch (e) {
  if (e instanceof ErrorTotp && e.bloqueado) { /* 429: e.reintentarEn segundos */ }
  else if (e instanceof ErrorTotp && e.servicioNoDisponible) { /* red / tiempo agotado / 503 */ }
  // en cualquier caso: NO hay acceso
}
```

## API

| Método | Endpoint | Devuelve |
| --- | --- | --- |
| `enrolar(userRef, { etiquetaCuenta?, algoritmo?, digitos?, periodo? })` | `POST /api/v1/enrollments` | `{ enrollmentId, otpauthUri, qrSvg, claveManual, expiraEn, … }` |
| `activar(enrollmentId, codigo)` | `POST /api/v1/enrollments/{id}/activate` | `{ estado: 'activo', codigosRecuperacion[10] }` |
| `verificar(userRef, codigo, { idempotencyKey? })` | `POST /api/v1/verify` | `{ aprobado: true, token, jti, kid, expiraEn, derivaPasos, riesgo }` |
| `validarToken(token, { consumirJti = true })` | `POST /api/v1/tokens/validate` | `{ valido, sub, aud, jti, kid, amr, exp, motivo }` |
| `resincronizar(enrollmentId, codigo1, codigo2)` | `POST /api/v1/enrollments/{id}/resync` | `{ resincronizado, derivaPasos }` |
| `recuperar(userRef, codigoRecuperacion)` | `POST /api/v1/recovery` | `{ recuperado, debeReenrolar, codigosRestantes }` |
| `revocar(enrollmentId)` | `DELETE /api/v1/enrollments/{id}` | `{ estado: 'revocado', revocadoEn }` |
| `jwks()` / `salud()` | `/.well-known/jwks.json` / `/health` | respuesta del servicio |
| `verificarTokenLocal(token)` | — (sin red) | `{ valido, header, claims }` o `{ valido: false, motivo }` |

Exportaciones sueltas: `verificarTokenLocal(token, { jwks, issuer, audience })` (acepta un JWKS o una caché), `crearCacheJwks({ obtener, ttlMs })`, `decodificarSinVerificar(token)` (solo para mostrar), `ErrorTotp`, `CODIGOS_LOCALES`.

## Garantías

- **Falla cerrado.** Solo una respuesta 2xx que cumple el contrato (`verified === true` estricto, token con forma JWT) aprueba; todo lo demás lanza `ErrorTotp`. `verificarTokenLocal` nunca lanza: devuelve `valido: false`.
- **Tiempo de espera total** por intento (conexión + TLS + respuesta), 3 s por defecto.
- **Un reintento** solo ante error de red, tiempo agotado o 503, con la **misma `Idempotency-Key`** (se genera si no se pasa). El servicio devuelve la misma respuesta sin volver a evaluar el código, así una respuesta perdida no se convierte en un falso "replay".
- **Errores tipados:** `ErrorTotp { status, codigo, reintentarEn, operacion }` con atajos `rechazado` (401), `bloqueado` (429) y `servicioNoDisponible`.
- **Validación offline:** caché JWKS con TTL de 10 min, refresco inmediato ante un `kid` desconocido (rotación; con freno de 30 s contra kids inventados) y uso de la copia vencida si el servicio no responde. Solo acepta `alg: EdDSA`, exige `iss`, `aud`, `exp`/`nbf`, `amr` con `otp`, `sub` y `jti`.
- **Nunca registra secretos:** el `clientSecret` no aparece en `console.log(cliente)`, `JSON.stringify`, errores ni trazas (`alTrazar` recibe método, ruta, estado, ms e intento).
- HTTP sin TLS solo se admite contra `localhost` (pruebas).

## Pruebas y servicio falso

```bash
node --test sdk/tests/sdk.test.js
node sdk/testing/servicio-falso.js --puerto 8099   # servicio TOTP falso para integrar sin backend
```

`sdk/testing/servicio-falso.js` simula el contrato con TOTP y JWT EdDSA reales, anti-replay, bloqueo, idempotencia y fallos inyectables (503, lentitud, cortes, token alterado). Solo para pruebas.
