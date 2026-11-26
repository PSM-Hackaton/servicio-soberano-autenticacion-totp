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
| `enrolar(userRef, { etiquetaCuenta?, algoritmo?, digitos?, periodo?, dispositivo? })` | `POST /api/v1/enrollments` | `{ enrollmentId, otpauthUri, qrSvg, claveManual, expiraEn, … }`; con `dispositivo: { nombre, plataforma? }` añade `dispositivoId` y `aprovisionamiento { otpauthUri, expiraEn, dispositivoId, huellaCaSha256 }` |
| `activar(enrollmentId, codigo, { clientIp? })` | `POST /api/v1/enrollments/{id}/activate` | `{ estado: 'activo', codigosRecuperacion[10] }` |
| `verificar(userRef, codigo, { idempotencyKey?, clientIp? })` | `POST /api/v1/verify` | `{ aprobado: true, token, jti, kid, expiraEn, derivaPasos, riesgo: { nivel } }` |
| `validarToken(token, { consumirJti = true })` | `POST /api/v1/tokens/validate` | `{ valido, sub, aud, jti, kid, amr, exp, motivo }` |
| `resincronizar(enrollmentId, codigo1, codigo2, { clientIp? })` | `POST /api/v1/enrollments/{id}/resync` | `{ resincronizado, derivaPasos }` |
| `recuperar(userRef, codigoRecuperacion, { clientIp? })` | `POST /api/v1/recovery` | `{ recuperado, debeReenrolar, codigosRestantes }` |
| `revocar(enrollmentId)` | `DELETE /api/v1/enrollments/{id}` | `{ estado: 'revocado', revocadoEn }` |
| `dispositivo(enrollmentId)` | `GET /api/v1/enrollments/{id}/device` | `{ dispositivoId, nombre, plataforma, creadoEn, ultimoUso, desvinculadoEn, estadoEnrolamiento }` |
| `desvincularDispositivo(enrollmentId)` | `DELETE /api/v1/enrollments/{id}/device` | `{ estado: 'revocado', dispositivoId, revocadoEn, desvinculadoEn }` (revoca el enrolamiento) |
| `jwks()` / `salud()` | `/.well-known/jwks.json` / `/health` | respuesta del servicio |
| `verificarTokenLocal(token)` | — (sin red) | `{ valido, header, claims }` o `{ valido: false, motivo }` |

Exportaciones sueltas: `verificarTokenLocal(token, { jwks, issuer, audience })` (acepta un JWKS o una caché), `crearCacheJwks({ obtener, ttlMs })`, `decodificarSinVerificar(token)` (solo para mostrar), `esClientIpValida(ip)`, `ErrorTotp`, `CODIGOS_LOCALES`.

**`clientIp` (muy recomendado):** la IP de SU usuario final, tomada de la conexión con su sistema (dirección del socket; `X-Forwarded-For` solo si hay un proxy propio de confianza). El servicio la usa —como HMAC, nunca en claro— para el detector de anomalías, el registro de intentos y el límite por origen. Sin ella, todos sus usuarios comparten un único origen (la IP de su servidor) y unos pocos fallos pueden frenar a todos. Se valida localmente (IPv4/IPv6; `::ffff:a.b.c.d` se envía como `a.b.c.d`); inválida → `ENTRADA_INVALIDA` sin llamar al servicio.

**Cédula de identidad como `userRef` (opcional):** `normalizarCedula(texto)` acepta `V-12.345.678`, `v12345678`, `E 80.000.003`… y devuelve `{ nacionalidad, numero, canonica, formateada }` o `null` (V o E, 6 a 9 dígitos, sin ceros a la izquierda). Si su app se registró en la consola con `user_ref_desde_cedula: 'hmac'`, derive el `userRef` con `derivarUserRefDesdeCedula(cedula, secretoDerivacion, prefijo)` = `prefijo + base64url(HMAC-SHA256(cédula canónica, secreto))`: la cédula nunca llega al servicio y el soporte puede buscar el factor por cédula desde la consola (el servicio recalcula el mismo valor con el secreto que guarda cifrado). El secreto de derivación se entrega una sola vez al registrar la app; guárdelo con el `client_secret`.

`userRef`: 1 a 128 caracteres imprimibles, sin espacios en los extremos ni caracteres de control, bidi o invisibles (mismo patrón que el servicio). Un código incorrecto, un usuario sin factor y un código ya usado producen el mismo `VERIFICATION_FAILED` (401); el bloqueo progresivo y el del detector, el mismo `TOO_MANY_REQUESTS` (429) con `reintentarEn`: es deliberado (sin oráculos).

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

## Guías relacionadas

- **Integración HTTP paso a paso:** [`docs/api/README.md`](../docs/api/README.md) ([PDF](../docs/api/guia-integracion.pdf))
- **Integración rápida con el SDK para el Reto 3:** [`sdk/INTEGRACION_RETO3.md`](./INTEGRACION_RETO3.md)
