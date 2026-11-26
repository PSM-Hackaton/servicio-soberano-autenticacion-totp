# Guía de integración para sistemas institucionales

Cómo añadir el segundo factor del **Servicio Soberano TOTP** a un sistema existente (trámites, datos
sensibles, intranets) a nivel HTTP, desde cualquier lenguaje. Quien use Node.js puede ir directo al SDK
(sección 3).

- Contrato completo y fuente de verdad: [`contracts/openapi.yaml`](../../contracts/openapi.yaml) (OpenAPI 3.1).
- Respuestas de ejemplo reales: [`contracts/mocks/`](../../contracts/mocks/).
- SDK JavaScript sin dependencias: [`sdk/README.md`](../../sdk/README.md) y guía del Reto 3: [`sdk/INTEGRACION_RETO3.md`](../../sdk/INTEGRACION_RETO3.md).
- Integración de referencia completa: [`demo-portal-tramites/`](../../demo-portal-tramites/).

Todos los ejemplos de esta guía se obtuvieron el 26-11-2026 contra el servicio real en
`https://localhost:8443` (secretos sustituidos por marcadores y tokens recortados).

---

## 1. Antes de empezar

| Qué necesita | De dónde sale |
| --- | --- |
| URL del servicio | `https://<servidor>:8443` (en desarrollo, `https://localhost:8443`). Solo HTTPS con TLS 1.3. |
| CA que firmó el certificado | En desarrollo, `backend/certs/ca.crt` (`npm run certs`); en producción, la CA institucional. |
| `client_id` y `client_secret` de su aplicación | `npm run seed` crea las apps **"Portal de Trámites"** y **"Agente Evaluador (Reto 3)"** y muestra sus secretos **una sola vez**. Una app nueva se registra con `POST /admin/api/apps` (sesión de administrador). |
| Emisor esperado del JWT (`iss`) | El valor de `JWT_ISSUER` del servicio (por defecto `https://totp.soberano.local`). |
| Audiencia del JWT (`aud`) | Su propio `client_id`. |

El secreto de la app se guarda en el servicio solo como hash scrypt. Guárdelo en el servidor del
sistema integrador (variable de entorno o archivo con permisos mínimos), **nunca** en el navegador ni en
una app móvil: todas las llamadas son **de servidor a servidor**.

### Identificador del usuario (`user_ref`)

Envíe un identificador **opaco y estable** de su usuario (por ejemplo `ptd-d092b2293dad48aad13586dd`), no
su nombre, documento ni correo. El servicio solo guarda `HMAC-SHA256(user_ref, pepper)`; el `sub` del JWT
es ese seudónimo, nunca el `user_ref` en claro.

### Cabeceras comunes

```http
Content-Type: application/json
X-Client-Id: app_…
X-Client-Secret: …
Idempotency-Key: …            (opcional, recomendado en /verify; 8–128 caracteres [A-Za-z0-9_.:-])
```

Cuerpos JSON de hasta 16 KiB con **esquema cerrado**: un campo no declarado responde `400 INVALID_REQUEST`.

---

## 2. Flujo completo

```text
Alta (una vez por usuario)                      Inicio de sesión (cada vez)
──────────────────────────                      ───────────────────────────
1. POST /api/v1/enrollments        → QR         3. POST /api/v1/verify          → JWT (300 s)
2. POST /api/v1/enrollments/{id}/activate       4. Verificar firma con JWKS (local, sin red)
   → 10 códigos de recuperación (una vez)       5. POST /api/v1/tokens/validate → consume el jti
                                                6. Abrir la sesión del sistema
```

En los ejemplos: `export CID=app_… CS=…` y se ejecutan desde `backend/` (por la ruta de `certs/ca.crt`).

### 2.1 Enrolar

```bash
curl --cacert certs/ca.crt -X POST https://localhost:8443/api/v1/enrollments \
  -H "Content-Type: application/json" -H "X-Client-Id: $CID" -H "X-Client-Secret: $CS" \
  -d '{"user_ref":"ciudadano-0001","account_label":"Portal de Trámites"}'
```

Respuesta `201`:

```json
{
  "enrollment_id": "b391211a-4062-47df-8be6-91fbd6da2ecf",
  "estado": "pendiente",
  "algoritmo": "SHA256",
  "digitos": 6,
  "periodo": 30,
  "otpauth_uri": "otpauth://totp/ServicioSoberanoTOTP:Portal%20de%20Tr%C3%A1mites?secret=…&issuer=ServicioSoberanoTOTP&algorithm=SHA256&digits=6&period=30",
  "qr_svg": "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"260\" …</svg>",
  "expires_at": "2026-11-26T17:29:36.682Z"
}
```

- Opcionales: `algorithm` (`SHA256`, `SHA512`; `SHA1` solo si la política de la app lo permite), `digits` (6/8), `period` (15–60). Por defecto se usa la política de la app.
- Muestre el QR **como imagen** (`<img src="data:image/svg+xml;base64,…">`), nunca insertando el SVG en el HTML.
- Ofrezca también la clave manual (parámetro `secret` del URI) y el enlace a la app autenticadora propia: `https://<servidor>:8443/app/#add=<otpauth_uri codificado>`.
- El enrolamiento pendiente caduca en 10 minutos. La semilla no vuelve a mostrarse.

### 2.2 Activar con el primer código

```bash
curl --cacert certs/ca.crt -X POST https://localhost:8443/api/v1/enrollments/$EID/activate \
  -H "Content-Type: application/json" -H "X-Client-Id: $CID" -H "X-Client-Secret: $CS" \
  -d '{"code":"494530"}'
```

```json
{"enrollment_id":"b391211a-4062-47df-8be6-91fbd6da2ecf","estado":"activo","activated_at":"2026-11-26T17:19:37.002Z",
 "recovery_codes":["6WZT-U2RR","76YC-TB68","M6HM-QGW5","AHEP-T5NN","HXSN-K33M","XUCE-FQB8","DGUF-T4E9","PQB4-S4DQ","MF78-HABA","SA7R-K8WK"]}
```

Muestre los 10 códigos de recuperación **una sola vez** y no los guarde. El código usado para activar ya
no sirve para entrar: el usuario debe esperar al siguiente.

### 2.3 Verificar un código

```bash
curl --cacert certs/ca.crt -X POST https://localhost:8443/api/v1/verify \
  -H "Content-Type: application/json" -H "X-Client-Id: $CID" -H "X-Client-Secret: $CS" \
  -H "Idempotency-Key: demo-verify-0001" \
  -d '{"user_ref":"ciudadano-0001","code":"318204"}'
```

Respuesta `200`:

```json
{
  "verified": true,
  "token": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsImtpZCI6IjdZVDBBMVBqVnVoeEZmVk1tSnBqekEifQ.eyJpc3Mi…",
  "jti": "7292e436-0a23-4321-b28b-4c34be70414b",
  "kid": "7YT0A1PjVuhxFfVMmJpjzA",
  "expires_at": "2026-11-26T17:24:47.000Z",
  "drift_steps": 1,
  "risk": { "score": 0, "level": "LOW", "action": "ALLOW", "inference_ms": 0.159,
            "reasons": ["Comportamiento dentro del patrón habitual"] }
}
```

Contenido del JWT (cabecera y claims):

```json
{ "alg": "EdDSA", "typ": "JWT", "kid": "7YT0A1PjVuhxFfVMmJpjzA" }
{ "iss": "https://totp.soberano.local",
  "sub": "3cdff853c3d85747833bedc1bae059bd790a96ded0f907c6026ee52e20bdf330",
  "aud": "app_3b57117f4df708b7cf7d40388b79892a",
  "amr": ["otp"], "iat": 1795713587, "nbf": 1795713587, "exp": 1795713887,
  "jti": "7292e436-0a23-4321-b28b-4c34be70414b" }
```

Respuestas de rechazo reales:

| Situación | HTTP | Cuerpo |
| --- | --- | --- |
| Código incorrecto **o** usuario sin enrolamiento (misma respuesta) | 401 | `{"error":"VERIFICATION_FAILED","message":"No se pudo completar la verificación."}` |
| Código ya usado (replay) | 401 | `{"error":"REPLAY_DETECTED","message":"El código TOTP ya fue utilizado dentro de la ventana temporal activa (ataque de repetición mitigado).","retry_after_seconds":13,…}` |
| Sexto intento tras 5 fallos (bloqueo progresivo 30 s → 2 min → 10 min → 1 h) | 429 | `{"error":"TOO_MANY_REQUESTS","message":"Demasiados intentos. Intente más tarde.","retry_after_seconds":30}` + cabecera `Retry-After: 30` |
| Detector local de anomalías | 429 | `{"error":"ANOMALY_BLOCKED",…,"riskAssessment":{"riskScore":100,"level":"CRITICAL",…}}` |
| Campo no declarado | 400 | `{"error":"INVALID_REQUEST","message":"Solicitud inválida."}` |
| Credenciales de app incorrectas | 401 | `{"error":"UNAUTHORIZED","message":"Credenciales inválidas."}` |
| Error interno o base de datos no disponible | 503 | `{"error":"SERVICE_UNAVAILABLE",…}` (nunca 200) |

**Idempotencia.** Con `Idempotency-Key` la respuesta se guarda 5 minutos por (app, clave): si su petición
se corta y la repite con la **misma** clave, recibe la misma respuesta sin que el código se evalúe dos
veces (evita un falso `REPLAY_DETECTED`). Reutilizar la clave con otro cuerpo da 400.

### 2.4 Validar el token

Primero, **verificación local** (sin red) con las claves públicas:

```bash
curl --cacert certs/ca.crt https://localhost:8443/.well-known/jwks.json
# {"keys":[{"kty":"OKP","crv":"Ed25519","x":"Ne4_0nRQXn7Yp-q-R4efGUR4vPWHqZVINh8c0QJCLWI","kid":"7YT0A1PjVuhxFfVMmJpjzA","use":"sig","alg":"EdDSA"}]}
```

Acepte solo `alg: EdDSA`, compruebe la firma con la clave de su `kid`, `iss`, `aud` = su `client_id`,
`exp`/`nbf`, `amr` contiene `otp` y que existan `sub` y `jti`. La JWKS puede guardarse en caché (el servicio
envía `Cache-Control: public, max-age=300`); ante un `kid` desconocido, vuelva a pedirla (rotación).

Después, **validación en el servicio**, que además consume el `jti` (uso único):

```bash
curl --cacert certs/ca.crt -X POST https://localhost:8443/api/v1/tokens/validate \
  -H "Content-Type: application/json" -H "X-Client-Id: $CID" -H "X-Client-Secret: $CS" \
  -d "{\"token\":\"$TOKEN\"}"
# 1.ª vez: {"valid":true,"sub":"3cdff853…","aud":"app_3b57117f…","jti":"7292e436-…","kid":"7YT0A1PjVuhxFfVMmJpjzA","amr":["otp"],"exp":1795713887}
# 2.ª vez: {"valid":false,"reason":"jti_consumido"}
```

Un token inválido responde `200` con `valid: false` y `reason` ∈ `formato`, `alg`, `kid`, `firma`, `iss`,
`aud`, `exp`, `nbf`, `jti_consumido`. Con `"consume_jti": false` solo se consulta.

### 2.5 Operaciones de mantenimiento

```bash
# Resincronizar un reloj desfasado con dos códigos consecutivos (búsqueda en ±10 pasos)
curl --cacert certs/ca.crt -X POST https://localhost:8443/api/v1/enrollments/$EID/resync \
  -H "Content-Type: application/json" -H "X-Client-Id: $CID" -H "X-Client-Secret: $CS" \
  -d '{"code_1":"…","code_2":"…"}'
# {"resynced":true,"drift_steps":5}

# Recuperación con un código de recuperación: revoca el factor y obliga a re-enrolar
curl --cacert certs/ca.crt -X POST https://localhost:8443/api/v1/recovery \
  -H "Content-Type: application/json" -H "X-Client-Id: $CID" -H "X-Client-Secret: $CS" \
  -d '{"user_ref":"ciudadano-0001","recovery_code":"6WZT-U2RR"}'
# {"recovered":true,"must_reenroll":true,"remaining_codes":9}

# Revocar (idempotente)
curl --cacert certs/ca.crt -X DELETE https://localhost:8443/api/v1/enrollments/$EID \
  -H "X-Client-Id: $CID" -H "X-Client-Secret: $CS"
# {"enrollment_id":"b391211a-…","estado":"revocado","revoked_at":"2026-11-26T17:19:57.184Z"}
```

Tras una recuperación **no** conceda acceso directo: inicie un enrolamiento nuevo y pida un código del
autenticador nuevo.

---

## 3. Con el SDK (Node.js 22, sin dependencias)

El SDK envuelve estas mismas llamadas con tiempo de espera, reintento idempotente, errores tipados y
validación local del JWT. No se repite aquí:

- **Guía paso a paso para el equipo del Reto 3:** [`sdk/INTEGRACION_RETO3.md`](../../sdk/INTEGRACION_RETO3.md) (credenciales de la app "Agente Evaluador (Reto 3)", inicialización, flujo de 4 llamadas y pruebas con el servicio falso).
- **Referencia de métodos y garantías:** [`sdk/README.md`](../../sdk/README.md).
- **Ejemplo completo en producción simulada:** [`demo-portal-tramites/src/portal.js`](../../demo-portal-tramites/src/portal.js).

## 4. Integración desde otros lenguajes

El SDK es opcional: cualquier lenguaje con cliente HTTPS y Ed25519 puede integrarse.

1. Confíe en la CA del servicio (no desactive la verificación TLS).
2. Envíe `X-Client-Id` y `X-Client-Secret` en cada llamada a `/api/v1/*`.
3. Ponga un **tiempo de espera total** corto (3 s) y como mucho **un** reintento, con la misma `Idempotency-Key`, solo ante error de red, tiempo agotado o 503.
4. Considere aprobado **solo** un `200` con `verified === true`. Cualquier otra cosa (incluida una respuesta mal formada) = sin acceso.
5. Verifique el JWT localmente (Ed25519 con la JWKS) y valídelo en el servicio para consumir el `jti`.

---

## 5. Buenas prácticas para cualquier integrador

- Use credenciales propias de su app (el `aud` del JWT debe ser su `client_id`); el equipo del Reto 3 usa la app **"Agente Evaluador (Reto 3)"** que crea `npm run seed`.
- Pida el segundo factor después de su primer factor y antes de crear la sesión; en operaciones sensibles, vuelva a pedir un código (*step-up*).
- Nunca deje pasar a un usuario porque el servicio no respondió (**falla cerrado**) y muestre mensajes genéricos.
- La política de su app (algoritmo, dígitos, periodo, ventana, intentos, umbral y modo del detector) se ajusta en `/consola/` → Aplicaciones.

## 6. Límites y protecciones que verá un integrador

| Protección | Comportamiento |
| --- | --- |
| Límites de tasa | Global por IP (anti-DDoS, antes de autenticar), por app y por origen; superarlos da `429` con `Retry-After`. Configurables con `RATE_LIMIT_*` (ver `README.md`). |
| Bloqueo progresivo por cuenta | 5 fallos → 30 s, luego 2 min, 10 min y 1 h; persiste tras reiniciar el servicio. |
| Detector local de anomalías | Puede responder `429 ANOMALY_BLOCKED` (300 s) ante spraying o fuerza bruta distribuida si la app está en modo `bloqueo`. |
| Cabeceras | `Strict-Transport-Security`, `Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Cache-Control: no-store`, entre otras. |
| CORS | Lista blanca (`CORS_ALLOWED_ORIGINS`); las llamadas de servidor a servidor no lo necesitan. |
