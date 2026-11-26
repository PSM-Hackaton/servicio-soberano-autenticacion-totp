# Portal de Trámites del Estado (demo)

Sistema institucional **ficticio** que muestra cómo una institución añade el segundo factor del Servicio Soberano TOTP con el SDK (`../sdk`). Servidor Node propio, HTML renderizado en el servidor, CSS/JS propios, sin dependencias ni recursos externos.

## Arranque

```bash
cd demo-portal-tramites
cp .env.example .env                 # ponga TOTP_CLIENT_ID / TOTP_CLIENT_SECRET de la app "Portal de Trámites"
node scripts/crear-usuarios.js       # ciudadanos ficticios (contraseña: Tramites-Demo-2026)
node server.js                       # https://localhost:8444 si existen ../backend/certs/, si no http://localhost:8444
```

Sin backend (servicio falso, para ensayar la demo):

```bash
node ../sdk/testing/servicio-falso.js --puerto 8099 &
TOTP_BASE_URL=http://127.0.0.1:8099 TOTP_CLIENT_SECRET=secreto-de-prueba-no-usar-en-produccion node server.js
```

Pruebas: `node --test tests/*.test.js` (desde la raíz: `node --test 'sdk/tests/*.test.js' 'demo-portal-tramites/tests/*.test.js'`).

## Flujo

1. **Usuario y contraseña** (primer factor propio del portal, scrypt). El portal solo envía al servicio un `user_ref` opaco (`ptd-…`): ni nombre ni documento.
2. **Sin segundo factor → enrolamiento:** QR del servicio (como imagen `data:`; nunca SVG en línea), clave manual, botón *Abrir en el Autenticador Soberano* (`AUTENTICADOR_URL#add=<otpauth>`), primer código para activar y **10 códigos de recuperación mostrados una sola vez** (copiar / imprimir).
3. **Con segundo factor → código TOTP:** `verificar` → JWT EdDSA → firma comprobada localmente con la JWKS en caché → `tokens/validate` (consume el `jti`) → sesión nueva.
4. **Panel** con trámites ficticios. Los sensibles (certificado, datos bancarios, desactivar el factor) piden **otro código** (step-up).

Errores visibles: código incorrecto (401), bloqueo con cuenta atrás (429; el portal no vuelve a consultar al servicio mientras dura), servicio caído o lento → «No se puede verificar en este momento. Intente más tarde.» y **nunca** acceso. Si solo `tokens/validate` falla tras un `verify` correcto, se acepta la verificación local y el portal registra el `jti`.

El botón **«Lo que ocurre por dentro»** muestra/oculta la traza de la sesión: llamadas al servicio con tiempos e intentos, claims del JWT (sin firma) y cada decisión. Nunca incluye contraseñas, códigos ni secretos.

## Seguridad

Cookie `__Host-` HttpOnly; Secure; SameSite=Strict, rotada al validar la contraseña y el segundo factor; CSRF por sesión + comprobación de `Origin`; CSP `default-src 'none'` sin nada en línea; HSTS con TLS; `Referrer-Policy: same-origin`; freno de contraseñas por usuario; sesiones de 15 min de inactividad.
