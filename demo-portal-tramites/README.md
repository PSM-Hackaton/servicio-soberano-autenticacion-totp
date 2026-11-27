# Portal de Trámites del Estado (demo)

Sistema institucional **ficticio** que muestra cómo una institución añade el segundo factor del Servicio Soberano TOTP con el SDK (`../sdk`). Servidor Node propio, HTML renderizado en el servidor, CSS/JS propios, sin dependencias ni recursos externos.

## Arranque

```bash
cd demo-portal-tramites
cp .env.example .env                 # ponga TOTP_CLIENT_ID / TOTP_CLIENT_SECRET (obligatorios) y TOTP_CEDULA_SECRETO de la app "Portal de Trámites"
node scripts/crear-usuarios.js       # ciudadanos ficticios: V-10.000.001, V-10.000.002, E-80.000.003 (contraseña: Tramites-Demo-2026)
node server.js                       # https://localhost:8444 si existen ../backend/certs/, si no http://localhost:8444
```

Sin backend (servicio falso, para ensayar la demo):

```bash
node ../sdk/testing/servicio-falso.js --puerto 8099 &
TOTP_BASE_URL=http://127.0.0.1:8099 TOTP_CLIENT_ID=portal-tramites TOTP_CLIENT_SECRET=secreto-de-prueba-no-usar-en-produccion node server.js
```

Pruebas: `node --test tests/*.test.js` (desde la raíz: `node --test 'sdk/tests/*.test.js' 'demo-portal-tramites/tests/*.test.js'`).

## Flujo

1. **Cédula de identidad y contraseña** (primer factor propio del portal, scrypt). El portal solo envía al servicio un seudónimo `user_ref` (`ptd-…` en el formato `hmac` del servicio, ver *Identificación del ciudadano*): ni nombre ni cédula.
   En cada llamada que comprueba un código (`verify`, `activate`, `recovery`) envía además `client_ip`, la IP de la conexión del ciudadano con el portal (dirección del socket), para que el detector de anomalías y los límites del servicio traten a cada ciudadano como un origen propio y los fallos de unos no bloqueen a todo el portal. `X-Forwarded-For` solo se usa con `PORTAL_CONFIAR_X_FORWARDED_FOR=1` (proxy inverso propio delante; vale la última entrada).
2. **Sin segundo factor → enrolamiento:** QR del servicio (como imagen `data:`; nunca SVG en línea), clave manual, botón *Abrir en el Autenticador Soberano* (`AUTENTICADOR_URL#add=<otpauth>`), primer código para activar y **10 códigos de recuperación mostrados una sola vez** (copiar / imprimir).
3. **Con segundo factor → código TOTP:** `verificar` → JWT EdDSA → firma comprobada localmente con la JWKS en caché → `tokens/validate` (consume el `jti`) → sesión nueva.
4. **Panel** con trámites ficticios. Los sensibles (certificado, datos bancarios, desactivar el factor) piden **otro código** (step-up).

Errores visibles: código incorrecto (401), bloqueo con cuenta atrás (429; el portal no vuelve a consultar al servicio mientras dura), servicio caído o lento → «No se puede verificar en este momento. Intente más tarde.» y **nunca** acceso. Si solo `tokens/validate` falla tras un `verify` correcto, se acepta la verificación local y el portal registra el `jti`.

El botón **«Lo que ocurre por dentro»** muestra/oculta la traza de la sesión: llamadas al servicio con tiempos e intentos, claims del JWT (sin firma) y cada decisión. Nunca incluye contraseñas, códigos ni secretos.

## Identificación del ciudadano: cédula de identidad

La **cédula de identidad** es el identificador institucional del ciudadano en el portal. El formulario pide la nacionalidad (`V` venezolano / `E` extranjero) y el número, de 6 a 9 dígitos, con o sin puntos (`12345678`, `12.345.678`; también se acepta el prefijo escrito en el campo, `V-12.345.678`). El servidor valida siempre el formato (`src/cedula.js`) y la normaliza a `V12345678` / `E12345678`; en pantalla se muestra como `V-12.345.678`. El JavaScript del cliente (`publico/app.js`) solo añade ayuda visual mientras se escribe.

El **servicio TOTP nunca ve la cédula**: el portal le envía como `user_ref` un seudónimo estable

```
user_ref = TOTP_CEDULA_PREFIJO + base64url(HMAC-SHA256(cédula canónica, TOTP_CEDULA_SECRETO))   # p. ej. ptd-3q2-…
```

Es exactamente la derivación del modo `user_ref_desde_cedula = hmac` del servicio: el portal la calcula con `derivarUserRefDesdeCedula` del SDK (`sdk/src/cedula.js`, el mismo archivo que usa el backend). `npm run seed` registra la app «Portal de Trámites» con ese modo y el prefijo `ptd-`, e imprime **una sola vez** su `cedula_secreto` junto al `client_secret` (`deploy/instalar.sh` lo copia a `TOTP_CEDULA_SECRETO`). Con ello el soporte de la consola puede **buscar el enrolamiento de un ciudadano escribiendo su cédula**: el servicio descifra el secreto de la app con la bóveda, recalcula el `user_ref` y no guarda la cédula en ningún sitio (en la bitácora solo queda su HMAC con pepper).

Si `TOTP_CEDULA_SECRETO` está vacío, el portal usa un secreto local al azar en `datos/seudonimos.clave` (0600) y avisa al arrancar: funciona igual, pero la consola no podrá encontrar a esos ciudadanos por cédula. Sin el secreto no se puede volver del seudónimo a la cédula ni comprobar si una cédula concreta está enrolada en el servicio. La etiqueta de cuenta que viaja en el `otpauth://` lleva solo los tres últimos dígitos (`Portal de Trámites (…001)`). Cambiar el secreto (o el prefijo) desvincula a todos los ciudadanos de sus autenticadores. `datos/usuarios.json` guarda la cédula normalizada, el nombre, el hash scrypt y el `enrollment_id`; nunca el seudónimo ni la semilla.

Las cédulas de demostración (`V-10.000.001` Ana Rivera Soto, `V-10.000.002` Bruno Méndez Lara, `E-80.000.003` Carla Ortiz Peña) son **ficticias y de prueba**.

## Interfaz

Estilo de portal institucional: cintillo blanco con la bandera nacional (SVG propio, sin escudo) y «República Bolivariana de Venezuela / Portal de Trámites del Estado», franja tricolor, menú horizontal (en móvil se colapsa con un botón accesible), portada con acceso y trámites en línea, migas de pan, «Oficina virtual» y pie institucional. La institución es ficticia y el aviso «Sitio de demostración» es siempre visible. Sin recursos externos, sin estilos ni scripts en línea.

## Seguridad

Cookie `__Host-` HttpOnly; Secure; SameSite=Strict, rotada al validar la contraseña y el segundo factor; CSRF por sesión + comprobación de `Origin`; CSP `default-src 'none'` sin nada en línea; HSTS con TLS; `Referrer-Policy: same-origin`; freno de contraseñas por cédula; sesiones de 15 min de inactividad.
