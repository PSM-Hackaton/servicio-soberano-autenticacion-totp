# Guion de Demostración en Vivo ante el Jurado (7 minutos)

> **Propósito:** Demostrar de punta a punta soberanía real (**0 dependencias npm**, **0 llamadas a Internet**, **0 contenedores obligatorios**), criptografía RFC 6238 (SHA-256 y SHA-512), resiliencia *fail-closed*, IA local explicable y trazabilidad auditable.

---

## Preparación previa (2 minutos antes de subir)

### 1. Arrancar el Backend Soberano HTTPS (Terminal 1)
```bash
cd backend
npm run env      # genera backend/.env con llave maestra y peppers aleatorios (CSPRNG)
npm run certs    # genera CA local y certificado TLS 1.3 en backend/certs/
npm run seed     # crea apps "Portal de Trámites" y "Reto 1" + admin inicial (guardar secretos)
npm start        # levanta https://localhost:8443 (API + /app/ PWA + /consola/ Admin)
```

### 2. Arrancar el Portal de Trámites Demo (Terminal 2)
```bash
cd demo-portal-tramites
cp .env.example .env  # colocar TOTP_CLIENT_ID y TOTP_CLIENT_SECRET impresos por npm run seed
node scripts/crear-usuarios.js
node server.js        # levanta https://localhost:8444
```

### 3. Abrir 3 pestañas locales y 1 terminal para el Attack Lab
- Pestaña 1: `https://localhost:8444` (**Portal de Trámites del Estado**)
- Pestaña 2: `https://localhost:8443/app/` (**PWA Autenticadora Soberana**)
- Pestaña 3: `https://localhost:8443/consola/` (**Consola Administrativa RBAC**)
- Terminal 3: exportar `ATTACK_CLIENT_ID` y `ATTACK_CLIENT_SECRET` para `attack-lab/`.

---

## Minuto 0:00 – 1:00 · Soberanía Real y Cero Dependencias

- **Mensaje clave:** *"Las apps comerciales imponen SHA-1, dependen de tiendas extranjeras y sincronizan semillas fuera del país. Nuestro servicio funciona 100 % en infraestructura propia con **cero dependencias npm externas** — todo el motor TOTP RFC 6238, AES-256-GCM, Ed25519/JWKS, generador QR ISO/IEC 18004, Isolation Forest local y servidor TLS 1.3 son código propio sobre Node.js 22 nativo."*
- Mostrar [`docs/sbom/sbom.cdx.json`](./sbom/sbom.cdx.json) (`third_party_runtime_dependencies: 0`) y la pestaña **Red** del navegador con **0 llamadas a CDNs o dominios externos**.

---

## Minuto 1:00 – 2:45 · Flujo Ciudadano Completo + Modo Sin Internet

1. **Desconectar Internet** del equipo antes de iniciar el flujo para demostrar operación 100 % aislada.
2. En **Portal de Trámites (`https://localhost:8444`)**: iniciar sesión con usuario demo → el sistema muestra el **QR SVG generado localmente** + botón *"Abrir en el Autenticador Soberano"* + clave manual Base32.
3. En **PWA Autenticadora (`https://localhost:8443/app/`)**:
   - Desbloquear bóveda cifrada por **PIN** (IndexedDB + PBKDF2 + AES-256-GCM).
   - Importar la cuenta (`HMAC-SHA256` o `HMAC-SHA512` 8 dígitos), ver el anillo de 30 s y copiar el código.
4. Activar el factor en el Portal → mostrar los **10 códigos de recuperación de un solo uso** (solo visibles una vez).
5. Iniciar sesión con segundo factor y abrir **«Lo que ocurre por dentro»**: mostrar las llamadas del **SDK (`sdk/`)**, firma **JWT Ed25519** validada localmente con JWKS en caché, consumo único de `jti` y **step-up MFA** en un trámite sensible.

---

## Minuto 2:45 – 4:15 · Consola Administrativa RBAC, Rotación de Llaves y Bitácora Inmutable

1. En **Consola Admin (`https://localhost:8443/consola/`)**: iniciar sesión como Administrador con **TOTP propio** (cookies `HttpOnly; Secure; SameSite=Strict` + CSRF).
2. Mostrar **Panel / Métricas** (disponibilidad, latencia p50/p95, desfase de reloj, sin telemetría externa) y **Aplicaciones** (`Portal de Trámites` y `Reto 1`, explicando la guía [`sdk/INTEGRACION_RETO1.md`](../sdk/INTEGRACION_RETO1.md)).
3. En **Llaves Ed25519**: rotar la clave activa en **1 clic** → aparece el nuevo `kid` mientras el previo queda en `solo_verificacion` en `/.well-known/jwks.json`.
4. En **Auditoría (`audit_log`)**: pulsar **Verificar integridad de la cadena** → comprueba criptográficamente `prev_hash → hash` en todos los registros.

---

## Minuto 4:15 – 6:30 · Attack Lab, IA Local y Pruebas de Caos en Vivo

En Terminal 3 ejecutar los 4 momentos de mayor impacto ante el jurado:
1. **Replay + carrera paralela:** `node attack-lab/escenarios/replay.js --detallado` → reenvío rechazado (`REPLAY_DETECTED`) y de 10 envíos simultáneos del mismo código solo 1 pasa (anti-replay atómico en SQLite).
2. **JWT alterados:** `node attack-lab/escenarios/jwt.js` → `alg: none`, HS256, firma rota, otra audiencia y `jti` repetido: todos rechazados.
3. **Spraying + Isolation Forest local:** `node attack-lab/escenarios/spraying.js` → el detector local bloquea el origen con riesgo `CRITICAL` y **razones explicables** (visible al instante en la pestaña *Anomalías* de la Consola Admin).
4. **Caos de red (*fail-closed*):** `node attack-lab/caos/escenario-caos.js --detallado` → inyecta latencia (800 ms) y corte total (10 s) mediante el proxy TCP propio: **0 accesos indebidos concedidos** y recuperación inmediata al restaurar.

---

## Minuto 6:30 – 7:00 · Cierre y Plan B

- **Cierre:** mostrar el informe autocontenido generado por `node attack-lab/ejecutar-todo.js` (`attack-lab/resultados/informe-*.html`) y el despliegue institucional `systemd` sin contenedores en [`deploy/servicio-totp.service`](../deploy/servicio-totp.service).
- **Plan B (si hubiera fallo de red o certificados en sala):**
  - El Portal Demo arranca en 2 segundos contra `node sdk/testing/servicio-falso.js --puerto 8099`.
  - Todas las pruebas automatizadas corren offline con `node --test` en menos de 10 segundos.
