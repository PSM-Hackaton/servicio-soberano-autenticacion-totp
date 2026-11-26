# Guion de Demostración en Vivo ante el Jurado (7 minutos)

> **Propósito:** Demostrar de punta a punta soberanía real (0 dependencias npm, 0 llamadas a Internet), criptografía estándar RFC 6238 (SHA-256 y SHA-512), resiliencia *fail-closed*, detección de ataques y trazabilidad verificable.

---

## Preparación previa (2 minutos antes de subir)

1. Abrir 3 pestañas en el navegador local (sin acceso a Internet / modo avión listo):
   - Pestaña 1: `http://127.0.0.1:3000/` (**Portal Institucional de Trámites**)
   - Pestaña 2: `http://127.0.0.1:3000/authenticator/` (**PWA Autenticadora Soberana**)
   - Pestaña 3: `http://127.0.0.1:3000/admin/` (**Consola Administrativa RBAC**)
2. Tener una terminal abierta en la raíz del repositorio lista para ejecutar `node attack-lab/run-all.js`.
3. En la PWA, crear un PIN rápido (ej. `2468`) y pulsar **"Cargar cuentas demo"** (deja lista la cuenta `SHA-256 / 6 dígitos` del Portal de Trámites y la cuenta `SHA-512 / 8 dígitos` del Reto 1).

---

## Minuto 0:00 – 1:00 · Problema y Soberanía Real (8 Pilares)

- **Mensaje clave:** *"Las apps autenticadoras comerciales obligan a usar SHA-1, dependen de tiendas extranjeras y sincronizan semillas en nubes fuera de nuestra jurisdicción. Nuestra solución corre 100 % en infraestructura propia con **cero dependencias npm externas** (ver `docs/sbom/sbom.cdx.json`), sobre Node.js 22 nativo, SQLite WAL y Web Crypto."*
- Mostrar rápidamente el **SBOM CycloneDX 1.5** (`0` dependencias externas) y la pestaña **Red (Network)** del navegador confirmando **0 llamadas a CDNs o dominios externos**.

---

## Minuto 1:00 – 2:45 · Flujo Ciudadano Completo + Modo Sin Internet

1. **Desconectar el equipo de Internet** (o activar modo Offline en DevTools) para probar soberanía real.
2. En **Pestaña 1 (Portal de Trámites)**: ingresar `ciudadano-demo` / `Tramites2026!` → avanza al **Paso 2: Desafío TOTP**.
3. En **Pestaña 2 (PWA Autenticadora)**:
   - Mostrar el badge **Modo Sin Conexión**, la bóveda cifrada por PIN (`PBKDF2-SHA256 + AES-256-GCM` en IndexedDB), las dos cuentas (`SHA-256 6d` y `SHA-512 8d`) y el **anillo animado de 30 s**.
   - Tocar la tarjeta para **copiar el código con un toque**.
4. Pegar el código en el Portal de Trámites → **Paso 3: Acceso autorizado**:
   - Mostrar la evidencia del **SDK (`sdk/`)**: JWT firmado con **Ed25519 (`EdDSA`)**, `amr: ["otp"]`, `jti` consumido una sola vez y **validado offline con caché JWKS**.
5. Mostrar opcionalmente el flujo **"Enrolar nuevo dispositivo"** con **HMAC-SHA512 / 8 dígitos**, URI `otpauth://` y entrega única de **10 códigos de recuperación**.

---

## Minuto 2:45 – 4:30 · Consola Administrativa RBAC, Rotación de Llaves y Bitácora Inmutable

1. En **Pestaña 3 (Consola Admin)**: iniciar sesión con perfil `Administrador` + código TOTP propio.
2. **Métricas & IA Local:** mostrar disponibilidad (`100%`), latencia p95 (`< 15 ms`), desfase de reloj, alertas del detector local de anomalías y la salida real de `/metrics` (Prometheus local).
3. **Aplicaciones y Políticas:** mostrar `portal-tramites` (`SHA256/6d`) y `reto1-evaluador` (`SHA512/8d`) — explicando cómo el **Reto 1** se integra en 4 llamadas usando `sdk/INTEGRACION_RETO1.md`.
4. **Llaves Ed25519 (JWKS):** pulsar **"🔄 Rotar llave Ed25519 (1 clic)"** → aparece un nuevo `kid` activo mientras la llave previa queda en ventana de gracia sin tumbar sesiones.
5. **Bitácora Encadenada (`audit_log`):**
   - Pulsar **"✔ Verificar integridad de la cadena"** → verde (`CADENA ÍNTEGRA`).
   - Pulsar **"⚠ Simular alteración (demo)"** y volver a verificar → **rojo inmediato** señalando exactamente el `broken_at_id` donde se rompió el encadenamiento `prev_hash → hash`.

---

## Minuto 4:30 – 6:15 · Attack Lab y Pruebas de Caos en Vivo

En la terminal, ejecutar:
```bash
node attack-lab/run-all.js
```
Mostrar la tabla de salida con **7/7 escenarios superados y 0 accesos indebidos**:
1. **Replay** bloqueado (anti-replay atómico).
2. **Fuerza bruta distribuida (8 IPs → 1 cuenta)** bloqueada con HTTP `429`.
3. **TOTP Spraying (1 IP → 10 cuentas)** bloqueado con HTTP `429`.
4. **Deriva de reloj (+150 s / +5 pasos)** rechazada y recuperada con **Resync de 2 códigos consecutivos**.
5. **Caos — Caída de SQLite:** `/health/ready` y `/verify` responden `503` (*fail-closed*, 0 accesos) y recuperación medida en milisegundos.
6. **Caos — Corte de red:** SDK aplica **1 reintento con la misma `Idempotency-Key`** y valida JWT previos **offline con caché JWKS**.
7. **Caos — Latencia artificial:** SDK aborta *fail-closed* por timeout estricto.

---

## Minuto 6:15 – 7:00 · Cierre y Plan B de Contingencia

- **Cierre:** Resumir impacto institucional: \$0 en licencias/APIs, 0 dependencias externas, auditable línea por línea, integrable en cualquier sistema público mediante `sdk/`.
- **Plan B si falla cámara o HTTPS móvil en sala:** usar el pegado de URI `otpauth://` o clave manual Base32 en la PWA y ejecutar `demo-portal-tramites/server.js` en `127.0.0.1:3000` (100 % independiente de red local o Wi-Fi del evento).
