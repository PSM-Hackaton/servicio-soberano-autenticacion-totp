# Prueba de Despliegue Institucional sin Contenedores (`systemd`)

> **Issue:** `#25` (C7) · **Referencias:** `deploy/servicio-totp.service`, `deploy/README.md`, `deploy/verificar-despliegue.js`  
> **Fecha de verificación:** 2026-11-26 · **Entorno:** Ubuntu Linux, `systemd 259 (259.9-0ubuntu0.1)`, `Node.js v22.22.1`, `OpenSSL` del sistema (**0 dependencias npm**, sin Docker, sin Internet).

---

## 1. Semáforo de Preparación para Producción (*Production Readiness*)

**LISTO PARA PRODUCCIÓN** (la observación de la cámara en `/app/` del Issue `#20` quedó resuelta: `camera=(self)` solo en `/app/`).

Se validaron de punta a punta la unidad `systemd`, la guía operativa `deploy/README.md`, la configuración en modo `NODE_ENV=production`, el cifrado TLS 1.3 obligatorio, la semilla institucional, el respaldo SQLite en caliente (`VACUUM INTO`), la parada ordenada con `SIGTERM` y el escaneo dinámico de seguridad propio (`attack-lab/escenarios/dast.js`) en vivo contra la instancia desplegada.

---

## 2. Resultados Reales de la Verificación (`node deploy/verificar-despliegue.js`)

| # | Control verificado | Resultado | Evidencia real observada |
| :---: | :--- | :---: | :--- |
| 1 | `systemd-analyze verify` sobre `deploy/servicio-totp.service` | **OK** | Sin errores sintácticos ni directivas inválidas |
| 2 | `systemd-analyze security --offline=yes deploy/servicio-totp.service` | **OK** | **`Overall exposure level: 3.0 OK :-)`** (`ProtectSystem=strict`, `NoNewPrivileges=true`, `PrivateTmp=true`, `PrivateDevices=true`, `ProtectClock=true`, `CapabilityBoundingSet=`, `UMask=0077`) |
| 3 | Generación `.env` (`generar-env.js`) + certificado EC P-256 (`openssl`) | **OK** | Permisos restringidos `0640` en `.env` y llave privada TLS, carpeta de datos `0700` |
| 4 | *Fail-fast* en `NODE_ENV=production` con `TLS_MODE=off` | **OK** | Código de salida `1` (`ERROR Configuración inválida`), impide arrancar inseguro |
| 5 | Inicialización `scripts/semilla.js` con `NODE_ENV=production` | **OK** | Base SQLite WAL creada con migraciones, apps `Portal de Trámites` y `Agente Evaluador (Reto 3)`, y admin inicial |
| 6 | Arranque producción TLS 1.3 + `GET /health/ready` | **OK** | HTTP `200` (`listo en ~280 ms`) |
| 7 | Rutas críticas servidas desde el mismo proceso | **OK** | `/.well-known/jwks.json=200`, `/app/=200`, `/consola/=200`, `/metrics=200` (solo loopback) |
| 8 | Escaneo dinámico DAST propio (`attack-lab/escenarios/dast.js`) en vivo | **OK** | **10/10 verificaciones OK, 0 hallazgos críticos/altos**: TLS 1.3 `TLS_AES_256_GCM_SHA384`, TLS 1.2 rechazado, cabeceras OWASP en las 34 sondas (31 rutas del contrato, `/app/`, `/consola/` y una ruta inexistente), `camera=(self)` en `/app/`, 7/7 métodos peligrosos bloqueados, 9/9 sondas CORS cerradas, `/metrics` aislado en loopback (`403` externo), 0 errores `5xx` y 0 fugas |
| 9 | Respaldo consistente en caliente (`SQLite VACUUM INTO`) | **OK** | Copia íntegra verificada en modo solo lectura (9 tablas incluyendo migraciones, 3 apps) sin detener el servicio |
| 10 | Apagado ordenado con `SIGTERM` (`TimeoutStopSec=15`) | **OK** | Código de salida `0` en **`~5 ms`** (cierre limpio de conexiones y SQLite WAL) |

---

## 3. Observaciones y Recomendaciones para Operación Institucional

1. **Cámara en `/app/` (Issue `#20` C2, resuelto):** el servidor envía `Permissions-Policy: camera=(self)` solo en `/app/` (lector de QR de la PWA); la API y la consola mantienen `camera=()`. El DAST lo comprueba en cada ejecución. Con sesión de administración (`--admin-user`, `--admin-pass`, `--admin-totp`) el escaneo añade la cookie y el CSRF: 12/12 (`docs/evidencias/dast-informe-2026-11-26.html`).
2. **Habilitación en servidor Linux real con privilegios `root`:** seguir los pasos 2–7 de [`deploy/README.md`](../../deploy/README.md) (`useradd --system totp`, `/opt/servicio-totp`, `/etc/servicio-totp/servicio-totp.env`, `systemctl enable --now servicio-totp`) y configurar `chrony` contra el servidor NTP institucional.
3. **Reproducibilidad:** cualquier auditor puede volver a ejecutar la prueba completa sin afectar la máquina con:
   ```bash
   node deploy/verificar-despliegue.js --guardar-dast docs/evidencias   # --puerto N si 18443 está ocupado
   ```
