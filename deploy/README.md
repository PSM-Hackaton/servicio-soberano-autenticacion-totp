# Despliegue en servidor institucional (sin contenedores)

Guía para instalar el Servicio Soberano TOTP en un servidor Linux de la institución con
`systemd`. No requiere Docker, gestores de paquetes de Node ni acceso a Internet: el backend
solo usa módulos nativos de Node.js 22 (`node:https`, `node:crypto`, `node:sqlite`).

Archivos de esta carpeta:

| Archivo | Uso |
| :--- | :--- |
| `servicio-totp.service` | Unidad `systemd` de ejemplo (usuario sin privilegios, sistema de archivos de solo lectura salvo los datos, reinicio automático). |
| `README.md` | Esta guía. |

## 1. Requisitos

- Linux con `systemd` (probado el formato de la unidad con `systemd-analyze verify`).
- **Node.js 22.5 o superior** (necesario para `node:sqlite`). Instálelo desde el repositorio de paquetes o el espejo interno de la institución y compruebe: `node --version`.
- `openssl` (solo si se generan certificados de prueba), `chrony` para la hora y `gpg` para las copias cifradas.
- Certificado de servidor emitido por la CA institucional para el nombre DNS del servicio.

## 2. Usuario dedicado y carpetas

```bash
sudo useradd --system --home-dir /var/lib/servicio-totp --shell /usr/sbin/nologin totp
sudo mkdir -p /opt/servicio-totp /etc/servicio-totp/tls
# Copia del repositorio (etiqueta o commit aprobado), propiedad de root: el servicio solo la lee.
sudo git clone --branch <etiqueta-aprobada> <url-del-repositorio> /opt/servicio-totp
sudo chown -R root:root /opt/servicio-totp
```

```bash
# Carpeta de datos (la unidad también la gestiona con StateDirectory=, pero la semilla
# del paso 6 se ejecuta antes de arrancar el servicio y la necesita ya creada).
sudo install -d -o totp -g totp -m 0700 /var/lib/servicio-totp
```

`/var/lib/servicio-totp` (propietario `totp`, modo `0700`) es la única ruta escribible para el
servicio (`ProtectSystem=strict` + `ReadWritePaths=`).

El mismo proceso sirve la PWA (`/app/`) y la consola (`/consola/`) desde
`/opt/servicio-totp/authenticator-app` y `/opt/servicio-totp/admin-console`, por eso se copia el
repositorio completo.

## 3. Configuración y secretos

Genere el archivo de configuración con valores aleatorios fuertes y muévalo fuera del repositorio:

```bash
cd /opt/servicio-totp/backend
sudo node scripts/generar-env.js --salida /etc/servicio-totp/servicio-totp.env
sudo chown root:totp /etc/servicio-totp/servicio-totp.env
sudo chmod 0640 /etc/servicio-totp/servicio-totp.env
```

Edite `/etc/servicio-totp/servicio-totp.env` (las variables se describen en `.env.example` de la raíz):

```ini
NODE_ENV=production
HOST=0.0.0.0
PORT=8443
TLS_MODE=node
TLS_CERT_PATH=/etc/servicio-totp/tls/servidor.crt
TLS_KEY_PATH=/etc/servicio-totp/tls/servidor.key
SQLITE_DB_PATH=/var/lib/servicio-totp/totp_soberano.db
JWT_ISSUER=https://totp.<dominio-institucional>
CORS_ALLOWED_ORIGINS=
CLOCK_REFERENCE_URL=
```

Con `NODE_ENV=production` el servicio se niega a arrancar con `TLS_MODE=off` o con orígenes CORS `http://`,
y cualquier valor que conserve `CHANGE_ME` detiene el arranque con un mensaje claro.

## 4. Certificados institucionales

1. Genere la llave y la solicitud de firma en el propio servidor (la llave no sale de él):
   ```bash
   sudo openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out /etc/servicio-totp/tls/servidor.key
   sudo openssl req -new -key /etc/servicio-totp/tls/servidor.key \
     -subj "/O=<Institución>/CN=totp.<dominio-institucional>" \
     -addext "subjectAltName=DNS:totp.<dominio-institucional>" -out /tmp/servidor.csr
   ```
2. Envíe `servidor.csr` a la CA institucional y guarde el certificado recibido (con la cadena intermedia, si la hay) en `/etc/servicio-totp/tls/servidor.crt`.
3. Permisos: `sudo chown root:totp /etc/servicio-totp/tls/*` y `sudo chmod 0640 /etc/servicio-totp/tls/servidor.key`.
4. El servicio solo acepta TLS 1.3. Los clientes (portal, SDK, navegadores) deben confiar en la CA institucional.
5. **Renovación:** sustituya los archivos y ejecute `sudo systemctl restart servicio-totp` (el certificado se lee al arrancar).

Para pruebas sin CA institucional existe `npm run certs` (CA local en `backend/certs/`), no apto para producción.

## 5. Hora del sistema (NTP institucional con chrony)

TOTP depende de la hora: con ventana ±1 se toleran unos 30 s de desfase. Use el NTP institucional:

```bash
sudo apt install chrony        # o el gestor de paquetes de la distribución
# /etc/chrony/chrony.conf: comente los "pool" públicos y añada el servidor institucional
#   server ntp.<dominio-institucional> iburst
#   makestep 1.0 3
sudo systemctl restart chrony
chronyc tracking               # "System time" debe estar por debajo de unos pocos milisegundos
chronyc sources -v
```

Opcional: `CLOCK_REFERENCE_URL` apuntando a un servidor HTTP(S) interno; el servicio mide cada
10 minutos el desfase con su cabecera `Date`, lo publica en `/admin/api/metrics` (`desfaseRelojMs`)
y en `/metrics` (`totp_clock_skew_ms`), y registra un aviso si supera 5 s.

## 6. Datos iniciales

Ejecute la semilla una sola vez, como el usuario del servicio. Muestra **una sola vez** los
`client_secret` de las apps "Portal de Trámites" y "Reto 1" y la contraseña, la URI TOTP y los
códigos de recuperación del administrador inicial:

```bash
sudo install -d -o totp -g totp -m 0700 /opt/servicio-totp/backend/data
sudo -u totp env NODE_ENV=production ENV_FILE=/etc/servicio-totp/servicio-totp.env \
  node /opt/servicio-totp/backend/scripts/semilla.js
# La semilla deja el QR del administrador en /opt/servicio-totp/backend/data/admin-qr.svg:
# escanéelo con la app autenticadora y bórrelo de inmediato.
sudo shred -u /opt/servicio-totp/backend/data/admin-qr.svg && sudo rmdir /opt/servicio-totp/backend/data
```

Entregue cada `client_secret` al responsable de cada sistema integrador por un canal seguro.

## 7. Instalación de la unidad y operación

```bash
sudo cp /opt/servicio-totp/deploy/servicio-totp.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now servicio-totp
systemctl status servicio-totp
journalctl -u servicio-totp -f       # los registros no contienen secretos ni direcciones IP
curl --cacert <ca-institucional.crt> https://totp.<dominio-institucional>:8443/health/ready
```

- Abra en el cortafuegos solo el puerto del servicio (8443, o 443 si activa `CAP_NET_BIND_SERVICE` en la unidad).
- `/metrics` solo responde sin sesión desde la propia máquina (127.0.0.1): un recolector local puede leerlo.
- Actualización: `git fetch && git checkout <nueva-etiqueta>` en `/opt/servicio-totp`, `cd backend && npm test` y `sudo systemctl restart servicio-totp`. Las migraciones se aplican solas al arrancar.

## 8. Copias de seguridad cifradas

La base (`/var/lib/servicio-totp/totp_soberano.db`) contiene semillas y claves de firma **cifradas**
con la llave maestra, y el archivo `.env` contiene esa llave. **Nunca guarde ambas cosas juntas ni
con la misma clave de cifrado.**

Copia consistente de la base en caliente (SQLite `VACUUM INTO`, sin detener el servicio) y cifrado
con GPG simétrico (AES-256):

```bash
FECHA=$(date -u +%Y%m%dT%H%M%SZ)
sudo -u totp node -e '
  const { DatabaseSync } = require("node:sqlite");
  const db = new DatabaseSync(process.argv[1]);
  db.exec(`VACUUM INTO '"'"'${process.argv[2]}'"'"'`);
  db.close();' /var/lib/servicio-totp/totp_soberano.db /var/lib/servicio-totp/copia-$FECHA.db
sudo gpg --batch --symmetric --cipher-algo AES256 --passphrase-file /root/.clave-copias-db \
  -o /respaldos/totp-db-$FECHA.db.gpg /var/lib/servicio-totp/copia-$FECHA.db
sudo shred -u /var/lib/servicio-totp/copia-$FECHA.db
```

- Programe la copia de la base con un temporizador `systemd` o `cron` (por ejemplo, cada hora) y conserve varias generaciones fuera del servidor.
- Copie `/etc/servicio-totp/servicio-totp.env` **por separado**, cifrado con otra frase (`/root/.clave-copias-env`) y en custodia distinta (por ejemplo, medio fuera de línea bajo responsabilidad del área de seguridad). Repita la copia cada vez que cambie (rotaciones).
- Pruebe la restauración periódicamente: descifrar con `gpg -d`, detener el servicio, sustituir la base, arrancar y comprobar `GET /admin/api/audit/verify-chain` (`intact: true`).

## 9. Rotación de llaves y secretos

| Elemento | Cómo se rota | Efecto |
| :--- | :--- | :--- |
| Clave de firma Ed25519 (JWT) | Consola, o `POST /admin/api/keys/rotate` (rol Administrador). | Se crea un `kid` nuevo; el anterior queda en `solo_verificacion` y sigue en el JWKS para validar tokens ya emitidos. Sin reinicio. |
| Llave maestra AES-256-GCM | Añada `MASTER_KEY_V2_HEX` (64 hex, `openssl rand -hex 32`), cambie `MASTER_KEY_VERSION=v2`, reinicie y haga copia del `.env`. | Lo nuevo se cifra con v2; lo existente se sigue descifrando con v1, que **no debe eliminarse** mientras queden registros cifrados con ella. Hoy no hay script de recifrado en lote (la bóveda ofrece `reencrypt` y el repositorio `recifrarSemilla`, pero falta el comando que los recorra). |
| `DAILY_IP_PEPPER_SEED` | Sustituya el valor y reinicie. | Solo cambia los `ip_hash` futuros (se pierde la correlación con el historial anterior). |
| `USER_REF_PEPPER` | **No rotar** en caliente. | Cambiarlo hace irreconocibles todos los `user_ref_hash`: todos los usuarios tendrían que volver a enrolarse. |
| `client_secret` de una app | Hoy no hay ruta de regeneración; registre una app nueva desde la consola y suspenda la anterior (`estado: suspendido`). | La app suspendida deja de autenticarse. |
| Certificado TLS | Ver sección 4. | Reinicio del servicio. |

Tras cualquier rotación, revise la bitácora en la consola (acciones `llaves.rotadas`, `app.politica_actualizada`) y verifique la cadena.
