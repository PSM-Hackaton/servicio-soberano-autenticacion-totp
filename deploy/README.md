# Despliegue como servicio (sin contenedores)

Instalador y guía de operación del Servicio Soberano TOTP en un servidor Linux con `systemd`. Todo
es propio: ni Docker, ni gestores de paquetes de Node, ni Internet, ni servicios externos. El backend
solo usa módulos nativos de Node.js 22 (`node:https`, `node:crypto`, `node:sqlite`).

```sh
sh deploy/instalar.sh                 # desde la raíz del repositorio
```

El mismo comando sirve en los dos escenarios; el modo se elige solo:

| | **Modo sistema** (servidor institucional) | **Modo usuario** (estación sin privilegios) |
| :--- | :--- | :--- |
| Se activa | ejecutando como root: `sudo sh deploy/instalar.sh` | ejecutando como usuario normal: `sh deploy/instalar.sh` |
| Identidad | usuario dedicado `totp`, sin login | el usuario que instala |
| Código (copia, solo lectura) | `/opt/servicio-totp` (root) | `~/.local/share/servicio-totp` |
| Datos SQLite | `/var/lib/servicio-totp` (0700 `totp`) | `~/.local/share/servicio-totp/datos` (0700) |
| Configuración y secretos | `/etc/servicio-totp` (0700, archivos 0600) | `~/.config/servicio-totp` (0700, archivos 0600) |
| Respaldos cifrados | `/var/backups/servicio-totp` (0700 root) | `~/.local/share/servicio-totp/respaldos` (0700) |
| Unidades | `/etc/systemd/system` | `~/.config/systemd/user` (`systemctl --user`) |
| Arranque sin sesión | siempre | requiere *linger* (ver §8) |

El servicio **nunca se ejecuta desde el repositorio**: el instalador copia `backend/`,
`authenticator-app/`, `admin-console/`, `demo-portal-tramites/`, `sdk/`, `contracts/` y `deploy/`
(sin `.env`, certificados ni bases de datos de desarrollo) y las unidades apuntan a esa copia.

## 1. Archivos de esta carpeta

| Archivo | Uso |
| :--- | :--- |
| `instalar.sh` | Instalador idempotente (POSIX `sh`, `set -eu`). Opciones: `--datos-demo`, `--ip <IP>`, `--sin-linger`. |
| `operar.sh` | Operación: `estado`, `logs`, `iniciar`, `reiniciar`, `detener`, `actualizar`, `respaldo`, `restaurar`, `rotar-llave-maestra`, `desinstalar`. |
| `comun.sh` | Rutas y funciones compartidas por los dos scripts. |
| `herramientas.mjs` | Utilidades en Node sin dependencias: espera de salud con TLS verificado, copia en caliente de SQLite (`VACUUM INTO`), comprobación de integridad y cifrado AES-256-GCM de respaldos. |
| `servicio-totp.service`, `portal-tramites.service` | Unidades del modo sistema (endurecidas: `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, `PrivateDevices`, `CapabilityBoundingSet=` vacío, filtros seccomp…). |
| `servicio-totp-respaldo.service` / `.timer` | Respaldo diario cifrado (modo sistema). |
| `usuario/*.service`, `usuario/*.timer` | Plantillas equivalentes para `systemctl --user` (`@PREFIJO@`, `@CONFIG@`, `@NODE@` se sustituyen al instalar). |

## 2. Requisitos

- Linux con `systemd` (unidades verificadas con `systemd-analyze verify`), `tar` y `openssl`.
- **Node.js 22.5 o superior** (por `node:sqlite`) instalado en `/usr` o `/usr/local`, desde los
  paquetes de la distribución o el espejo interno: `node --version`.
- Reloj sincronizado por NTP (`chrony` o `systemd-timesyncd`) con el servidor de hora institucional (§7).
- Puertos **8443/tcp** (servicio, PWA y consola) y **8444/tcp** (Portal de Trámites de demostración).

## 3. Qué hace el instalador, paso a paso

1. Comprueba Node ≥ 22.5, `openssl`, `systemd` y detecta la IP principal de la red local (primera
   IPv4 global que no sea de VPN/túnel/contenedor; se puede fijar con `--ip`).
2. Crea el usuario `totp` sin login (modo sistema) y las carpetas con permisos 0700.
3. Copia el código. Si se vuelve a ejecutar, sustituye el código y conserva datos y configuración.
4. Genera `servicio-totp.env` con `backend/scripts/generar-env.js` (llave maestra AES-256 y *peppers*
   del CSPRNG, 0600) y fija `NODE_ENV=production`, `HOST=0.0.0.0`, `PORT=8443`, `TLS_MODE=node`,
   rutas de TLS y base de datos y `TLS_CA_PUBLIC_PATH`. Un `.env` existente **no se regenera**.
5. Crea una **CA propia** (ECDSA P-256) y un certificado de servidor (TLS 1.3, 825 días) con SAN para
   `localhost`, `127.0.0.1`, `::1`, el nombre del equipo, `<nombre>.local` y **todas las IP** de
   `hostname -I`. En ejecuciones posteriores solo vuelve a emitir el certificado del servidor, con la
   misma CA, si cambiaron las IP o caduca en menos de 30 días: los teléfonos no tienen que reinstalar la CA.
6. Ejecuta la semilla (apps «Portal de Trámites» y «Reto 1», administrador inicial con TOTP) **una sola
   vez** y guarda su salida en `credenciales.txt` (0600) sin imprimirla ni enviarla al diario.
7. Configura el Portal de Trámites: `portal.env` (0600) con el `client_id`/`client_secret` de su app,
   `TOTP_BASE_URL=https://<IP>:8443`, la CA, HTTPS propio en 8444 con el mismo certificado y
   `AUTENTICADOR_URL=https://<IP>:8443/app/`; crea los ciudadanos ficticios.
8. Genera la frase de los respaldos `clave-respaldo` (384 bits, 0600).
9. Instala las unidades, las habilita, arranca y **espera `/health/ready` = 200** verificando TLS con la CA.
10. Activa el temporizador de respaldo diario (02:30 ± 15 min, `Persistent=true`).
11. Modo usuario: intenta `loginctl enable-linger` y, si no se permite, explica la consecuencia.
12. Comprueba `timedatectl show -p NTPSynchronized` y avisa si el reloj no está sincronizado.
13. Con `--datos-demo`: carga ciudadanos ficticios, tráfico legítimo, códigos erróneos y dos ataques
    simulados (`backend/scripts/datos-demo.js --sin-pagina`, HTTPS verificado con la CA) para poblar la
    consola. No escribe en disco ninguna página con semillas y no se repite en reinstalaciones.
14. Imprime el resumen: URL, instalación de la CA en teléfonos, ubicación de credenciales y comandos.

### Archivos de configuración resultantes

| Archivo (carpeta de configuración) | Contenido |
| :--- | :--- |
| `servicio-totp.env` | Variables del backend (llaves maestras, *peppers*). Lo lee el servicio vía `ENV_FILE`. |
| `portal.env` | Variables del portal (incluye su `client_secret`). Enlazado como `demo-portal-tramites/.env`. |
| `credenciales.txt` | Salida de la semilla: `client_id`/`client_secret` de las apps, contraseña, URI TOTP y códigos de recuperación del administrador. |
| `admin-qr.svg` | QR del TOTP del administrador. Escanéelo y bórrelo (`shred -u`). |
| `usuarios-portal.txt` | Ciudadanos ficticios del portal y su contraseña de demostración. |
| `clave-respaldo` | Frase de cifrado de los respaldos (se custodia aparte; no entra en los respaldos). |
| `tls/ca.crt`, `tls/ca.key` | CA propia (en modo sistema `ca.key` es de root: el servicio no la necesita). |
| `tls/servidor.crt`, `tls/servidor.key`, `tls/san.txt` | Certificado del servidor y lista de nombres/IP que cubre. |
| `instalacion.conf` | Modo, rutas, Node e IP (sin secretos); lo usa `operar.sh`. |

## 4. Instalación en el servidor institucional (modo sistema)

```sh
git clone --branch <etiqueta-aprobada> <url-del-repositorio> /root/servicio-totp-fuente
cd /root/servicio-totp-fuente
sudo sh deploy/instalar.sh
```

- Para usar el **certificado de la CA institucional** en lugar de la CA propia: genere la llave y la
  solicitud en el propio servidor, pida la firma y sustituya `/etc/servicio-totp/tls/servidor.crt`
  (con la cadena intermedia) y `servidor.key` (0600 `totp`), copie el certificado de la CA institucional
  en `tls/ca.crt` y ejecute `sudo sh /opt/servicio-totp/deploy/operar.sh reiniciar`.
  ```sh
  sudo openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out /etc/servicio-totp/tls/servidor.key
  sudo openssl req -new -key /etc/servicio-totp/tls/servidor.key -subj "/O=<Institución>/CN=totp.<dominio>" \
    -addext "subjectAltName=DNS:totp.<dominio>" -out /root/servidor.csr
  ```
  Si después vuelve a ejecutar el instalador, no tocará ese certificado mientras `tls/san.txt` coincida
  con la lista de la máquina (deje en él la línea que imprime el instalador) y no esté por caducar.
- Ajuste `JWT_ISSUER` en `/etc/servicio-totp/servicio-totp.env` al nombre institucional
  (`https://totp.<dominio>`), reinicie y vuelva a ejecutar el instalador para propagar el emisor al portal.
- El Portal de Trámites es un integrador **de demostración**: en producción puede detenerse y
  deshabilitarse (`sudo systemctl disable --now portal-tramites`) sin afectar al servicio.

## 5. Instalación en una estación sin privilegios (modo usuario)

```sh
cd servicio-soberano-autenticacion-totp
sh deploy/instalar.sh --datos-demo
```

Se gestiona con `systemctl --user status servicio-totp portal-tramites` o con `operar.sh`. En modo
usuario systemd no puede crear espacios de nombres de montaje, así que `ProtectSystem`, `ProtectHome`
y `PrivateTmp` no tendrían efecto; las unidades usan lo que sí funciona sin privilegios:
`NoNewPrivileges`, filtros seccomp (`SystemCallFilter=@system-service`, sin `@privileged` ni
`@resources`), `RestrictAddressFamilies`, `RestrictNamespaces`, `LockPersonality`, `UMask=0077`,
`MemoryMax`, `TasksMax`, `LimitNOFILE` y `Restart=on-failure` (reinicio en 3 s). El aislamiento completo
del sistema de archivos requiere el modo sistema.

## 6. Acceso desde la red local y teléfonos

| URL | Qué es |
| :--- | :--- |
| `https://<IP>:8443/app/` | App autenticadora (PWA). «Añadir a pantalla de inicio» en el teléfono. |
| `https://<IP>:8443/consola/` | Consola administrativa (usuario, contraseña y TOTP de `credenciales.txt`). |
| `https://<IP>:8444/` | Portal de Trámites de demostración. |
| `https://<IP>:8443/health/ready` | Salud (200 si la base responde). |
| `https://<IP>:8443/ca.crt` | Certificado **público** de la CA propia (`application/x-x509-ca-cert`, solo lectura). |

**Confiar en la CA** (una vez por dispositivo; compruebe antes la huella SHA-256 que imprime el instalador):

- **Android**: abra `https://<IP>:8443/ca.crt`, acepte el aviso del navegador esa única vez, y en
  Ajustes → Seguridad → Cifrado y credenciales → Instalar un certificado → **Certificado de CA**,
  elija el archivo descargado.
- **iOS**: abra la misma URL en Safari → Ajustes → Perfil descargado → Instalar; después General →
  Información → Ajustes de confianza de certificados → active la CA.
- **Equipos**: importe `tls/ca.crt` (por archivo o USB) en el almacén de autoridades del navegador o
  del sistema (`/usr/local/share/ca-certificates/` + `update-ca-certificates`).

La llave privada de la CA nunca se sirve: `/ca.crt` solo entrega el archivo de `TLS_CA_PUBLIC_PATH`
y el backend se niega a ofrecerlo si contiene una llave.

### Cortafuegos recomendado (solo red interna)

```sh
# ufw (ajuste 172.20.0.0/16 a la red interna de la institución)
sudo ufw allow from 172.20.0.0/16 to any port 8443 proto tcp
sudo ufw allow from 172.20.0.0/16 to any port 8444 proto tcp
# nftables equivalente
#   tcp dport { 8443, 8444 } ip saddr 172.20.0.0/16 accept
#   tcp dport { 8443, 8444 } drop
```

No publique 8443/8444 hacia Internet. `/metrics` solo responde sin sesión desde la propia máquina.

## 7. Hora (NTP institucional)

TOTP depende de la hora: con ventana ±1 se toleran unos 30 s de desfase. El instalador y
`operar.sh estado` muestran `NTPSynchronized`. Con chrony:

```sh
sudo apt install chrony
# /etc/chrony/chrony.conf: comente los «pool» públicos y añada el servidor institucional
#   server ntp.<dominio-institucional> iburst
#   makestep 1.0 3
sudo systemctl restart chrony
chronyc tracking && chronyc sources -v
```

Opcional: `CLOCK_REFERENCE_URL` (servidor HTTP interno) para que el servicio mida el desfase cada
10 minutos y lo publique en `/metrics` (`totp_clock_skew_ms`) y en la consola.

## 8. Operación continua en modo usuario (*linger*)

Sin *linger*, el gestor `systemd --user` vive solo mientras el usuario tenga una sesión: al cerrar la
última se detienen los servicios, y tras reiniciar el equipo no arrancan hasta que el usuario inicia
sesión. El instalador ejecuta `loginctl enable-linger`; si la política del equipo no lo permite, un
administrador puede activarlo con `sudo loginctl enable-linger <usuario>`. Para un servicio 24×7
institucional use el modo sistema. Comprobación: `loginctl show-user $USER -p Linger`.

## 9. Operación diaria

```sh
OP="sh ~/.local/share/servicio-totp/deploy/operar.sh"     # modo sistema: sudo sh /opt/servicio-totp/deploy/operar.sh
$OP estado          # unidades, salud, portal, certificado, NTP, linger, respaldos y próximo respaldo
$OP logs -f         # diario de servicio, portal y respaldos (no contiene secretos ni IP en claro)
$OP reiniciar       # reinicia y espera la salud de ambos
$OP detener         # detiene (siguen habilitados); «iniciar» los vuelve a levantar
```

## 10. Respaldos y restauración

`operar.sh respaldo` (y el temporizador diario) hace:

1. Copia **consistente en caliente** de la base con `VACUUM INTO` (sin detener el servicio), con la
   identidad del servicio, y `PRAGMA integrity_check`.
2. Empaqueta la base, la configuración (llaves maestras, credenciales, certificados) y los ciudadanos
   del portal. **No incluye `clave-respaldo`.**
3. Cifra con **AES-256-GCM** (llave derivada de `clave-respaldo` con scrypt, sal e IV aleatorios,
   cabecera autenticada) en `servicio-totp-<fecha>.stotp` (0600) y conserva las **7** copias más recientes.

```sh
$OP respaldo
$OP restaurar <archivo.stotp> --destino /ruta/prueba   # descifra, comprueba y extrae; la instancia no se toca
$OP restaurar <archivo.stotp>                         # sustituye la base (pide escribir RESTAURAR)
$OP restaurar <archivo.stotp> --con-configuracion     # además restaura la configuración (llave maestra incluida)
```

La restauración en sitio hace antes un respaldo del estado actual, detiene los servicios, deja la base
anterior en `datos/antes-de-restaurar-<fecha>/`, arranca y espera la salud. Tras restaurar, verifique la
cadena de auditoría en la consola (Bitácora → Verificar cadena).

Una base restaurada solo se descifra con la llave maestra con la que se cifró: si se ha rotado la llave
después del respaldo, use `--con-configuracion` o conserve las llaves antiguas en el `.env`.

**Custodia**: copie periódicamente los `.stotp` fuera del servidor y guarde `clave-respaldo` en un
medio distinto, bajo responsabilidad del área de seguridad. Quien tenga ambos tiene la base y la
llave maestra. Pruebe la restauración con `--destino` al menos una vez al mes.

## 11. Actualización

```sh
cd <repositorio> && git pull   # o git checkout <nueva-etiqueta>
$OP actualizar                 # respaldo previo → copia del código → reinicio → salud
$OP actualizar --desde /otra/ruta/del/repositorio
```

Datos y configuración se conservan; las migraciones de la base se aplican solas al arrancar. Si la
versión nueva no responde en `/health/ready`, `actualizar` restaura el código anterior y reinicia.
Para aplicar cambios en las unidades o en el certificado, ejecute de nuevo `deploy/instalar.sh`.

## 12. Rotación de llaves y secretos

| Elemento | Cómo se rota | Efecto |
| :--- | :--- | :--- |
| Llave maestra AES-256-GCM | `$OP rotar-llave-maestra`: respaldo previo, añade `MASTER_KEY_V<n+1>_HEX` (CSPRNG), cambia `MASTER_KEY_VERSION`, detiene, recifra en una transacción todas las semillas y claves de firma (`backend/scripts/rotar-llave-maestra.js`), arranca y verifica la salud. | Si el recifrado falla, se restaura el `.env` anterior y no se modifica la base. La llave anterior queda en el archivo: retírela solo tras comprobar y respaldar. |
| Clave de firma Ed25519 (JWT) | Consola, o `POST /admin/api/keys/rotate` (rol Administrador). | `kid` nuevo; el anterior queda solo para verificación y sigue en el JWKS. Sin reinicio. |
| `DAILY_IP_PEPPER_SEED` | Sustituir en el `.env` y `$OP reiniciar`. | Solo cambian los `ip_hash` futuros. |
| `USER_REF_PEPPER` | **No rotar** en caliente. | Haría irreconocibles todos los enrolamientos. |
| `client_secret` de una app | Registrar una app nueva en la consola y suspender la anterior. | La app suspendida deja de autenticarse. |
| Certificado del servidor | Automático al reinstalar si cambian las IP o caduca en < 30 días; o sustituir los archivos y `$OP reiniciar`. | Misma CA: los dispositivos no tienen que reinstalarla. |
| Frase de respaldos | Sustituir `clave-respaldo` (`node deploy/herramientas.mjs aleatorio 48 base64url`). | Los respaldos anteriores siguen necesitando la frase antigua: consérvela mientras existan. |

Tras cualquier rotación, revise la bitácora en la consola y verifique la cadena.

## 13. Desinstalación

```sh
$OP desinstalar      # pide escribir DESINSTALAR
```

Detiene y deshabilita las unidades, las elimina, borra el código, los datos y la configuración (y, en
modo sistema, el usuario `totp`). **Conserva** los respaldos y `clave-respaldo`.

## 14. Verificación posterior a la instalación

```sh
IP=<IP del servidor>; CA=<carpeta de configuración>/tls/ca.crt
systemctl --user status servicio-totp portal-tramites          # (modo sistema: sin --user)
curl --cacert $CA https://$IP:8443/health/ready                 # {"status":"ok",…,"database":"ok"}
curl --cacert $CA -o /dev/null -w '%{http_code}\n' https://$IP:8443/app/       # 200
curl --cacert $CA -o /dev/null -w '%{http_code}\n' https://$IP:8443/consola/   # 200
curl --cacert $CA -o /dev/null -w '%{http_code} %{content_type}\n' https://$IP:8443/ca.crt   # 200 application/x-x509-ca-cert
curl --cacert $CA -o /dev/null -w '%{http_code}\n' https://$IP:8444/           # 303 (al formulario de acceso)
openssl s_client -connect $IP:8443 -tls1_3 -CAfile $CA </dev/null | grep -E 'Protocol|Verify return'   # TLSv1.3, 0 (ok)
openssl s_client -connect $IP:8443 -tls1_2 </dev/null    # debe fallar: protocol version
# Reinicio automático: systemd vuelve a levantar el proceso y /health/ready responde en ~4 s
kill -9 "$(systemctl --user show -p MainPID --value servicio-totp)"
$OP estado && $OP respaldo && $OP restaurar <último .stotp> --destino /tmp/prueba-restauracion
```

Resultado de la verificación realizada el 26-11-2026 en una estación Ubuntu 26.04.1 LTS (systemd 259, Node 22.22.1,
modo usuario): ambos servicios activos con linger; tras `kill -9` systemd relanzó el backend y
`/health/ready` volvió a 200 en 3,7 s; desde la IP de red, `/health/ready`, `/app/`, `/consola/` y
`/ca.crt` → 200 y el portal → 303, TLS 1.3 (`TLS_AES_256_GCM_SHA384`) verificado con la CA y TLS 1.2
rechazado; flujo enrolar → activar → verificar → validar token por HTTPS (y reutilización del token
rechazada con `jti_consumido`); respaldo cifrado, rotación a 7 copias, restauración sobre una copia
arrancada en otro puerto con la misma clave de firma activa, rotación de la llave maestra (15 semillas
y 1 clave de firma recifradas) y actualización con verificación de salud.
