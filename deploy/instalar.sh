#!/bin/sh
# Instalador del Servicio Soberano de Autenticación TOTP como servicio systemd.
#
#   sh deploy/instalar.sh [--datos-demo] [--ip <IP>] [--sin-linger]
#
# Detecta el modo automáticamente:
#   - como root (sudo): MODO SISTEMA — usuario dedicado «totp» sin login, código en /opt/servicio-totp,
#     datos en /var/lib/servicio-totp (0700), configuración en /etc/servicio-totp (0600), unidades del
#     sistema endurecidas y respaldo diario cifrado en /var/backups/servicio-totp.
#   - sin root: MODO USUARIO — código en ~/.local/share/servicio-totp, datos en .../datos (0700),
#     configuración en ~/.config/servicio-totp (0600) y unidades «systemctl --user».
#
# Es idempotente: volver a ejecutarlo actualiza el código y las unidades, regenera el certificado del
# servidor solo si cambiaron las IP o está por caducar, y nunca toca secretos, datos ni credenciales.
#
# Opciones:
#   --datos-demo   tras arrancar, carga ciudadanos ficticios, tráfico y ataques simulados para poblar la
#                  consola (no escribe en disco ninguna página con semillas). Solo una vez por instalación.
#   --ip <IP>      IP de la red local que se anuncia en las URL (por defecto, la de la interfaz principal).
#   --sin-linger   no intenta «loginctl enable-linger» (modo usuario).

set -eu
umask 077

REPO=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
# shellcheck source=deploy/comun.sh
. "$REPO/deploy/comun.sh"

DATOS_DEMO=0
IP_FORZADA=''
LINGER=1
while [ $# -gt 0 ]; do
  case "$1" in
    --datos-demo) DATOS_DEMO=1 ;;
    --ip) [ $# -ge 2 ] || fallo "--ip necesita una dirección"; IP_FORZADA=$2; shift ;;
    --sin-linger) LINGER=0 ;;
    -h|--ayuda|--help) sed -n '2,22p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) fallo "Opción desconocida: $1 (use --ayuda)" ;;
  esac
  shift
done

definir_rutas
printf 'Servicio Soberano de Autenticación TOTP — instalación en modo %s\n' "$MODO"
printf '  origen del código:  %s\n  instalación:        %s\n  datos:              %s\n  configuración:      %s\n' \
  "$REPO" "$PREFIJO" "$DATOS" "$CONFIG"

# ------------------------------------------------------------------ 1. requisitos
paso "Comprobando requisitos"
NODE=$(command -v node || true)
[ -n "$NODE" ] || fallo "No se encontró Node.js. Instale Node.js 22.5 o superior (paquete del sistema o espejo institucional)."
NODE=$(readlink -f "$NODE" 2>/dev/null || printf '%s' "$NODE")
"$NODE" -e '
  const [ma, mi] = process.versions.node.split(".").map(Number);
  if (ma < 22 || (ma === 22 && mi < 5)) { console.error("Node.js " + process.versions.node + " es anterior a 22.5"); process.exit(1); }
' || fallo "Se necesita Node.js 22.5 o superior (node:sqlite)."
ok "Node.js $("$NODE" --version) ($NODE)"
command -v openssl >/dev/null 2>&1 || fallo "No se encontró openssl (necesario para la CA y el certificado del servidor)."
ok "$(openssl version)"
command -v systemctl >/dev/null 2>&1 || fallo "No se encontró systemctl: este instalador requiere systemd."
command -v tar >/dev/null 2>&1 || fallo "No se encontró tar."
if [ "$MODO" = usuario ]; then
  systemctl --user show-environment >/dev/null 2>&1 || fallo "No hay gestor «systemctl --user» en esta sesión (inicie sesión gráfica o por SSH con el mismo usuario)."
  ok "systemd de usuario disponible"
else
  # El usuario del servicio no puede entrar en carpetas personales: un Node.js instalado en la carpeta de
  # root o en la de quien ejecuta sudo (nvm, asdf…) no arrancaría. Se compara con esas carpetas reales.
  for CASA in "$HOME" "$(getent passwd root | cut -d: -f6)" ${SUDO_USER:+"$(getent passwd "$SUDO_USER" | cut -d: -f6)"}; do
    [ -n "$CASA" ] && [ "$CASA" != / ] || continue
    case "$NODE" in "$CASA"/*) fallo "Node.js está en $NODE, dentro de $CASA y fuera del alcance del usuario del servicio. Instálelo en /usr o /usr/local." ;; esac
  done
  ok "systemd del sistema disponible"
fi
IP=${IP_FORZADA:-$(ip_principal)}
SAN=$(lista_san "$IP")
ok "IP principal de la red local: $IP"
info "Nombres e IP del certificado: $SAN"

# ------------------------------------------------------------------ 2. usuario y carpetas
paso "Preparando usuario y carpetas"
if [ "$MODO" = sistema ]; then
  if id "$USUARIO_SERVICIO" >/dev/null 2>&1; then
    ok "El usuario «$USUARIO_SERVICIO» ya existe"
  else
    SIN_LOGIN=/usr/sbin/nologin; [ -x "$SIN_LOGIN" ] || SIN_LOGIN=/sbin/nologin
    useradd --system --user-group --home-dir "$DATOS" --no-create-home --shell "$SIN_LOGIN" "$USUARIO_SERVICIO"
    ok "Creado el usuario de sistema «$USUARIO_SERVICIO» (sin login)"
  fi
  install -d -m 0755 -o root -g root "$PREFIJO"
  install -d -m 0700 -o "$USUARIO_SERVICIO" -g "$USUARIO_SERVICIO" "$DATOS" "$DATOS/portal" "$CONFIG" "$TLS"
  install -d -m 0700 -o root -g root "$RESPALDOS"
else
  mkdir -p "$PREFIJO" "$DATOS/portal" "$CONFIG" "$TLS" "$RESPALDOS" "$DIR_UNIDADES"
  chmod 0700 "$DATOS" "$DATOS/portal" "$CONFIG" "$TLS" "$RESPALDOS"
  chmod 0755 "$PREFIJO"
fi
ok "Datos $DATOS (0700) · configuración $CONFIG (0700) · respaldos $RESPALDOS (0700)"

# ------------------------------------------------------------------ 3. código
paso "Copiando el código a $PREFIJO"
SERVICIO_ACTIVO=0
if ctl is-active --quiet servicio-totp.service 2>/dev/null; then SERVICIO_ACTIVO=1; fi
copiar_codigo "$REPO"
confirmar_codigo
ok "Código copiado (versión $(sed -n 's/^version=//p' "$PREFIJO/VERSION")); el servicio no usa el repositorio"

# ------------------------------------------------------------------ 4. configuración del servicio
paso "Configuración del servicio ($ENV_SERVICIO)"
if [ -f "$ENV_SERVICIO" ]; then
  ok "Ya existe: se conservan sus secretos (solo se completan variables que falten)"
else
  "$NODE" "$PREFIJO/backend/scripts/generar-env.js" --salida "$ENV_SERVICIO" >/dev/null
  fijar_var "$ENV_SERVICIO" NODE_ENV production
  fijar_var "$ENV_SERVICIO" HOST 0.0.0.0
  fijar_var "$ENV_SERVICIO" PORT "$PUERTO_SERVICIO"
  fijar_var "$ENV_SERVICIO" TLS_MODE node
  ok "Creado con llave maestra AES-256 y peppers del CSPRNG (0600)"
fi
asegurar_var "$ENV_SERVICIO" NODE_ENV production
asegurar_var "$ENV_SERVICIO" HOST 0.0.0.0
asegurar_var "$ENV_SERVICIO" PORT "$PUERTO_SERVICIO"
asegurar_var "$ENV_SERVICIO" TLS_MODE node
fijar_var "$ENV_SERVICIO" TLS_CERT_PATH "$TLS/servidor.crt"
fijar_var "$ENV_SERVICIO" TLS_KEY_PATH "$TLS/servidor.key"
fijar_var "$ENV_SERVICIO" TLS_CA_PUBLIC_PATH "$CA"
fijar_var "$ENV_SERVICIO" SQLITE_DB_PATH "$BASE_DATOS"
fijar_var "$ENV_SERVICIO" ADMIN_QR_PATH "$CONFIG/admin-qr.svg"
info "HOST=$(leer_var "$ENV_SERVICIO" HOST) PORT=$(leer_var "$ENV_SERVICIO" PORT) TLS_MODE=$(leer_var "$ENV_SERVICIO" TLS_MODE) NODE_ENV=$(leer_var "$ENV_SERVICIO" NODE_ENV)"
PUERTO_SERVICIO=$(leer_var "$ENV_SERVICIO" PORT)

# ------------------------------------------------------------------ 5. certificados
paso "CA propia y certificado del servidor ($TLS)"
SAN_ANTERIOR=$(cat "$TLS/san.txt" 2>/dev/null || true)
REGENERAR=0
if [ ! -f "$TLS/servidor.crt" ] || [ ! -f "$CA" ]; then
  REGENERAR=1
elif [ "$SAN_ANTERIOR" != "$SAN" ]; then
  REGENERAR=1; info "Cambiaron los nombres o IP de la máquina: se emite un certificado nuevo con la misma CA"
elif ! openssl x509 -in "$TLS/servidor.crt" -noout -checkend 2592000 >/dev/null 2>&1; then
  REGENERAR=1; info "El certificado caduca en menos de 30 días: se renueva"
fi
if [ "$REGENERAR" = 1 ]; then
  "$NODE" "$PREFIJO/backend/scripts/certificados.js" --carpeta "$TLS" --nombre servidor --san "$SAN" --solo-servidor --forzar >/dev/null
  printf '%s\n' "$SAN" > "$TLS/san.txt"
  ok "Certificado emitido (TLS 1.3, ECDSA P-256, 825 días) para: $SAN"
else
  ok "El certificado vigente ya cubre: $SAN"
fi
chmod 0644 "$CA"
chmod 0600 "$TLS/ca.key" "$TLS/servidor.key"
if [ "$MODO" = sistema ]; then
  chown -R "$USUARIO_SERVICIO:$USUARIO_SERVICIO" "$CONFIG"
  chown root:root "$TLS/ca.key"   # la llave de la CA no la necesita el servicio
fi
info "Huella SHA-256 de la CA: $(openssl x509 -in "$CA" -noout -fingerprint -sha256 | sed 's/^.*=//')"

# ------------------------------------------------------------------ 6. datos iniciales
paso "Datos iniciales (apps integradoras y administrador)"
if [ -f "$CREDENCIALES" ]; then
  ok "Ya se ejecutó la semilla: credenciales en $CREDENCIALES"
else
  _tmp="$CONFIG/.semilla.$$"
  _err="$CONFIG/.semilla-errores.$$"
  if ! como_servicio env NODE_ENV=production ENV_FILE="$ENV_SERVICIO" \
      "$NODE" --disable-warning=ExperimentalWarning "$PREFIJO/backend/scripts/semilla.js" > "$_tmp" 2> "$_err"; then
    cat "$_err" >&2; rm -f "$_tmp" "$_err"
    fallo "La semilla falló."
  fi
  {
    printf '# Credenciales iniciales del Servicio Soberano TOTP (%s)\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf '# Archivo 0600. Entregue cada client_secret por un canal seguro, cargue la URI TOTP del\n'
    printf '# administrador en la app autenticadora y guarde los códigos de recuperación fuera del servidor.\n'
    cat "$_tmp"
  } > "$CREDENCIALES"
  rm -f "$_tmp" "$_err"
  [ "$MODO" = sistema ] && chown "$USUARIO_SERVICIO:$USUARIO_SERVICIO" "$CREDENCIALES"
  grep -q 'ya existía' "$CREDENCIALES" && aviso "Algunas apps ya existían en la base: sus client_secret no se pueden recuperar."
  ok "Semilla ejecutada; salida (secretos) guardada en $CREDENCIALES (0600), sin mostrarla"
fi

# Credenciales de una app de la semilla: credencial_app "<nombre>" client_id|client_secret
credencial_app() {
  awk -v app="  $1" -v campo="$2:" '
    $0 == app { dentro = 1; next }
    dentro && $1 == campo { print $2; exit }
    dentro && /^  [^ ]/ { dentro = 0 }' "$CREDENCIALES"
}

# ------------------------------------------------------------------ 7. portal de trámites
paso "Portal de Trámites (integrador de demostración, HTTPS $PUERTO_PORTAL)"
EMISOR=$(leer_var "$ENV_SERVICIO" JWT_ISSUER)
if [ ! -f "$ENV_PORTAL" ]; then
  ID_PORTAL=$(credencial_app "Portal de Trámites" client_id)
  SECRETO_PORTAL=$(credencial_app "Portal de Trámites" client_secret)
  case "$SECRETO_PORTAL" in ''|'(ya') fallo "No hay client_secret de «Portal de Trámites» en $CREDENCIALES: registre una app en la consola y cree $ENV_PORTAL a mano." ;; esac
  # Derivación del user_ref desde la cédula (modo hmac): permite buscar ciudadanos por cédula en la consola.
  SECRETO_CEDULA_PORTAL=$(credencial_app "Portal de Trámites" cedula_secreto)
  PREFIJO_CEDULA_PORTAL=$(credencial_app "Portal de Trámites" cedula_prefijo)
  case "$SECRETO_CEDULA_PORTAL" in '(ya') SECRETO_CEDULA_PORTAL= ;; esac
  [ -n "$SECRETO_CEDULA_PORTAL" ] || aviso "Sin cedula_secreto de «Portal de Trámites»: el portal usará un secreto local y la consola no buscará por cédula."
  cat > "$ENV_PORTAL" <<EOF
# Portal de Trámites (demo) — generado por deploy/instalar.sh. Archivo 0600: contiene el client_secret.
PORTAL_HOST=0.0.0.0
PORTAL_PUERTO=$PUERTO_PORTAL
PORTAL_TLS_CERT=$TLS/servidor.crt
PORTAL_TLS_KEY=$TLS/servidor.key
TOTP_BASE_URL=https://$IP:$PUERTO_SERVICIO
TOTP_CLIENT_ID=$ID_PORTAL
TOTP_CLIENT_SECRET=$SECRETO_PORTAL
TOTP_CA_PATH=$CA
TOTP_ISSUER=$EMISOR
TOTP_AUDIENCE=
TOTP_TIMEOUT_MS=3000
AUTENTICADOR_URL=https://$IP:$PUERTO_SERVICIO/app/
PORTAL_ETIQUETA_CUENTA=Portal de Trámites
PORTAL_TRAZAS=1
PORTAL_SESION_MINUTOS=15
PORTAL_USUARIOS=$DATOS/portal/usuarios.json
PORTAL_CONFIAR_X_FORWARDED_FOR=0
TOTP_CEDULA_SECRETO=$SECRETO_CEDULA_PORTAL
TOTP_CEDULA_PREFIJO=${PREFIJO_CEDULA_PORTAL:-ptd-}
EOF
  chmod 0600 "$ENV_PORTAL"
  ok "Creado $ENV_PORTAL (0600) con las credenciales de la app «Portal de Trámites»"
else
  fijar_var "$ENV_PORTAL" TOTP_BASE_URL "https://$IP:$PUERTO_SERVICIO"
  fijar_var "$ENV_PORTAL" AUTENTICADOR_URL "https://$IP:$PUERTO_SERVICIO/app/"
  fijar_var "$ENV_PORTAL" TOTP_ISSUER "$EMISOR"
  ok "Ya existía $ENV_PORTAL: se actualizaron las URL a https://$IP:$PUERTO_SERVICIO"
fi
[ "$MODO" = sistema ] && chown "$USUARIO_SERVICIO:$USUARIO_SERVICIO" "$ENV_PORTAL"
if [ -f "$DATOS/portal/usuarios.json" ]; then
  ok "Los ciudadanos de demostración ya existen (se conserva su estado de enrolamiento)"
else
  como_servicio "$NODE" "$PREFIJO/demo-portal-tramites/scripts/crear-usuarios.js" --archivo "$DATOS/portal/usuarios.json" > "$CONFIG/usuarios-portal.txt"
  chmod 0600 "$CONFIG/usuarios-portal.txt"
  [ "$MODO" = sistema ] && chown "$USUARIO_SERVICIO:$USUARIO_SERVICIO" "$CONFIG/usuarios-portal.txt"
  ok "Ciudadanos ficticios creados (lista y contraseñas de demo en $CONFIG/usuarios-portal.txt)"
fi

# ------------------------------------------------------------------ 8. clave de respaldos
paso "Clave de los respaldos cifrados"
if [ -f "$CLAVE_RESPALDO" ]; then
  ok "Ya existe $CLAVE_RESPALDO"
else
  "$NODE" "$PREFIJO/deploy/herramientas.mjs" aleatorio 48 base64url > "$CLAVE_RESPALDO"
  chmod 0600 "$CLAVE_RESPALDO"
  [ "$MODO" = sistema ] && chown root:root "$CLAVE_RESPALDO"
  ok "Generada $CLAVE_RESPALDO (0600, 384 bits del CSPRNG). Guarde una copia fuera del servidor: sin ella no se pueden restaurar los respaldos."
fi

{
  printf '# Instalación del Servicio Soberano TOTP (generado por deploy/instalar.sh; sin secretos)\n'
  printf 'MODO=%s\nPREFIJO=%s\nDATOS=%s\nCONFIG=%s\nRESPALDOS=%s\nNODE=%s\nORIGEN=%s\nIP_PRINCIPAL=%s\nINSTALADO=%s\n' \
    "$MODO" "$PREFIJO" "$DATOS" "$CONFIG" "$RESPALDOS" "$NODE" "$REPO" "$IP" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
} > "$CONF_INSTALACION"
chmod 0600 "$CONF_INSTALACION"

# ------------------------------------------------------------------ 9. unidades systemd
paso "Unidades systemd ($DIR_UNIDADES)"
instalar_unidad() { # <plantilla> <destino>
  sed -e "s|@NODE@|$NODE|g" -e "s|@PREFIJO@|$PREFIJO|g" -e "s|@CONFIG@|$CONFIG|g" -e "s|@DATOS@|$DATOS|g" \
      -e "s|@RESPALDOS@|$RESPALDOS|g" -e "s|/usr/bin/node |$NODE |g" "$1" > "$2.tmp"
  chmod 0644 "$2.tmp"
  mv -f "$2.tmp" "$2"
  info "$(basename "$2")"
}
if [ "$MODO" = sistema ]; then ORIGEN_UNIDADES="$PREFIJO/deploy"; else ORIGEN_UNIDADES="$PREFIJO/deploy/usuario"; fi
for u in servicio-totp.service portal-tramites.service servicio-totp-respaldo.service servicio-totp-respaldo.timer; do
  instalar_unidad "$ORIGEN_UNIDADES/$u" "$DIR_UNIDADES/$u"
done
ctl daemon-reload
if command -v systemd-analyze >/dev/null 2>&1; then
  if [ "$MODO" = sistema ]; then _va=''; else _va='--user'; fi
  # shellcheck disable=SC2086
  systemd-analyze $_va verify "$DIR_UNIDADES/servicio-totp.service" "$DIR_UNIDADES/portal-tramites.service" \
    "$DIR_UNIDADES/servicio-totp-respaldo.service" "$DIR_UNIDADES/servicio-totp-respaldo.timer" 2>&1 \
    | grep -v -e '^$' -e 'Unknown key' -e 'network-online.target' | sed 's/^/    /' || true
fi
ok "Unidades instaladas y systemd recargado"

# ------------------------------------------------------------------ 10. arranque
paso "Arrancando los servicios"
ctl enable servicio-totp.service portal-tramites.service servicio-totp-respaldo.timer >/dev/null 2>&1
if [ "$SERVICIO_ACTIVO" = 1 ]; then ctl restart servicio-totp.service; else ctl start servicio-totp.service; fi
esperar_servicio 40 >/dev/null || { jctl -u servicio-totp -n 30 --no-pager >&2 || true; fallo "El servicio no quedó listo."; }
ok "servicio-totp activo: https://127.0.0.1:$PUERTO_SERVICIO/health/ready → 200"
ctl restart portal-tramites.service
esperar_portal 40 >/dev/null || { jctl -u portal-tramites -n 30 --no-pager >&2 || true; fallo "El portal no quedó listo."; }
ok "portal-tramites activo en el puerto $PUERTO_PORTAL"
ctl start servicio-totp-respaldo.timer
ok "Respaldo diario programado: $(ctl list-timers servicio-totp-respaldo.timer --no-pager 2>/dev/null | sed -n 2p | awk '{print $1, $2, $3}')"

# ------------------------------------------------------------------ 11. operación continua (linger)
if [ "$MODO" = usuario ]; then
  paso "Arranque sin sesión abierta (linger)"
  if [ "$(loginctl show-user "$USUARIO_SERVICIO" -p Linger --value 2>/dev/null || true)" = yes ]; then
    ok "Linger ya activo: los servicios arrancan con el equipo y siguen al cerrar la sesión"
  elif [ "$LINGER" = 1 ] && loginctl enable-linger "$USUARIO_SERVICIO" >/dev/null 2>&1 \
      && [ "$(loginctl show-user "$USUARIO_SERVICIO" -p Linger --value 2>/dev/null || true)" = yes ]; then
    ok "Linger activado: los servicios arrancan con el equipo y siguen al cerrar la sesión"
  else
    aviso "No se pudo activar «linger» (requiere permiso de un administrador: sudo loginctl enable-linger $USUARIO_SERVICIO)."
    aviso "Consecuencia: los servicios solo funcionan mientras $USUARIO_SERVICIO tenga una sesión abierta; al cerrar la"
    aviso "última sesión systemd los detiene y tras reiniciar el equipo no arrancan hasta que el usuario inicie sesión."
    aviso "Para operación continua 24×7 use el modo sistema (sudo sh deploy/instalar.sh) o pida activar linger."
  fi
fi

# ------------------------------------------------------------------ 12. hora
paso "Sincronización horaria (TOTP depende de la hora)"
NTP=$(timedatectl show -p NTPSynchronized --value 2>/dev/null || echo desconocido)
if [ "$NTP" = yes ]; then
  ok "Reloj sincronizado por NTP ($(timedatectl show -p TimeUSec --value 2>/dev/null || date))"
else
  aviso "El reloj NO figura como sincronizado (NTPSynchronized=$NTP). Configure chrony con el NTP institucional:"
  aviso "con más de ±30 s de desfase los códigos TOTP se rechazan. Ver deploy/README.md, apartado «Hora»."
fi

# ------------------------------------------------------------------ 13. datos de demostración
if [ "$DATOS_DEMO" = 1 ]; then
  paso "Datos de demostración para la consola"
  if [ -f "$DATOS/.datos-demo-cargados" ]; then
    ok "Ya se cargaron en esta instalación ($(cat "$DATOS/.datos-demo-cargados")): no se repiten"
  else
    ID_DEMO=$(credencial_app "Agente Evaluador (Reto 3)" client_id)
    SECRETO_DEMO=$(credencial_app "Agente Evaluador (Reto 3)" client_secret)
    case "$SECRETO_DEMO" in ''|'(ya') aviso "No hay client_secret de «Agente Evaluador (Reto 3)» en $CREDENCIALES: se omiten los datos de demostración." ;;
      *)
        info "Enrolando ciudadanos ficticios y simulando tráfico y ataques (≈ 40 s)…"
        "$NODE" --disable-warning=ExperimentalWarning "$PREFIJO/backend/scripts/datos-demo.js" \
          --url "https://127.0.0.1:$PUERTO_SERVICIO" --ca "$CA" --client-id "$ID_DEMO" --client-secret "$SECRETO_DEMO" \
          --sin-pagina | sed 's/^/    /'
        date -u +%Y-%m-%dT%H:%M:%SZ > "$DATOS/.datos-demo-cargados"
        [ "$MODO" = sistema ] && chown "$USUARIO_SERVICIO:$USUARIO_SERVICIO" "$DATOS/.datos-demo-cargados"
        ok "Consola poblada (sin páginas con semillas en disco)" ;;
    esac
  fi
fi

# ------------------------------------------------------------------ resumen
if [ "$MODO" = sistema ]; then OPERAR="sudo sh $PREFIJO/deploy/operar.sh"; else OPERAR="sh $PREFIJO/deploy/operar.sh"; fi
cat <<EOF

========================================================================================
 Servicio Soberano TOTP instalado y en marcha (modo $MODO)
========================================================================================
 Desde cualquier equipo o teléfono de la red local:
   App autenticadora (PWA)   https://$IP:$PUERTO_SERVICIO/app/
   Consola administrativa    https://$IP:$PUERTO_SERVICIO/consola/
   Portal de Trámites (demo) https://$IP:$PUERTO_PORTAL/
   Salud                     https://$IP:$PUERTO_SERVICIO/health/ready
   Certificado de la CA      https://$IP:$PUERTO_SERVICIO/ca.crt

 Confiar en la CA propia (una vez por dispositivo):
   Teléfono: abra https://$IP:$PUERTO_SERVICIO/ca.crt, acepte el aviso del navegador esa única vez y
     instale el archivo descargado. Android: Ajustes → Seguridad → Cifrado y credenciales → Instalar
     un certificado → Certificado de CA. iOS: Ajustes → Perfil descargado → Instalar, y después
     General → Información → Ajustes de confianza de certificados → activar la CA.
   Equipos: importe $CA como autoridad (o cópielo por archivo/USB).
   Compruebe la huella SHA-256 antes de confiar:
     $(openssl x509 -in "$CA" -noout -fingerprint -sha256 | sed 's/^.*=//')

 Credenciales (archivos 0600; no se muestran aquí):
   $CREDENCIALES        client_id/secret de las apps y administrador inicial
   $CONFIG/admin-qr.svg         QR del TOTP del administrador (bórrelo tras escanearlo)
   $CONFIG/usuarios-portal.txt  ciudadanos ficticios del portal
   $CLAVE_RESPALDO       frase de los respaldos (custodie una copia fuera del servidor)

 Operación:
   $OPERAR estado | logs [-f] | reiniciar | detener | iniciar
   $OPERAR respaldo | restaurar <archivo> [--destino <dir>]
   $OPERAR actualizar | rotar-llave-maestra | desinstalar
 Puertos a abrir en el cortafuegos (solo red interna): $PUERTO_SERVICIO/tcp y $PUERTO_PORTAL/tcp.
========================================================================================
EOF
