# Funciones y rutas comunes de deploy/instalar.sh y deploy/operar.sh (POSIX sh).
# No se ejecuta por sí solo: lo cargan los otros dos scripts con «. comun.sh».

# Componentes del repositorio que se copian a la instalación (el servicio nunca se ejecuta desde el repo).
COMPONENTES="backend authenticator-app admin-console demo-portal-tramites sdk contracts deploy LICENSE README.md .env.example"
UNIDADES_SERVICIO="servicio-totp.service portal-tramites.service"
UNIDAD_TEMPORIZADOR="servicio-totp-respaldo.timer"
COPIAS_A_CONSERVAR=7
PUERTO_SERVICIO=8443
PUERTO_PORTAL=8444

# ------------------------------------------------------------------ mensajes

if [ -t 1 ]; then
  C_PASO=$(printf '\033[1;34m'); C_OK=$(printf '\033[32m'); C_AVISO=$(printf '\033[33m'); C_ERR=$(printf '\033[31m'); C_FIN=$(printf '\033[0m')
else
  C_PASO=''; C_OK=''; C_AVISO=''; C_ERR=''; C_FIN=''
fi
NUM_PASO=0
paso() { NUM_PASO=$((NUM_PASO + 1)); printf '\n%s[%s] %s%s\n' "$C_PASO" "$NUM_PASO" "$*" "$C_FIN"; }
info() { printf '    %s\n' "$*"; }
ok() { printf '    %s✔ %s%s\n' "$C_OK" "$*" "$C_FIN"; }
aviso() { printf '    %s⚠ %s%s\n' "$C_AVISO" "$*" "$C_FIN" >&2; }
fallo() { printf '\n%s✖ %s%s\n' "$C_ERR" "$*" "$C_FIN" >&2; exit 1; }

# ------------------------------------------------------------------ rutas según el modo

definir_rutas() {
  if [ "$(id -u)" -eq 0 ]; then
    MODO=sistema
    PREFIJO=/opt/servicio-totp
    DATOS=/var/lib/servicio-totp
    CONFIG=/etc/servicio-totp
    RESPALDOS=/var/backups/servicio-totp
    DIR_UNIDADES=/etc/systemd/system
    USUARIO_SERVICIO=totp
  else
    MODO=usuario
    PREFIJO="${XDG_DATA_HOME:-$HOME/.local/share}/servicio-totp"
    DATOS="$PREFIJO/datos"
    CONFIG="${XDG_CONFIG_HOME:-$HOME/.config}/servicio-totp"
    RESPALDOS="$PREFIJO/respaldos"
    DIR_UNIDADES="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
    USUARIO_SERVICIO=$(id -un)
  fi
  ENV_SERVICIO="$CONFIG/servicio-totp.env"
  ENV_PORTAL="$CONFIG/portal.env"
  TLS="$CONFIG/tls"
  CA="$TLS/ca.crt"
  CREDENCIALES="$CONFIG/credenciales.txt"
  CLAVE_RESPALDO="$CONFIG/clave-respaldo"
  CONF_INSTALACION="$CONFIG/instalacion.conf"
  BASE_DATOS="$DATOS/totp_soberano.db"
}

ctl() {
  if [ "$MODO" = sistema ]; then systemctl "$@"; else systemctl --user "$@"; fi
}

jctl() {
  if [ "$MODO" = sistema ]; then journalctl "$@"; else journalctl --user "$@"; fi
}

# Ejecuta una orden con la identidad del servicio (en modo usuario, el propio usuario).
como_servicio() {
  if [ "$MODO" = sistema ]; then
    if command -v setpriv >/dev/null 2>&1; then
      setpriv --reuid="$USUARIO_SERVICIO" --regid="$USUARIO_SERVICIO" --init-groups -- "$@"
    else
      runuser -u "$USUARIO_SERVICIO" -- "$@"
    fi
  else
    "$@"
  fi
}

# ------------------------------------------------------------------ archivos de configuración

# leer_var <archivo> <CLAVE>: último valor asignado (vacío si no existe).
leer_var() {
  [ -f "$1" ] || return 0
  sed -n "s/^$2=//p" "$1" | tail -n 1
}

# fijar_var <archivo> <CLAVE> <valor>: sustituye o añade CLAVE=valor conservando permisos (0600).
fijar_var() {
  _archivo=$1; _clave=$2
  _valor=$(printf '%s' "$3" | sed 's/[\\&|]/\\&/g')
  _tmp="$_archivo.tmp.$$"
  if grep -q "^$_clave=" "$_archivo"; then
    sed "s|^$_clave=.*|$_clave=$_valor|" "$_archivo" > "$_tmp"
  else
    cat "$_archivo" > "$_tmp"
    printf '%s=%s\n' "$_clave" "$3" >> "$_tmp"
  fi
  chmod 0600 "$_tmp"
  mv -f "$_tmp" "$_archivo"
}

# asegurar_var <archivo> <CLAVE> <valor>: solo la fija si falta o está vacía (respeta lo editado a mano).
asegurar_var() {
  if [ -z "$(leer_var "$1" "$2")" ]; then fijar_var "$1" "$2" "$3"; fi
}

cargar_instalacion() {
  [ -f "$CONF_INSTALACION" ] || fallo "No hay una instalación en modo $MODO ($CONF_INSTALACION no existe). Ejecute primero: sh deploy/instalar.sh"
  NODE=$(leer_var "$CONF_INSTALACION" NODE)
  ORIGEN=$(leer_var "$CONF_INSTALACION" ORIGEN)
  IP_PRINCIPAL=$(leer_var "$CONF_INSTALACION" IP_PRINCIPAL)
  [ -x "$NODE" ] || NODE=$(command -v node || true)
  [ -n "$NODE" ] || fallo "No se encuentra Node.js."
}

# ------------------------------------------------------------------ red

# IP principal de la red local: primera IPv4 global que no sea de túnel/VPN/contenedor.
ip_principal() {
  _ip=''
  if command -v ip >/dev/null 2>&1; then
    _ip=$(ip -o -4 addr show scope global 2>/dev/null \
      | awk '$2 !~ /^(wg|tun|tap|docker|br-|virbr|veth|lxc|zt|tailscale|cni|flannel)/ { split($4, a, "/"); print a[1]; exit }')
  fi
  [ -n "$_ip" ] || _ip=$(hostname -I 2>/dev/null | awk '{ print $1 }')
  [ -n "$_ip" ] || _ip=127.0.0.1
  printf '%s\n' "$_ip"
}

# Lista SAN para el certificado: nombre del host (y .local) y TODAS las IP de «hostname -I».
lista_san() {
  _h=$(hostname 2>/dev/null || true)
  _san=''
  if [ -n "$_h" ]; then _san="DNS:$_h,DNS:$_h.local"; fi
  for _i in $(hostname -I 2>/dev/null) $1; do
    case ",$_san," in *",IP:$_i,"*) continue ;; esac
    _san="${_san:+$_san,}IP:$_i"
  done
  printf '%s\n' "$_san"
}

# ------------------------------------------------------------------ código

# copiar_codigo <repo-origen>: copia los componentes a $PREFIJO; lo anterior queda en $PREFIJO/.anterior
# hasta confirmar_codigo (o se recupera con revertir_codigo).
copiar_codigo() {
  _origen=$1
  [ -f "$_origen/backend/src/main.js" ] || fallo "$_origen no parece el repositorio del servicio (falta backend/src/main.js)."
  (
    umask 022
    rm -rf "$PREFIJO/.nuevo" "$PREFIJO/.anterior"
    mkdir -p "$PREFIJO/.nuevo" "$PREFIJO/.anterior"
    _lista=''
    for _c in $COMPONENTES; do [ -e "$_origen/$_c" ] && _lista="$_lista $_c"; done
    # shellcheck disable=SC2086
    tar -C "$_origen" \
      --exclude='.git' --exclude='node_modules' --exclude='.env' --exclude='*.db' --exclude='*.db-wal' --exclude='*.db-shm' \
      --exclude='backend/certs' --exclude='backend/data' --exclude='demo-portal-tramites/datos' \
      --exclude='attack-lab/resultados' --exclude='*.key' --exclude='*.pem' \
      -cf - $_lista | tar -C "$PREFIJO/.nuevo" --no-same-owner -xf -
    _version=$(git -C "$_origen" describe --always --dirty 2>/dev/null || echo desconocida)
    printf 'version=%s\norigen=%s\ncopiado=%s\n' "$_version" "$_origen" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$PREFIJO/.nuevo/VERSION"
    for _c in $_lista VERSION; do
      if [ -e "$PREFIJO/$_c" ]; then mv "$PREFIJO/$_c" "$PREFIJO/.anterior/$_c"; fi
      mv "$PREFIJO/.nuevo/$_c" "$PREFIJO/$_c"
    done
    rm -rf "$PREFIJO/.nuevo"
    if [ "$MODO" = sistema ]; then chown -R root:root "$PREFIJO"; chmod -R go-w,a+rX "$PREFIJO"; fi
  )
  # La configuración del portal vive fuera del código: enlace al archivo 0600 de la configuración.
  ln -sfn "$ENV_PORTAL" "$PREFIJO/demo-portal-tramites/.env"
}

confirmar_codigo() { rm -rf "$PREFIJO/.anterior"; }

revertir_codigo() {
  [ -d "$PREFIJO/.anterior" ] || return 0
  for _c in $(ls -A "$PREFIJO/.anterior"); do
    rm -rf "${PREFIJO:?}/$_c"
    mv "$PREFIJO/.anterior/$_c" "$PREFIJO/$_c"
  done
  rm -rf "$PREFIJO/.anterior"
}

# ------------------------------------------------------------------ salud

esperar_servicio() {
  "$NODE" "$PREFIJO/deploy/herramientas.mjs" esperar-salud "https://127.0.0.1:$PUERTO_SERVICIO/health/ready" "$CA" "${1:-40}"
}

esperar_portal() {
  "$NODE" "$PREFIJO/deploy/herramientas.mjs" esperar-http "https://127.0.0.1:$PUERTO_PORTAL/" "$CA" "${1:-40}"
}
