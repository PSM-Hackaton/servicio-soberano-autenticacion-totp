#!/bin/sh
# Operación del Servicio Soberano TOTP instalado con deploy/instalar.sh (mismo modo: root = sistema,
# usuario normal = modo usuario).
#
#   sh operar.sh estado                      estado de las unidades, salud, certificado y respaldos
#   sh operar.sh logs [-f] [líneas]          diario de ambos servicios (sin secretos ni IP)
#   sh operar.sh iniciar | reiniciar | detener
#   sh operar.sh actualizar [--desde <repo>] copia de nuevo el código (conserva datos y configuración),
#                                            reinicia y verifica la salud; si falla, vuelve a la versión anterior
#   sh operar.sh respaldo                    copia cifrada (AES-256-GCM) de la base y la configuración; conserva 7
#   sh operar.sh restaurar <archivo> [--destino <dir>] [--con-configuracion] [--si]
#                                            sin --destino: sustituye la base de la instancia (pide RESTAURAR)
#                                            con --destino: solo descifra y comprueba en <dir> (instancia intacta)
#   sh operar.sh rotar-llave-maestra         añade una llave maestra nueva, recifra todo y reinicia
#   sh operar.sh desinstalar                 elimina servicio, código, datos y configuración (pide DESINSTALAR);
#                                            conserva los respaldos y su clave

set -eu
umask 077

AQUI=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=deploy/comun.sh
. "$AQUI/comun.sh"
definir_rutas

ORDEN=${1:-ayuda}
[ $# -gt 0 ] && shift

ayuda() { sed -n '2,19p' "$0" | sed 's/^# \{0,1\}//'; }

# ------------------------------------------------------------------ estado / logs / ciclo de vida

estado() {
  cargar_instalacion
  printf 'Servicio Soberano TOTP — modo %s (%s)\n' "$MODO" "$(sed -n 's/^version=//p' "$PREFIJO/VERSION" 2>/dev/null)"
  for u in $UNIDADES_SERVICIO $UNIDAD_TEMPORIZADOR; do
    printf '  %-32s %s (%s)\n' "$u" "$(ctl is-active "$u" 2>/dev/null || true)" "$(ctl is-enabled "$u" 2>/dev/null || true)"
  done
  ctl status servicio-totp.service portal-tramites.service --no-pager -n 0 2>/dev/null | grep -E '^\S|Active:|Main PID|Memory' | sed 's/^/  /' || true
  if esperar_servicio 3 >/dev/null 2>&1; then ok "/health/ready → 200"; else aviso "/health/ready no responde"; fi
  if esperar_portal 3 >/dev/null 2>&1; then ok "Portal en $PUERTO_PORTAL responde"; else aviso "El portal no responde"; fi
  info "Certificado del servidor: caduca $(openssl x509 -in "$TLS/servidor.crt" -noout -enddate | sed 's/^notAfter=//')"
  info "Nombres e IP: $(cat "$TLS/san.txt" 2>/dev/null)"
  info "Reloj sincronizado por NTP: $(timedatectl show -p NTPSynchronized --value 2>/dev/null || echo desconocido)"
  if [ "$MODO" = usuario ]; then info "Linger: $(loginctl show-user "$USUARIO_SERVICIO" -p Linger --value 2>/dev/null || echo desconocido)"; fi
  _n=$(ls -1 "$RESPALDOS"/servicio-totp-*.stotp 2>/dev/null | wc -l)
  info "Respaldos en $RESPALDOS: $_n (último: $(ls -1t "$RESPALDOS"/servicio-totp-*.stotp 2>/dev/null | head -n 1 | xargs -r basename))"
  info "Próximo respaldo: $(ctl list-timers "$UNIDAD_TEMPORIZADOR" --no-pager 2>/dev/null | sed -n 2p | awk '{print $1, $2, $3}')"
}

logs() {
  _seguir=''; _n=100
  for a in "$@"; do case "$a" in -f) _seguir=-f ;; *[!0-9]*) ;; *) _n=$a ;; esac; done
  # shellcheck disable=SC2086
  jctl -u servicio-totp -u portal-tramites -u servicio-totp-respaldo -n "$_n" --no-pager $_seguir
}

iniciar() {
  cargar_instalacion
  ctl start servicio-totp.service
  esperar_servicio 40
  ctl start portal-tramites.service
  esperar_portal 40
}

reiniciar() {
  cargar_instalacion
  ctl restart servicio-totp.service
  esperar_servicio 40
  ctl restart portal-tramites.service
  esperar_portal 40
  ok "Servicios reiniciados y sanos"
}

detener() {
  ctl stop portal-tramites.service servicio-totp.service
  ok "Servicios detenidos (siguen habilitados: arrancarán con el sistema o con «operar.sh iniciar»)"
}

# ------------------------------------------------------------------ actualizar

actualizar() {
  cargar_instalacion
  _desde=$ORIGEN
  while [ $# -gt 0 ]; do case "$1" in --desde) _desde=$2; shift ;; esac; shift; done
  _desde=$(CDPATH='' cd -- "$_desde" && pwd) || fallo "No existe el repositorio de origen $_desde"
  paso "Respaldo previo"
  respaldo
  paso "Copiando el código desde $_desde"
  copiar_codigo "$_desde"
  ok "Nueva versión: $(sed -n 's/^version=//p' "$PREFIJO/VERSION")"
  paso "Reiniciando y verificando"
  ctl daemon-reload
  if ctl restart servicio-totp.service && esperar_servicio 40 && ctl restart portal-tramites.service && esperar_portal 40; then
    confirmar_codigo
    fijar_var "$CONF_INSTALACION" ORIGEN "$_desde"
    ok "Actualización completada; datos y configuración conservados"
    info "Para aplicar cambios en las unidades systemd o en el certificado, vuelva a ejecutar deploy/instalar.sh."
  else
    aviso "La versión nueva no quedó sana: se restaura la anterior"
    revertir_codigo
    ln -sfn "$ENV_PORTAL" "$PREFIJO/demo-portal-tramites/.env"
    ctl restart servicio-totp.service portal-tramites.service || true
    esperar_servicio 40 || true
    fallo "Actualización revertida. Revise: sh $0 logs"
  fi
}

# ------------------------------------------------------------------ respaldo / restaurar

herramienta() { "$NODE" "$PREFIJO/deploy/herramientas.mjs" "$@"; }

respaldo() {
  cargar_instalacion
  [ -f "$CLAVE_RESPALDO" ] || fallo "Falta la clave de respaldos $CLAVE_RESPALDO."
  mkdir -p "$RESPALDOS"; chmod 0700 "$RESPALDOS"
  _fecha=$(date -u +%Y%m%dT%H%M%SZ)
  _trabajo="$RESPALDOS/.trabajo-$_fecha-$$"
  mkdir -m 0700 "$_trabajo"
  trap 'rm -rf "$_trabajo"' EXIT INT TERM
  # Copia consistente en caliente con la identidad del servicio (no crea archivos ajenos en los datos).
  _inst="$DATOS/.instantanea-$$.db"
  como_servicio "$NODE" "$PREFIJO/deploy/herramientas.mjs" instantanea "$BASE_DATOS" "$_inst"
  mv "$_inst" "$_trabajo/totp_soberano.db"
  herramienta comprobar "$_trabajo/totp_soberano.db" > "$_trabajo/comprobacion.txt"
  # Configuración (secretos incluidos) salvo la propia clave de los respaldos, que se custodia aparte.
  mkdir -m 0700 "$_trabajo/configuracion"
  (cd "$CONFIG" && tar --exclude=./clave-respaldo --exclude='./.*' -cf - .) | tar -C "$_trabajo/configuracion" -xf -
  if [ -d "$DATOS/portal" ]; then cp -Rp "$DATOS/portal" "$_trabajo/portal"; fi
  printf 'fecha=%s\nmodo=%s\nversion=%s\nhost=%s\n' "$_fecha" "$MODO" "$(sed -n 's/^version=//p' "$PREFIJO/VERSION")" "$(hostname)" > "$_trabajo/MANIFIESTO"
  tar -C "$_trabajo" -cf "$_trabajo.tar" MANIFIESTO comprobacion.txt totp_soberano.db configuracion $( [ -d "$_trabajo/portal" ] && echo portal )
  _salida="$RESPALDOS/servicio-totp-$_fecha.stotp"
  herramienta cifrar "$_trabajo.tar" "$_salida" "$CLAVE_RESPALDO"
  _comprobacion=$(cat "$_trabajo/comprobacion.txt")
  rm -f "$_trabajo.tar"
  rm -rf "$_trabajo"
  trap - EXIT INT TERM
  # Rotación: se conservan las $COPIAS_A_CONSERVAR más recientes.
  ls -1t "$RESPALDOS"/servicio-totp-*.stotp 2>/dev/null | tail -n +$((COPIAS_A_CONSERVAR + 1)) | while read -r _viejo; do
    rm -f "$_viejo"; info "Rotación: eliminado $(basename "$_viejo")"
  done
  ok "Respaldo cifrado (AES-256-GCM): $_salida ($(wc -c < "$_salida") bytes; $_comprobacion)"
}

restaurar() {
  cargar_instalacion
  _archivo=''; _destino=''; _conf=0; _si=0
  while [ $# -gt 0 ]; do
    case "$1" in
      --destino) _destino=$2; shift ;;
      --con-configuracion) _conf=1 ;;
      --si) _si=1 ;;
      *) _archivo=$1 ;;
    esac
    shift
  done
  [ -n "$_archivo" ] && [ -f "$_archivo" ] || fallo "Indique un respaldo existente: sh $0 restaurar <archivo.stotp> [--destino <dir>]"
  _tmp=$(mktemp -d "${TMPDIR:-/tmp}/restaurar-totp.XXXXXX")
  trap 'rm -rf "$_tmp"' EXIT INT TERM
  paso "Descifrando y comprobando $(basename "$_archivo")"
  herramienta descifrar "$_archivo" "$_tmp/respaldo.tar" "$CLAVE_RESPALDO"
  mkdir "$_tmp/contenido"
  tar -C "$_tmp/contenido" -xf "$_tmp/respaldo.tar"
  rm -f "$_tmp/respaldo.tar"
  sed 's/^/    /' "$_tmp/contenido/MANIFIESTO"
  ok "Base: $(herramienta comprobar "$_tmp/contenido/totp_soberano.db")"

  if [ -n "$_destino" ]; then
    mkdir -p "$_destino"; chmod 0700 "$_destino"
    cp -Rp "$_tmp/contenido/." "$_destino/"
    ok "Restaurado en $_destino (la instancia en marcha no se ha tocado)"
    info "Para probarlo en otro puerto: ENV_FILE=$_destino/configuracion/servicio-totp.env SQLITE_DB_PATH=$_destino/totp_soberano.db PORT=18443 HOST=127.0.0.1 node $PREFIJO/backend/src/main.js"
    return 0
  fi

  if [ "$_si" != 1 ]; then
    printf 'Se sustituirá la base de datos en %s%s.\nEscriba RESTAURAR para continuar: ' "$BASE_DATOS" "$( [ "$_conf" = 1 ] && echo ' y la configuración')"
    read -r _r
    [ "$_r" = RESTAURAR ] || fallo "Cancelado."
  fi
  paso "Respaldo de seguridad del estado actual"
  respaldo
  trap 'rm -rf "$_tmp"' EXIT INT TERM
  paso "Sustituyendo datos"
  ctl stop portal-tramites.service servicio-totp.service
  _antes="$DATOS/antes-de-restaurar-$(date -u +%Y%m%dT%H%M%SZ)"
  mkdir -m 0700 "$_antes"
  for f in "$BASE_DATOS" "$BASE_DATOS-wal" "$BASE_DATOS-shm"; do [ -f "$f" ] && mv "$f" "$_antes/"; done
  cp "$_tmp/contenido/totp_soberano.db" "$BASE_DATOS"
  if [ -d "$_tmp/contenido/portal" ]; then rm -rf "$DATOS/portal"; cp -Rp "$_tmp/contenido/portal" "$DATOS/portal"; fi
  if [ "$_conf" = 1 ]; then
    (cd "$_tmp/contenido/configuracion" && tar -cf - .) | tar -C "$CONFIG" -xf -
    info "Configuración restaurada (incluida la llave maestra con la que se cifró la base)"
  fi
  if [ "$MODO" = sistema ]; then chown -R "$USUARIO_SERVICIO:$USUARIO_SERVICIO" "$DATOS" "$CONFIG"; chown root:root "$CLAVE_RESPALDO" "$TLS/ca.key"; fi
  chmod 0600 "$BASE_DATOS"
  iniciar
  ok "Restauración completada. Estado anterior guardado en $_antes"
  info "Compruebe la cadena de auditoría en la consola (Bitácora → Verificar cadena)."
}

# ------------------------------------------------------------------ rotación de la llave maestra

rotar_llave_maestra() {
  cargar_instalacion
  _actual=$(leer_var "$ENV_SERVICIO" MASTER_KEY_VERSION)
  _n=$(printf '%s' "$_actual" | sed -n 's/^v\([0-9][0-9]*\)$/\1/p')
  [ -n "$_n" ] || fallo "MASTER_KEY_VERSION=$_actual no tiene el formato vN."
  _nueva="v$((_n + 1))"
  _var="MASTER_KEY_$(printf '%s' "$_nueva" | tr '[:lower:]' '[:upper:]')_HEX"
  [ -z "$(leer_var "$ENV_SERVICIO" "$_var")" ] || fallo "$_var ya existe en $ENV_SERVICIO; revise el archivo a mano."
  paso "Respaldo previo (base y configuración con la llave $_actual)"
  respaldo
  paso "Generando la llave maestra $_nueva (256 bits del CSPRNG)"
  cp -p "$ENV_SERVICIO" "$CONFIG/.servicio-totp.env.antes-rotacion"
  fijar_var "$ENV_SERVICIO" "$_var" "$(herramienta aleatorio 32 hex)"
  fijar_var "$ENV_SERVICIO" MASTER_KEY_VERSION "$_nueva"
  [ "$MODO" = sistema ] && chown "$USUARIO_SERVICIO:$USUARIO_SERVICIO" "$ENV_SERVICIO"
  paso "Recifrando semillas y claves de firma (servicio detenido)"
  ctl stop portal-tramites.service servicio-totp.service
  _registro="$CONFIG/.rotacion.$$.log"
  if como_servicio env NODE_ENV=production ENV_FILE="$ENV_SERVICIO" "$NODE" --disable-warning=ExperimentalWarning \
      "$PREFIJO/backend/scripts/rotar-llave-maestra.js" > "$_registro" 2>&1; then
    sed 's/^/    /' "$_registro"; rm -f "$_registro"
    rm -f "$CONFIG/.servicio-totp.env.antes-rotacion"
    iniciar
    ok "Llave maestra rotada a $_nueva. La anterior ($_actual) sigue en el archivo: retírela solo tras comprobar y respaldar."
  else
    sed 's/^/    /' "$_registro" >&2; rm -f "$_registro"
    mv -f "$CONFIG/.servicio-totp.env.antes-rotacion" "$ENV_SERVICIO"
    iniciar || true
    fallo "La rotación falló y no se modificó la base; configuración anterior restaurada."
  fi
}

# ------------------------------------------------------------------ desinstalar

desinstalar() {
  printf 'Se eliminarán el servicio, el código (%s), los datos (%s) y la configuración (%s).\n' "$PREFIJO" "$DATOS" "$CONFIG"
  printf 'Se conservan los respaldos (%s) y su clave (%s).\nEscriba DESINSTALAR para continuar: ' "$RESPALDOS" "$CLAVE_RESPALDO"
  read -r _r
  [ "$_r" = DESINSTALAR ] || fallo "Cancelado."
  ctl disable --now portal-tramites.service servicio-totp.service servicio-totp-respaldo.timer 2>/dev/null || true
  for u in servicio-totp.service portal-tramites.service servicio-totp-respaldo.service servicio-totp-respaldo.timer; do
    rm -f "$DIR_UNIDADES/$u"
  done
  ctl daemon-reload || true
  # Código y datos (en modo usuario los respaldos están dentro de $PREFIJO y se conservan).
  for e in "$PREFIJO"/* "$PREFIJO"/.[!.]*; do
    [ -e "$e" ] || continue
    [ "$e" = "$RESPALDOS" ] && continue
    rm -rf "$e"
  done
  [ "$MODO" = sistema ] && rm -rf "$DATOS"
  # Configuración: todo salvo la clave de los respaldos.
  for e in "$CONFIG"/* "$CONFIG"/.[!.]*; do
    [ -e "$e" ] || continue
    [ "$e" = "$CLAVE_RESPALDO" ] && continue
    rm -rf "$e"
  done
  if [ "$MODO" = sistema ] && id "$USUARIO_SERVICIO" >/dev/null 2>&1; then userdel "$USUARIO_SERVICIO" 2>/dev/null || true; fi
  ok "Desinstalado. Conservados: $RESPALDOS y $CLAVE_RESPALDO"
}

case "$ORDEN" in
  estado) estado ;;
  logs) logs "$@" ;;
  iniciar) iniciar ;;
  reiniciar) reiniciar ;;
  detener) detener ;;
  actualizar) actualizar "$@" ;;
  respaldo) respaldo ;;
  restaurar) restaurar "$@" ;;
  rotar-llave-maestra) rotar_llave_maestra ;;
  desinstalar) desinstalar ;;
  ayuda|-h|--ayuda|--help) ayuda ;;
  *) ayuda; fallo "Orden desconocida: $ORDEN" ;;
esac
