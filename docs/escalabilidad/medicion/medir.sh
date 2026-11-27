#!/usr/bin/env bash
# Ejecuta un escenario de medición completo en una carpeta temporal FUERA del repositorio.
# Uso: medir.sh <carpeta-temporal> <escenario> [FULL|NORMAL] [usuarios] [duracion_s] [concurrencias]
#   Variables opcionales: ACELERACION (100), PUERTO (18900), PERFIL=1 (perfil de CPU del banco con --cpu-prof),
#   FASES (jwks,verify,validate).
set -euo pipefail
TMP=${1:?carpeta temporal}; ESC=${2:?nombre del escenario}; SINC=${3:-FULL}
USU=${4:-1000}; DUR=${5:-8}; CONC=${6:-1,10,50,100}; FASES=${FASES:-jwks,verify,validate}
AQUI=$(cd "$(dirname "$0")" && pwd); BACK=$(cd "$AQUI/../../../backend" && pwd)
DIR="$TMP/$ESC"; rm -rf "$DIR"; mkdir -p "$DIR"
[ -f "$TMP/escala.env" ] || node "$BACK/scripts/generar-env.js" --salida "$TMP/escala.env"
[ -f "$BACK/certs/localhost.crt" ] || (cd "$BACK" && node scripts/certificados.js)

export ENV_FILE="$TMP/escala.env" PORT=${PUERTO:-18900} SQLITE_DB_PATH="$DIR/totp.db" \
  TLS_CERT_PATH="$BACK/certs/localhost.crt" TLS_KEY_PATH="$BACK/certs/localhost.key" \
  JWT_TTL_SECONDS=3600 T0=$(date +%s%3N) ACELERACION=${ACELERACION:-100} SINCRONO="$SINC" NODE_NO_WARNINGS=1
PERF=(); [ "${PERFIL:-0}" = 1 ] && PERF=(--cpu-prof --cpu-prof-dir="$DIR")
node "${PERF[@]}" "$AQUI/banco.js" "$DIR" > "$DIR/banco.log" 2>&1 &
PID=$!
trap 'kill $PID 2>/dev/null || true' EXIT
for _ in $(seq 50); do [ -f "$DIR/banco.json" ] && break; sleep 0.2; done
node "$AQUI/carga.js" "$DIR" --usuarios "$USU" --duracion "$DUR" --concurrencias "$CONC" --fases "$FASES" | tee "$DIR/carga.log"
kill -TERM $PID; wait $PID 2>/dev/null || true
echo "Escenario $ESC terminado en $DIR"
