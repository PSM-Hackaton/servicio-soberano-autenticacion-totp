#!/bin/sh
# UNA ETAPA de la subida progresiva sobre el GitLab REAL del evento (modelo del evento).
#
# En el GitLab del evento la rama "desarrollo" ya existe (commit del organizador con la plantilla del
# README, más lo ya fusionado) y cada persona sube a su rama personal (diego, laya) y abre un Merge
# Request hacia "desarrollo". Por eso este script NO crea un repositorio nuevo (como subir-por-etapas.sh):
# añade UN commit encima de lo que ya hay, sin reescribir historia.
#
#   1. Genera y verifica la copia limpia completa de --ref (mismas funciones que preparar-entrega.sh).
#   2. Reparte sus archivos en las etapas de scripts/etapas-entrega.txt y toma la etapa pedida.
#   3. Base: --sobre, o la rama personal del autor en GitLab (gitlab/<rama>) si existe, o gitlab/desarrollo.
#      Exige que la base contenga gitlab/desarrollo y avisa si faltan archivos de etapas anteriores (p. ej.
#      la de otra persona que aún no se ha fusionado): entonces la etapa se puede subir igual, pero cuando
#      se fusione la otra habrá que rehacerla sobre "desarrollo" actualizado (el script lo explica).
#   4. Construye el árbol "base + archivos de la etapa" en una carpeta temporal, lo verifica (limpieza y
#      README de la plantilla del evento, si ya existe) y ejecuta las pruebas de los componentes que
#      contiene, sobre una copia.
#   5. Crea el commit con la identidad GitLab del autor de la etapa (scripts/gitlab-evento.txt; autor y
#      quien confirma, hora real) y la rama LOCAL --rama-local (por defecto <rama>-etapa<N>) en el clon.
#      No cambia la rama actual del clon ni su carpeta de trabajo.
#   6. Muestra (sin ejecutarlos) el push a la rama personal y el Merge Request hacia "desarrollo" por la
#      API con remove_source_branch=false (scripts/mr-gitlab.sh).
#
# Uso: sh scripts/etapa-gitlab.sh --clon DIR --etapa N|ID [opciones]
# Requisitos: sh POSIX, git y Node.js 22 o superior. Nunca hace push, nunca fuerza, nunca llama a la API.

set -eu

uso() {
  cat <<'FIN'
Uso: sh scripts/etapa-gitlab.sh --clon DIR --etapa N|ID [opciones]

  --clon DIR          clon local del proyecto del GitLab del evento, con el remoto "gitlab" ya
                      actualizado (git -C DIR fetch gitlab). No se cambia su rama actual.
  --etapa N|ID        etapa de scripts/etapas-entrega.txt (número de orden o identificador)
  --ref REF           referencia del repositorio de trabajo (GitHub) a entregar. Por defecto: HEAD
  --sobre REF         commit del clon sobre el que se construye. Por defecto: gitlab/<rama del autor>
                      si existe; si no, gitlab/desarrollo
  --rama-local NOMBRE rama local que recibe el commit. Por defecto: <rama>-etapa<N>
  --forzar            rehace --rama-local si ya existe
  --sin-pruebas       no ejecuta las pruebas de los componentes de la etapa
  --permitidos ARCH   lista de hallazgos aceptados (como en preparar-entrega.sh)
  --config ARCH       datos del proyecto e identidades. Por defecto: scripts/gitlab-evento.txt
  -h, --help          muestra esta ayuda
FIN
}

DIR_SCRIPT=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=scripts/entrega-comun.sh
. "$DIR_SCRIPT/entrega-comun.sh"

CLON=; ETAPA=; REF=HEAD; SOBRE=; RAMA_LOCAL=; FORZAR=0; PRUEBAS=1; PERMITIDOS=
CONFIG="$DIR_SCRIPT/gitlab-evento.txt"
RESUMEN_PRUEBAS='no ejecutadas (--sin-pruebas); verificaciones de limpieza del árbol en verde'
while [ $# -gt 0 ]; do
  case "$1" in
    --clon) [ $# -ge 2 ] || falla 'falta el valor de --clon'; CLON=$2; shift 2 ;;
    --etapa) [ $# -ge 2 ] || falla 'falta el valor de --etapa'; ETAPA=$2; shift 2 ;;
    --ref) [ $# -ge 2 ] || falla 'falta el valor de --ref'; REF=$2; shift 2 ;;
    --sobre) [ $# -ge 2 ] || falla 'falta el valor de --sobre'; SOBRE=$2; shift 2 ;;
    --rama-local) [ $# -ge 2 ] || falla 'falta el valor de --rama-local'; RAMA_LOCAL=$2; shift 2 ;;
    --forzar) FORZAR=1; shift ;;
    --sin-pruebas) PRUEBAS=0; shift ;;
    --permitidos) [ $# -ge 2 ] || falla 'falta el valor de --permitidos'; PERMITIDOS=$2; shift 2 ;;
    --config) [ $# -ge 2 ] || falla 'falta el valor de --config'; CONFIG=$2; shift 2 ;;
    -h|--help) uso; exit 0 ;;
    *) uso >&2; falla "opción desconocida: $1" ;;
  esac
done
[ -n "$CLON" ] || { uso >&2; falla 'falta --clon'; }
[ -n "$ETAPA" ] || { uso >&2; falla 'falta --etapa'; }
[ -f "$CONFIG" ] || falla "no existe el archivo de datos del proyecto $CONFIG"

dato() {
  if [ $# -eq 1 ]; then
    awk -v k="$1" '$1 == k { sub(/^[^ \t]+[ \t]+/, ""); print; exit }' "$CONFIG"
  else
    awk -v k="$1" -v s="$2" '$1 == k && $2 == s { sub(/^[^ \t]+[ \t]+[^ \t]+[ \t]+/, ""); print; exit }' "$CONFIG"
  fi
}

# ------------------------------------------------------------------ entorno

entrega_entorno
[ -f "$ETAPAS" ] || falla "no existe $ETAPAS"
entrega_permitidos
CLON=$(CDPATH='' cd -- "$CLON" 2>/dev/null && pwd) || falla "no existe la carpeta del clon"
[ "$(git -C "$CLON" rev-parse --show-toplevel 2>/dev/null)" = "$CLON" ] || falla "$CLON no es la raíz de un repositorio git"
[ "$CLON" != "$RAIZ" ] || falla '--clon debe ser el clon de GitLab, no el repositorio de trabajo'
git -C "$CLON" remote get-url gitlab >/dev/null 2>&1 || falla "el clon no tiene el remoto \"gitlab\""
case "$(git -C "$CLON" remote get-url gitlab)" in
  *://*@*) falla 'el remoto "gitlab" del clon lleva credenciales en la URL; quítelas (git remote set-url gitlab <URL sin usuario ni token>)' ;;
esac
DESTINO=$(dato destino); DESTINO=${DESTINO:-desarrollo}
git -C "$CLON" rev-parse --verify --quiet "refs/remotes/gitlab/$DESTINO" >/dev/null \
  || falla "el clon no tiene gitlab/$DESTINO; actualícelo: git -C \"$CLON\" fetch gitlab"
COMMIT=$(entrega_commit "$REF") || exit 1
COMMIT_CORTO=$(git -C "$RAIZ" rev-parse --short "$COMMIT")
entrega_temporales etapa-gitlab

# ------------------------------------------------------------------ 1. copia limpia completa

titulo "1. Copia limpia completa de $REF ($COMMIT_CORTO)"
LIMPIA="$TMP/limpia"
mkdir -p "$LIMPIA"
entrega_copia_limpia "$COMMIT" "$LIMPIA"
entrega_verificar "$LIMPIA" > "$TMP/verificacion-limpia.log" \
  || { cat "$TMP/verificacion-limpia.log"; falla 'la copia limpia no pasa las verificaciones; corrija el repositorio de trabajo'; }
printf '  OK     %s archivos, verificaciones de limpieza en verde\n' "$(find "$LIMPIA" -type f | wc -l | tr -d ' ')"

# ------------------------------------------------------------------ 2. etapa pedida

titulo '2. Plan de etapas (scripts/etapas-entrega.txt)'
PLAN="$TMP/plan"
node "$HERRAMIENTAS" etapas "$LIMPIA" "$ETAPAS" "$EXCLUSIONES" "$PLAN" --autor-laya "$(dato identidad laya)" > "$TMP/plan.log" \
  || { cat "$TMP/plan.log"; falla 'el plan de etapas no es válido'; }
TAB=$(printf '\t')
LINEA=$(awk -F "$TAB" -v e="$ETAPA" '$1 == e || $2 == e' "$PLAN/plan.tsv")
[ -n "$LINEA" ] || { cat "$TMP/plan.log"; falla "no existe la etapa \"$ETAPA\""; }
N=$(printf '%s\n' "$LINEA" | cut -f1)
ID=$(printf '%s\n' "$LINEA" | cut -f2)
RAMA=$(printf '%s\n' "$LINEA" | cut -f3)
MENSAJE=$(printf '%s\n' "$LINEA" | cut -f7-)
N_ETAPAS=$(wc -l < "$PLAN/plan.tsv" | tr -d ' ')
IDENTIDAD=$(dato identidad "$RAMA")
[ -n "$IDENTIDAD" ] || falla "falta \"identidad $RAMA Nombre <correo>\" en $CONFIG"
NOMBRE=$(printf '%s\n' "$IDENTIDAD" | sed -n 's/^\(.*[^ ]\) *<\([^<>]*\)>$/\1/p')
CORREO=$(printf '%s\n' "$IDENTIDAD" | sed -n 's/^\(.*[^ ]\) *<\([^<>]*\)>$/\2/p')
[ -n "$NOMBRE" ] && [ -n "$CORREO" ] || falla "identidad sin formato \"Nombre <correo>\": $IDENTIDAD"
entrega_identidad_valida "$NOMBRE" "$CORREO" || falla "identidad no permitida para la rama $RAMA: $IDENTIDAD"
entrega_texto_valido "$MENSAJE" || falla "el mensaje de la etapa contiene texto no permitido: $MENSAJE"
printf '  Etapa %s/%s: %s (rama %s, %s archivos)\n  Autor GitLab: %s <%s>\n  Mensaje: %s\n' \
  "$N" "$N_ETAPAS" "$ID" "$RAMA" "$(wc -l < "$PLAN/etapa-$N.lista" | tr -d ' ')" "$NOMBRE" "$CORREO" "$MENSAJE"
[ -n "$RAMA_LOCAL" ] || RAMA_LOCAL="$RAMA-etapa$N"
git check-ref-format --branch "$RAMA_LOCAL" >/dev/null 2>&1 || falla "nombre de rama no válido: $RAMA_LOCAL"

# ------------------------------------------------------------------ 3. base en el clon de GitLab

titulo '3. Base en el clon de GitLab'
if [ -z "$SOBRE" ]; then
  if git -C "$CLON" rev-parse --verify --quiet "refs/remotes/gitlab/$RAMA" >/dev/null; then SOBRE="gitlab/$RAMA"
  else SOBRE="gitlab/$DESTINO"; fi
fi
BASE=$(git -C "$CLON" rev-parse --verify --quiet "$SOBRE^{commit}") || falla "la referencia \"$SOBRE\" no existe en el clon"
printf '  Base: %s = %s\n' "$SOBRE" "$(git -C "$CLON" log -1 --format='%h %an: %s' "$BASE")"
git -C "$CLON" merge-base --is-ancestor "gitlab/$DESTINO" "$BASE" || falla "la base $SOBRE no contiene gitlab/$DESTINO (hay trabajo fusionado que falta).
  Actualice antes la rama personal con desarrollo (merge, sin reescribir historia):
    git -C \"$CLON\" switch $RAMA && git -C \"$CLON\" merge --no-ff gitlab/$DESTINO -m \"Actualizar $RAMA con $DESTINO\"
  o construya la etapa directamente sobre desarrollo: --sobre gitlab/$DESTINO"
if git -C "$CLON" rev-parse --verify --quiet "refs/remotes/gitlab/$RAMA" >/dev/null \
  && ! git -C "$CLON" merge-base --is-ancestor "gitlab/$RAMA" "$BASE"; then
  falla "la base $SOBRE no contiene gitlab/$RAMA: el push a $RAMA no sería de avance rápido (nunca se fuerza).
  Fusione antes gitlab/$RAMA en la base o use --sobre gitlab/$RAMA"
fi

ARBOL="$TMP/arbol"
mkdir -p "$ARBOL"
git -C "$CLON" archive --format=tar "$BASE" | tar -x -f - -C "$ARBOL"

# Archivos de etapas anteriores que la base todavía no tiene o tiene con otro contenido.
PENDIENTES="$TMP/pendientes"; : > "$PENDIENTES"
k=1
while [ "$k" -lt "$N" ]; do
  faltan=0; distintos=0
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    if [ ! -f "$ARBOL/$f" ]; then faltan=$((faltan + 1))
    elif ! cmp -s "$ARBOL/$f" "$LIMPIA/$f"; then distintos=$((distintos + 1)); fi
  done < "$PLAN/etapa-$k.lista"
  if [ "$faltan" -gt 0 ] || [ "$distintos" -gt 0 ]; then
    printf '%s\t%s\t%s\t%s\n' "$k" "$(awk -F "$TAB" -v k="$k" '$1 == k { print $2 "\t" $3 }' "$PLAN/plan.tsv")" "$faltan" "$distintos" >> "$PENDIENTES"
  fi
  k=$((k + 1))
done
if [ -s "$PENDIENTES" ]; then
  while IFS="$TAB" read -r k idk ramak faltan distintos; do
    printf '  AVISO  la base no tiene la etapa %s (%s, rama %s): %s archivo(s) que faltan, %s distinto(s)\n' \
      "$k" "$idk" "$ramak" "$faltan" "$distintos"
  done < "$PENDIENTES"
else
  printf '  OK     la base ya contiene todas las etapas anteriores (1-%s)\n' "$((N - 1))"
fi

# ------------------------------------------------------------------ 4. árbol de la etapa

titulo "4. Árbol de la etapa $N: base + $(wc -l < "$PLAN/etapa-$N.lista" | tr -d ' ') archivos"
node "$HERRAMIENTAS" copiar "$LIMPIA" "$PLAN/etapa-$N.lista" "$ARBOL" || falla 'no se pudieron copiar los archivos de la etapa'
OPCION_README=
[ -f "$ARBOL/README.md" ] || OPCION_README=--sin-readme
entrega_verificar "$ARBOL" "$OPCION_README" > "$TMP/verificacion.log" \
  || { cat "$TMP/verificacion.log"; falla "el árbol de la etapa $ID no pasa las verificaciones"; }
printf '  OK     verificaciones de limpieza%s\n' "$([ -z "$OPCION_README" ] && printf ' y README de la plantilla del evento' || printf ' (sin README todavía)')"

if [ "$PRUEBAS" -eq 1 ]; then
  COPIA="$TMP/pruebas"
  mkdir -p "$COPIA"
  (cd "$ARBOL" && tar -c -f - .) | tar -x -f - -C "$COPIA"
  FALLOS_PRUEBAS=0; PROBADOS=0
  : > "$TMP/pruebas.log"
  if [ -f "$COPIA/backend/package.json" ]; then
    PROBADOS=$((PROBADOS + 1)); _ejecutar_pruebas "$COPIA" backend npm test --silent >> "$TMP/pruebas.log"
  fi
  for componente in authenticator-app sdk demo-portal-tramites attack-lab; do
    if [ -d "$COPIA/$componente/tests" ]; then
      PROBADOS=$((PROBADOS + 1)); _ejecutar_pruebas "$COPIA" "$componente" _pruebas_node >> "$TMP/pruebas.log"
    fi
  done
  cat "$TMP/pruebas.log"
  if [ "$PROBADOS" -gt 0 ]; then
    RESUMEN_PRUEBAS="árbol de la etapa (base + sus archivos) en verde: $(entrega_resumen_pruebas "$TMP/pruebas.log")"
  else
    printf '  (la etapa no contiene todavía componentes con pruebas)\n'
    RESUMEN_PRUEBAS='la etapa no contiene componentes con pruebas; verificaciones de limpieza del árbol en verde'
  fi
  [ "$FALLOS_PRUEBAS" -eq 0 ] || falla "$FALLOS_PRUEBAS componente(s) con pruebas fallidas en el árbol de la etapa"
fi

# ------------------------------------------------------------------ 5. commit y rama local

titulo "5. Commit en el clon (rama local $RAMA_LOCAL)"
if git -C "$CLON" rev-parse --verify --quiet "refs/heads/$RAMA_LOCAL" >/dev/null; then
  [ "$FORZAR" -eq 1 ] || falla "la rama local $RAMA_LOCAL ya existe (use --forzar para rehacerla)"
  [ "$(git -C "$CLON" symbolic-ref --quiet --short HEAD || true)" != "$RAMA_LOCAL" ] \
    || falla "la rama $RAMA_LOCAL es la actual del clon; cambie de rama antes de rehacerla"
fi
INDICE="$TMP/indice"
DIR_GIT=$(git -C "$CLON" rev-parse --absolute-git-dir)
GIT_INDEX_FILE=$INDICE git --git-dir="$DIR_GIT" --work-tree="$ARBOL" -C "$ARBOL" add --all --force .
ARBOL_GIT=$(GIT_INDEX_FILE=$INDICE git -C "$CLON" write-tree)
[ "$ARBOL_GIT" != "$(git -C "$CLON" rev-parse "$BASE^{tree}")" ] || falla "la etapa $ID no añade cambios sobre $SOBRE (¿ya está subida?)"
# Commit detallado: título y cuerpo de etapas-entrega.txt, pruebas ejecutadas y «Closes #<issue>».
ISSUE=$(cat "$PLAN/etapa-$N.issue")
entrega_mensaje_etapa "$PLAN/etapa-$N.mensaje" "$RESUMEN_PRUEBAS" "$ISSUE" > "$TMP/mensaje"
entrega_texto_valido "$(cat "$TMP/mensaje")" || falla 'el mensaje del commit contiene texto no permitido'
NUEVO=$(GIT_AUTHOR_NAME=$NOMBRE GIT_AUTHOR_EMAIL=$CORREO GIT_COMMITTER_NAME=$NOMBRE GIT_COMMITTER_EMAIL=$CORREO \
  git -C "$CLON" commit-tree "$ARBOL_GIT" -p "$BASE" -F "$TMP/mensaje")
git -C "$CLON" branch --force "$RAMA_LOCAL" "$NUEVO"
entrega_historial_valido "$CLON" -1 "$NUEVO" || falla 'el commit contiene autoría o texto no permitido'

# Lo que cambia respecto a la base debe ser exactamente parte de los archivos de la etapa.
git -C "$CLON" diff --name-only "$BASE" "$NUEVO" | sort > "$TMP/cambios"
sort "$PLAN/etapa-$N.lista" > "$TMP/esperados"
FUERA=$(comm -23 "$TMP/cambios" "$TMP/esperados")
[ -z "$FUERA" ] || falla "el commit cambia archivos que no son de la etapa: $FUERA"
printf '  OK     %s  %s <%s>\n         %s archivo(s) cambiados, todos de la etapa; padre %s\n' \
  "$(git -C "$CLON" rev-parse --short "$NUEVO")" "$NOMBRE" "$CORREO" "$(wc -l < "$TMP/cambios" | tr -d ' ')" \
  "$(git -C "$CLON" rev-parse --short "$BASE")"

# ------------------------------------------------------------------ 6. siguientes pasos

titulo 'Siguientes pasos (NO se ha ejecutado nada de esto)'
CORTO=$(git -C "$CLON" rev-parse --short "$NUEVO")
cat <<FIN

  Revisar:   git -C "$CLON" show --stat $RAMA_LOCAL
  Subir (lo hace $NOMBRE con su cuenta; avance rápido, nunca forzado):
             git -C "$CLON" push gitlab $RAMA_LOCAL:$RAMA
  Merge Request $RAMA -> $DESTINO (solo si no hay ya uno abierto de $RAMA; si lo hay, el push lo actualiza):
             GITLAB_TOKEN=<token> sh scripts/mr-gitlab.sh --origen $RAMA --titulo "Etapa $N · $MENSAJE"${ISSUE:+ --issue $ISSUE} --ejecutar
             (sin --ejecutar muestra la petición; siempre con remove_source_branch=false)
  Comprobar en GitLab: Repository > Commits (rama $RAMA) muestra $CORTO con autor $NOMBRE;
             el Merge Request no tiene marcado "Delete source branch".
FIN
if [ -s "$PENDIENTES" ]; then
  cat <<FIN

  ATENCIÓN: esta etapa se construyó sin las etapas anteriores que faltan en la base (arriba).
  Cuando esas etapas se fusionen en $DESTINO, actualice antes de seguir (sin reescribir lo ya subido):
    - si $RAMA_LOCAL NO se ha subido todavía, rehágala encima de $DESTINO actualizado:
        git -C "$CLON" fetch gitlab
        sh scripts/etapa-gitlab.sh --clon "$CLON" --etapa $N --sobre gitlab/$DESTINO --forzar
      (si gitlab/$RAMA tiene commits que $DESTINO no tiene, fusione primero $DESTINO en $RAMA, abajo)
    - si ya se subió, fusione $DESTINO en la rama personal antes de la etapa siguiente:
        git -C "$CLON" fetch gitlab
        git -C "$CLON" switch $RAMA && git -C "$CLON" merge --ff-only gitlab/$RAMA
        git -C "$CLON" merge --no-ff gitlab/$DESTINO -m "Actualizar $RAMA con $DESTINO"
        git -C "$CLON" push gitlab $RAMA
FIN
fi
