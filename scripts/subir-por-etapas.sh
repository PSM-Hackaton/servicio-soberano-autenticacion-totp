#!/bin/sh
# SUBIDA PROGRESIVA (día 1): reconstruye la copia limpia como una serie de commits por etapas.
#
#   1. Genera y verifica la copia limpia completa (mismas funciones que preparar-entrega.sh:
#      exportar, excluir, ajustar enlaces, verificar y probar).
#   2. Reparte sus archivos en las etapas de scripts/etapas-entrega.txt (ninguno sin etapa).
#   3. Crea en la carpeta de salida un repositorio git nuevo y aplica cada etapa como un commit
#      con su autor y su mensaje (hora real), verificando el árbol antes de cada commit.
#   4. Modelo de ramas: historia LINEAL en la rama local "integracion" (nunca se sube). Cada commit
#      mueve además la rama de trabajo de su autor (diego o laya) hasta él, por avance rápido; es
#      lo mismo que si cada persona actualizara su rama con la del compañero antes de su commit.
#      Así ningún push necesita forzarse y ambas ramas comparten historia.
#   5. Con --subir, tras cada commit muestra "git push gitlab <rama>" y lo ejecuta solo si se
#      escribe SI. Sin --subir solo prepara el repositorio y muestra el plan de subida.
#   6. Prepara la rama "avance" como merge (--no-ff) de las ramas de trabajo, deja el estado para
#      sincronizar-gitlab.sh e imprime cómo abrir los Merge Request en GitLab (no los abre).
#
# Uso: sh scripts/subir-por-etapas.sh --autor-laya "Nombre Apellido <correo>" [opciones]
# Requisitos: sh POSIX, git y Node.js 22 o superior. Sin dependencias externas.

set -eu

uso() {
  cat <<'FIN'
Uso: sh scripts/subir-por-etapas.sh --autor-laya "Nombre Apellido <correo>" [opciones]

  --autor-laya "N <c>"  autor de las etapas de Juan Laya (obligatorio: sustituye AUTOR_LAYA)
  --ref REF             referencia git a entregar. Por defecto: HEAD
  --salida DIR          carpeta del repositorio de la entrega (vacía o inexistente).
                        Por defecto: ../entrega-gitlab respecto a la raíz del repositorio
  --forzar              borra la carpeta de salida si es una entrega anterior
  --permitidos ARCH     lista de hallazgos aceptados (como en preparar-entrega.sh)
  --subir               tras cada commit, ofrece "git push gitlab <rama>" (requiere --remoto)
  --remoto URL          configura el remoto "gitlab" del repositorio de la entrega con esa URL
  -h, --help            muestra esta ayuda

La confirmación de cada push se lee de la entrada estándar: solo "SI" (en mayúsculas) sube.
Nunca fuerza un push ni abre Merge Request.
FIN
}

DIR_SCRIPT=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=scripts/entrega-comun.sh
. "$DIR_SCRIPT/entrega-comun.sh"

# ------------------------------------------------------------------ argumentos

REF=HEAD
SALIDA=
FORZAR=0
PERMITIDOS=
SUBIR=0
REMOTO=
AUTOR_LAYA=
HAY_AUTOR_LAYA=0
while [ $# -gt 0 ]; do
  case "$1" in
    --autor-laya) [ $# -ge 2 ] || falla 'falta el valor de --autor-laya'; AUTOR_LAYA=$2; HAY_AUTOR_LAYA=1; shift 2 ;;
    --ref) [ $# -ge 2 ] || falla 'falta el valor de --ref'; REF=$2; shift 2 ;;
    --salida) [ $# -ge 2 ] || falla 'falta el valor de --salida'; SALIDA=$2; shift 2 ;;
    --forzar) FORZAR=1; shift ;;
    --permitidos) [ $# -ge 2 ] || falla 'falta el valor de --permitidos'; PERMITIDOS=$2; shift 2 ;;
    --subir) SUBIR=1; shift ;;
    --remoto) [ $# -ge 2 ] || falla 'falta el valor de --remoto'; REMOTO=$2; shift 2 ;;
    -h|--help) uso; exit 0 ;;
    *) uso >&2; falla "opción desconocida: $1" ;;
  esac
done
[ "$SUBIR" -eq 0 ] || [ -n "$REMOTO" ] || falla '--subir requiere --remoto URL (la dirección del proyecto en el GitLab del evento)'

# ------------------------------------------------------------------ entorno

entrega_entorno
[ -f "$ETAPAS" ] || falla "no existe $ETAPAS"
if [ "$HAY_AUTOR_LAYA" -eq 0 ] && grep -Eq '^[[:space:]]*autor[[:space:]]+AUTOR_LAYA[[:space:]]*$' "$ETAPAS"; then
  falla 'hay etapas de Juan Laya (autor AUTOR_LAYA): indique su identidad con --autor-laya "Nombre Apellido <correo>"'
fi
entrega_permitidos
[ -n "$SALIDA" ] || SALIDA="$RAIZ/../entrega-gitlab"
SALIDA=$(entrega_absoluta "$SALIDA")
entrega_validar_salida "$SALIDA"
entrega_autor_repositorio
COMMIT=$(entrega_commit "$REF") || exit 1
COMMIT_CORTO=$(git -C "$RAIZ" rev-parse --short "$COMMIT")
entrega_temporales subir-por-etapas

printf 'Subida progresiva por etapas\n'
printf '  Repositorio: %s\n' "$RAIZ"
printf '  Referencia:  %s (%s)\n' "$REF" "$COMMIT_CORTO"
printf '  Salida:      %s\n' "$SALIDA"
printf '  Ejecuta:     %s <%s> (confirma los commits; el autor es el de cada etapa)\n' "$AUTOR_NOMBRE" "$AUTOR_CORREO"
if [ "$SUBIR" -eq 1 ]; then
  printf '  Modo:        --subir: se pedirá SI antes de cada push a %s\n' "$REMOTO"
else
  printf '  Modo:        solo preparar (sin --subir no se ejecuta ningún push)\n'
fi
if [ "$REF" = HEAD ] && [ -n "$(git -C "$RAIZ" status --porcelain --untracked-files=no)" ]; then
  printf '  AVISO: hay cambios sin commit en el repositorio; solo se incluye lo confirmado en %s.\n' "$COMMIT_CORTO"
fi

# ------------------------------------------------------------------ 1. copia limpia completa

titulo '1. Copia limpia completa (exportar, excluir, ajustar, verificar y probar)'
LIMPIA="$TMP/limpia"
mkdir -p "$LIMPIA"
entrega_copia_limpia "$COMMIT" "$LIMPIA"
printf '  %s archivos en la copia limpia (%s excluidos)\n' \
  "$(find "$LIMPIA" -type f | wc -l | tr -d ' ')" "$(wc -l < "$LIMPIA.excluidos" | tr -d ' ')"
grep -E 'AVISO|CORREGIDO' "$LIMPIA.registro" || true
entrega_verificar "$LIMPIA" || falla 'la copia limpia no pasa las verificaciones; corrija el repositorio de trabajo'
entrega_probar "$LIMPIA" "$TMP/pruebas" || falla "$FALLOS_PRUEBAS comprobación(es) de pruebas fallaron sobre la copia limpia"

# ------------------------------------------------------------------ 2. plan de etapas

titulo '2. Plan de etapas (scripts/etapas-entrega.txt)'
PLAN="$TMP/plan"
mkdir -p "$PLAN"
if [ "$HAY_AUTOR_LAYA" -eq 1 ]; then
  node "$HERRAMIENTAS" etapas "$LIMPIA" "$ETAPAS" "$EXCLUSIONES" "$PLAN" --autor-laya "$AUTOR_LAYA" \
    || falla 'el plan de etapas no es válido'
else
  node "$HERRAMIENTAS" etapas "$LIMPIA" "$ETAPAS" "$EXCLUSIONES" "$PLAN" || falla 'el plan de etapas no es válido'
fi
N_ETAPAS=$(wc -l < "$PLAN/plan.tsv" | tr -d ' ')

# ------------------------------------------------------------------ 3. repositorio y commits

titulo "3. Repositorio de la entrega y $N_ETAPAS commits por etapas"
entrega_preparar_salida "$SALIDA" "$FORZAR"
git init --quiet --template= -b integracion "$SALIDA"
git -C "$SALIDA" config user.name "$AUTOR_NOMBRE"
git -C "$SALIDA" config user.email "$AUTOR_CORREO"
[ -z "$REMOTO" ] || git -C "$SALIDA" remote add gitlab "$REMOTO"

TAB=$(printf '\t')
SUBIDAS=
OMITIDAS=
ORDEN_RAMAS=
exec 3<&0
while IFS="$TAB" read -r N ID RAMA NOMBRE CORREO N_ARCH MENSAJE; do
  printf '\n  -- Etapa %s/%s: %s (%s, rama %s, %s archivos)\n' "$N" "$N_ETAPAS" "$ID" "$NOMBRE" "$RAMA" "$N_ARCH"
  node "$HERRAMIENTAS" copiar "$LIMPIA" "$PLAN/etapa-$N.lista" "$SALIDA" || falla "no se pudieron copiar los archivos de la etapa $ID"
  # El README de 6 apartados entra en una etapa concreta; antes de ella no se exige.
  OPCION_README=--sin-readme
  [ -f "$SALIDA/README.md" ] && OPCION_README=
  entrega_verificar "$SALIDA" "$OPCION_README" > "$TMP/verificacion.log" \
    || { cat "$TMP/verificacion.log"; falla "la etapa $ID no pasa las verificaciones"; }
  printf '  Verificaciones: OK%s\n' "$([ -n "$OPCION_README" ] && printf ' (README aún no incorporado)' || true)"
  entrega_git "$SALIDA" add --all --force .
  if entrega_git "$SALIDA" diff --cached --quiet; then falla "la etapa $ID no añade cambios"; fi
  entrega_confirmar_commit "$SALIDA" "$MENSAJE" "$NOMBRE" "$CORREO"
  entrega_git "$SALIDA" branch --force "$RAMA" HEAD
  # Orden en que cada rama recibió su último commit (para preparar avance).
  ORDEN_RAMAS="$(printf '%s\n' $ORDEN_RAMAS | grep -vx "$RAMA" || true) $RAMA"
  printf '  Commit: %s  ->  rama %s\n' "$(git -C "$SALIDA" log -1 --format='%h  %an <%ae>  %s' HEAD)" "$RAMA"
  if [ "$SUBIR" -eq 1 ]; then
    # La respuesta se lee del descriptor 3 (entrada estándar original): la del bucle es el plan.
    entrega_subir_rama "$SALIDA" "$RAMA" <&3 \
      || falla "falló git push gitlab $RAMA; revise el remoto (no se fuerza nunca)"
  else
    printf '  Se subiría con: git push gitlab %s   (solo con --subir)\n' "$RAMA"
  fi
done < "$PLAN/plan.tsv"

# ------------------------------------------------------------------ 4. comprobaciones

titulo '4. Comprobaciones del repositorio'
N_COMMITS=$(git -C "$SALIDA" rev-list --count integracion)
[ "$N_COMMITS" -eq "$N_ETAPAS" ] || falla "se esperaban $N_ETAPAS commits y hay $N_COMMITS"
git -C "$SALIDA" log --format='%an%n%ae%n%cn%n%ce%n%B' integracion | grep -Eiq "$LIMITE_PALABRAS" \
  && falla 'algún commit contiene autoría o texto no permitido'
[ -z "$(git -C "$SALIDA" status --porcelain)" ] || falla 'el repositorio de la entrega quedó con cambios sin confirmar'
# Árbol final idéntico a la copia limpia (contenido y permisos), comparado como árbol git.
ARBOL_LIMPIO=$(GIT_INDEX_FILE="$TMP/indice" git -C "$LIMPIA" --git-dir="$SALIDA/.git" --work-tree="$LIMPIA" add --all --force . \
  && GIT_INDEX_FILE="$TMP/indice" git -C "$LIMPIA" --git-dir="$SALIDA/.git" write-tree)
[ "$ARBOL_LIMPIO" = "$(git -C "$SALIDA" rev-parse 'integracion^{tree}')" ] \
  || falla 'el árbol final no coincide con la copia limpia'
printf '  OK     %s commits; árbol final idéntico a la copia limpia (%s archivos)\n' \
  "$N_COMMITS" "$(git -C "$SALIDA" ls-files | wc -l | tr -d ' ')"

# ------------------------------------------------------------------ 5. avance

titulo '5. Rama avance (merge de las ramas de trabajo)'
set -- $ORDEN_RAMAS
PRIMERA=$1
entrega_git "$SALIDA" branch avance "$PRIMERA"
if [ $# -gt 1 ]; then
  shift
  entrega_git "$SALIDA" switch --quiet avance
  for OTRA in "$@"; do
    GIT_AUTHOR_NAME=$AUTOR_NOMBRE GIT_AUTHOR_EMAIL=$AUTOR_CORREO \
    GIT_COMMITTER_NAME=$AUTOR_NOMBRE GIT_COMMITTER_EMAIL=$AUTOR_CORREO \
      entrega_git "$SALIDA" merge --quiet --no-ff --no-edit \
        -m "Cierre del día: integrar la rama $OTRA en avance" "$OTRA"
  done
  entrega_git "$SALIDA" switch --quiet integracion
fi
entrega_git "$SALIDA" diff --quiet avance integracion -- || falla 'avance no contiene todo lo de las ramas de trabajo'
for R in $ORDEN_RAMAS; do
  git -C "$SALIDA" merge-base --is-ancestor "$R" avance || falla "avance no contiene la rama $R"
done
printf '  OK     avance = %s (contiene %s; mismo árbol que la copia limpia)\n' \
  "$(git -C "$SALIDA" log -1 --format='%h %s' avance)" "$(echo $ORDEN_RAMAS | sed 's/ / y /g')"
entrega_guardar_estado "$SALIDA" "$COMMIT"
printf '  Estado para sincronizar-gitlab.sh: ultimo=%s (en %s)\n' "$COMMIT_CORTO" "$(entrega_archivo_estado "$SALIDA")"

# ------------------------------------------------------------------ resumen e instrucciones

titulo 'Historial preparado'
git -C "$SALIDA" log --reverse --format='  %h  %<(16,trunc)%an  %s' integracion
printf '\n  Ramas: %s\n' "$(git -C "$SALIDA" for-each-ref --format='%(refname:short)=%(objectname:short)' refs/heads | tr '\n' ' ')"

if [ "$SUBIR" -eq 1 ]; then
  printf '  Subidas: %s\n' "${SUBIDAS:-ninguna}"
  [ -z "$OMITIDAS" ] || printf '  Omitidas (no se subieron): %s\n' "$OMITIDAS"
fi

titulo 'Siguientes pasos (NO se ha ejecutado nada de esto)'
if [ "$SUBIR" -eq 0 ]; then
  cat <<FIN

  Para subir las etapas de una en una, repita con --subir y la URL del proyecto:
    sh scripts/subir-por-etapas.sh --autor-laya "<Nombre> <correo>" --forzar --subir --remoto <URL>
  o, en esta carpeta, empuje cada rama tras revisar el historial:
    cd "$SALIDA"
    git remote add gitlab <URL>
FIN
  for R in $ORDEN_RAMAS; do printf '    git push gitlab %s\n' "$R"; done
fi
cat <<FIN

  Cierre del día (Merge Request diario hacia avance), en la web de GitLab:
    1. Si la rama avance no existe aún en GitLab, créela desde el primer commit:
         git -C "$SALIDA" push gitlab $(git -C "$SALIDA" rev-list --max-parents=0 integracion | cut -c1-12):refs/heads/avance
    2. Code > Merge requests > New merge request.
FIN
for R in $ORDEN_RAMAS; do
  printf '         Origen: %s  ->  Destino: avance   (título: "Cierre del día: rama %s")\n' "$R" "$R"
done
cat <<FIN
       Como las ramas comparten historia, basta el Merge Request de la rama más adelantada
       (la última de la lista); el de la otra quedará sin cambios y se puede cerrar.
    3. Revise que el diff coincide con lo preparado aquí (la rama local avance muestra el resultado)
       y haga el merge. No marque "Squash commits": se perdería el historial por etapas.
  La rama local "integracion" es solo de trabajo: no la suba.
  Días siguientes: sh scripts/sincronizar-gitlab.sh --entrega "$SALIDA" --hasta <rama de GitHub>
FIN
