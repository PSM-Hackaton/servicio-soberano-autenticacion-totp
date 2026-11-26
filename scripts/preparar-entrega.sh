#!/bin/sh
# Prepara la ENTREGA LIMPIA para el GitLab del evento, sin subir nada.
#
#   1. Exporta el árbol de una referencia git (sin historial) a una carpeta nueva.
#   2. Quita el material interno (scripts/exclusiones-entrega.txt).
#   3. Revisa enlaces y menciones a lo excluido; corrige README.md y ARCHITECTURE.md en la copia.
#   4. Verifica la copia: cadenas prohibidas, rutas /home/, secretos, tamaño, README de 6 apartados.
#   5. Ejecuta las pruebas de todos los componentes y la instalación mínima en una copia temporal.
#   6. Crea en la carpeta de salida un repositorio git nuevo (rama avance; terminado con --final)
#      con un único commit e imprime los comandos para subirlo. No añade remotos ni hace push.
#
# Uso: sh scripts/preparar-entrega.sh [--ref REF] [--salida DIR] [--final] [--forzar] [--permitidos ARCHIVO]
# Requisitos: sh POSIX, git y Node.js 22 o superior. Sin dependencias externas.

set -eu

MENSAJE_COMMIT='Entrega: Servicio Soberano de Autenticación Multifactorial basado en Tiempo'
LIMITE_PALABRAS='claude|anthropic|gemini|chatgpt|openai|copilot|co-authored-by|\[bot\]|noreply'

uso() {
  cat <<'FIN'
Uso: sh scripts/preparar-entrega.sh [opciones]

  --ref REF            referencia git a exportar (rama, etiqueta o commit). Por defecto: HEAD
  --salida DIR         carpeta de salida (no debe existir o debe estar vacía).
                       Por defecto: ../entrega-gitlab respecto a la raíz del repositorio
  --final              crea también la rama "terminado" (entrega final) en el mismo commit
  --forzar             borra la carpeta de salida si ya existe (solo si es una entrega anterior)
  --permitidos ARCH    lista de hallazgos aceptados (formato: "marcas|rutas|secretos <ruta>")
  -h, --help           muestra esta ayuda

No ejecuta git push ni configura remotos: al final imprime los comandos para hacerlo.
FIN
}

titulo() { printf '\n== %s\n' "$1"; }
falla() { printf '\nERROR: %s\n' "$1" >&2; exit 1; }

# ------------------------------------------------------------------ argumentos

REF=HEAD
SALIDA=
FINAL=0
FORZAR=0
PERMITIDOS=
while [ $# -gt 0 ]; do
  case "$1" in
    --ref) [ $# -ge 2 ] || falla 'falta el valor de --ref'; REF=$2; shift 2 ;;
    --salida) [ $# -ge 2 ] || falla 'falta el valor de --salida'; SALIDA=$2; shift 2 ;;
    --final) FINAL=1; shift ;;
    --forzar) FORZAR=1; shift ;;
    --permitidos) [ $# -ge 2 ] || falla 'falta el valor de --permitidos'; PERMITIDOS=$2; shift 2 ;;
    -h|--help) uso; exit 0 ;;
    *) uso >&2; falla "opción desconocida: $1" ;;
  esac
done

# ------------------------------------------------------------------ entorno

command -v git >/dev/null 2>&1 || falla 'no se encontró git'
command -v node >/dev/null 2>&1 || falla 'no se encontró node (se requiere Node.js 22 o superior)'
VERSION_NODE=$(node -p 'process.versions.node.split(".")[0]')
[ "$VERSION_NODE" -ge 22 ] || falla "se requiere Node.js 22 o superior (hay $(node --version))"

DIR_SCRIPT=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
RAIZ=$(git -C "$DIR_SCRIPT" rev-parse --show-toplevel) || falla 'el script debe estar dentro del repositorio'
HERRAMIENTAS="$DIR_SCRIPT/entrega-herramientas.mjs"
EXCLUSIONES="$DIR_SCRIPT/exclusiones-entrega.txt"
[ -f "$HERRAMIENTAS" ] || falla "no existe $HERRAMIENTAS"
[ -f "$EXCLUSIONES" ] || falla "no existe $EXCLUSIONES"
if [ -n "$PERMITIDOS" ]; then
  [ -f "$PERMITIDOS" ] || falla "no existe la lista de permitidos $PERMITIDOS"
  PERMITIDOS=$(CDPATH='' cd -- "$(dirname -- "$PERMITIDOS")" && pwd)/$(basename -- "$PERMITIDOS")
fi

[ -n "$SALIDA" ] || SALIDA="$RAIZ/../entrega-gitlab"
mkdir -p -- "$(dirname -- "$SALIDA")"
SALIDA=$(CDPATH='' cd -- "$(dirname -- "$SALIDA")" && pwd)/$(basename -- "$SALIDA")

# La salida nunca puede ser el repositorio, estar dentro de él ni contenerlo.
case "$SALIDA/" in
  "$RAIZ"/*) falla "la carpeta de salida ($SALIDA) no puede estar dentro del repositorio ($RAIZ)" ;;
esac
case "$RAIZ/" in
  "$SALIDA"/*) falla "la carpeta de salida ($SALIDA) no puede contener el repositorio" ;;
esac
[ "$SALIDA" != "/" ] && [ "$SALIDA" != "${HOME:-/}" ] || falla "carpeta de salida no permitida: $SALIDA"

# Autor: persona del equipo configurada en el repositorio original.
AUTOR_NOMBRE=$(git -C "$RAIZ" config user.name || true)
AUTOR_CORREO=$(git -C "$RAIZ" config user.email || true)
[ -n "$AUTOR_NOMBRE" ] && [ -n "$AUTOR_CORREO" ] \
  || falla 'configure el autor en el repositorio: git config user.name "Nombre Apellido" y git config user.email "correo@dominio"'
if printf '%s %s\n' "$AUTOR_NOMBRE" "$AUTOR_CORREO" | grep -Eiq "$LIMITE_PALABRAS"; then
  falla "el autor configurado ($AUTOR_NOMBRE <$AUTOR_CORREO>) no parece una persona del equipo"
fi

COMMIT=$(git -C "$RAIZ" rev-parse --verify --quiet "$REF^{commit}") || falla "la referencia '$REF' no existe"
COMMIT_CORTO=$(git -C "$RAIZ" rev-parse --short "$COMMIT")

# ------------------------------------------------------------------ temporales

TMP=$(mktemp -d "${TMPDIR:-/tmp}/preparar-entrega.XXXXXX")
limpiar() { rm -rf -- "$TMP"; }
trap limpiar EXIT
trap 'exit 130' INT TERM

printf 'Preparación de la entrega\n'
printf '  Repositorio: %s\n' "$RAIZ"
printf '  Referencia:  %s (%s)\n' "$REF" "$COMMIT_CORTO"
printf '  Salida:      %s\n' "$SALIDA"
printf '  Autor:       %s <%s>\n' "$AUTOR_NOMBRE" "$AUTOR_CORREO"
printf '  Ramas:       avance%s\n' "$([ "$FINAL" -eq 1 ] && printf ' y terminado' || true)"
if [ "$REF" = HEAD ] && [ -n "$(git -C "$RAIZ" status --porcelain --untracked-files=no)" ]; then
  printf '  AVISO: hay cambios sin commit en el repositorio; la entrega solo incluye lo confirmado en %s.\n' "$COMMIT_CORTO"
fi

# ------------------------------------------------------------------ 1. exportar

titulo '1. Exportación con git archive (sin historial)'
if [ -e "$SALIDA" ] && [ -n "$(ls -A -- "$SALIDA" 2>/dev/null)" ]; then
  [ "$FORZAR" -eq 1 ] || falla "la carpeta de salida ya existe y no está vacía: $SALIDA (use --forzar para rehacerla)"
  # Solo se borra si parece una entrega anterior: un repositorio git con la rama avance.
  if [ -d "$SALIDA/.git" ] && git -C "$SALIDA" rev-parse --verify --quiet refs/heads/avance >/dev/null; then
    rm -rf -- "$SALIDA"
  else
    falla "--forzar solo borra entregas anteriores; $SALIDA no lo parece. Bórrela a mano si está seguro."
  fi
fi
mkdir -p -- "$SALIDA"
git -C "$RAIZ" archive --format=tar "$COMMIT" | tar -x -f - -C "$SALIDA"
printf '  %s archivos exportados desde %s\n' "$(find "$SALIDA" -type f | wc -l | tr -d ' ')" "$COMMIT_CORTO"

# ------------------------------------------------------------------ 2. exclusiones

titulo '2. Exclusión de material interno'
node "$HERRAMIENTAS" excluir "$SALIDA" "$EXCLUSIONES" > "$TMP/excluidos.txt"
if [ -s "$TMP/excluidos.txt" ]; then
  sed 's/^/  - /' "$TMP/excluidos.txt"
  printf '  %s archivo(s) excluido(s)\n' "$(wc -l < "$TMP/excluidos.txt" | tr -d ' ')"
else
  printf '  Nada que excluir.\n'
fi

# ------------------------------------------------------------------ 3. enlaces

titulo '3. Enlaces y menciones a material excluido'
node "$HERRAMIENTAS" ajustar "$SALIDA" "$TMP/excluidos.txt"

# ------------------------------------------------------------------ 4. verificaciones

titulo '4. Verificaciones de limpieza'
if [ -n "$PERMITIDOS" ]; then
  node "$HERRAMIENTAS" verificar "$SALIDA" "$PERMITIDOS" || falla "la copia no está limpia; revise los hallazgos (la copia queda en $SALIDA para inspección)"
else
  node "$HERRAMIENTAS" verificar "$SALIDA" || falla "la copia no está limpia; revise los hallazgos (la copia queda en $SALIDA para inspección)"
fi

# ------------------------------------------------------------------ 5. pruebas aisladas

titulo '5. Pruebas e instalación mínima sobre una copia aislada'
PRUEBAS="$TMP/copia"
mkdir -p "$PRUEBAS"
cp -R "$SALIDA/." "$PRUEBAS/"

FALLOS_PRUEBAS=0
resumen_pruebas() {
  # $1 = nombre, $2 = registro
  total=$(sed -n 's/^ℹ tests \([0-9]*\).*/\1/p' "$2" | tail -n 1)
  ok=$(sed -n 's/^ℹ pass \([0-9]*\).*/\1/p' "$2" | tail -n 1)
  mal=$(sed -n 's/^ℹ fail \([0-9]*\).*/\1/p' "$2" | tail -n 1)
  printf '%s pruebas, %s correctas, %s fallidas' "${total:-?}" "${ok:-?}" "${mal:-?}"
}

ejecutar_pruebas() {
  # $1 = componente; el resto, la orden a ejecutar dentro de él
  componente=$1; shift
  registro="$TMP/pruebas-$(printf '%s' "$componente" | tr '/' '-').log"
  if [ ! -d "$PRUEBAS/$componente" ]; then
    printf '  FALLA  %s: no existe la carpeta\n' "$componente"; FALLOS_PRUEBAS=$((FALLOS_PRUEBAS + 1)); return 0
  fi
  if (cd "$PRUEBAS/$componente" && "$@") > "$registro" 2>&1; then
    printf '  OK     %-22s %s\n' "$componente" "$(resumen_pruebas "$componente" "$registro")"
  else
    printf '  FALLA  %-22s %s\n' "$componente" "$(resumen_pruebas "$componente" "$registro")"
    tail -n 40 "$registro" | sed 's/^/           | /'
    FALLOS_PRUEBAS=$((FALLOS_PRUEBAS + 1))
  fi
}

pruebas_node() {
  # Ejecuta node --test con los *.test.js / *.test.mjs de tests/ del componente actual.
  set --
  for f in tests/*.test.js tests/*.test.mjs; do
    [ -f "$f" ] && set -- "$@" "$f"
  done
  [ $# -gt 0 ] || { echo 'No hay archivos de prueba en tests/'; return 1; }
  node --test --test-reporter=spec "$@"
}

ejecutar_pruebas backend npm test --silent
for componente in authenticator-app sdk demo-portal-tramites attack-lab; do
  ejecutar_pruebas "$componente" pruebas_node
done

# Instalación mínima: generar el .env con secretos aleatorios en una ruta temporal.
mkdir -p "$TMP/env"
if (cd "$PRUEBAS/backend" && node scripts/generar-env.js --salida "$TMP/env/.env") > "$TMP/env.log" 2>&1; then
  node "$HERRAMIENTAS" env "$TMP/env/.env" || FALLOS_PRUEBAS=$((FALLOS_PRUEBAS + 1))
else
  printf '  FALLA  node scripts/generar-env.js\n'; sed 's/^/           | /' "$TMP/env.log"
  FALLOS_PRUEBAS=$((FALLOS_PRUEBAS + 1))
fi

[ "$FALLOS_PRUEBAS" -eq 0 ] || falla "$FALLOS_PRUEBAS comprobación(es) de pruebas fallaron; la entrega no funciona aislada (copia en $SALIDA)"

# La copia de salida no debe haber cambiado con las pruebas (se ejecutaron en otra carpeta).
node "$HERRAMIENTAS" verificar "$SALIDA" ${PERMITIDOS:+"$PERMITIDOS"} > /dev/null \
  || falla 'la copia cambió durante las pruebas; repita la preparación'

# ------------------------------------------------------------------ 6. repositorio nuevo

titulo '6. Repositorio git nuevo de la entrega'
git init --quiet --template= -b avance "$SALIDA"
(
  cd "$SALIDA"
  export GIT_AUTHOR_NAME="$AUTOR_NOMBRE" GIT_AUTHOR_EMAIL="$AUTOR_CORREO"
  export GIT_COMMITTER_NAME="$AUTOR_NOMBRE" GIT_COMMITTER_EMAIL="$AUTOR_CORREO"
  G() { git -c core.hooksPath=/dev/null -c commit.gpgsign=false -c commit.template= \
            -c user.name="$AUTOR_NOMBRE" -c user.email="$AUTOR_CORREO" "$@"; }
  # --force: la copia ya está filtrada; todo lo que contiene debe quedar versionado.
  G add --all --force .
  G commit --quiet --no-verify -m "$MENSAJE_COMMIT"
  [ "$FINAL" -eq 1 ] && G branch terminado avance
  # Autor del equipo también para commits posteriores en esta carpeta (p. ej. ramas de Merge Request).
  git config user.name "$AUTOR_NOMBRE"
  git config user.email "$AUTOR_CORREO"
)

# Comprobaciones del repositorio creado.
N_COMMITS=$(git -C "$SALIDA" rev-list --count avance)
[ "$N_COMMITS" -eq 1 ] || falla "se esperaba un único commit y hay $N_COMMITS"
git -C "$SALIDA" log -1 --format='%an%n%ae%n%cn%n%ce%n%B' avance | grep -Eiq "$LIMITE_PALABRAS" \
  && falla 'el commit contiene autoría o texto no permitido'
N_VERSIONADOS=$(git -C "$SALIDA" ls-files | wc -l | tr -d ' ')
N_ARCHIVOS=$(find "$SALIDA" -path "$SALIDA/.git" -prune -o -type f -print | wc -l | tr -d ' ')
[ "$N_VERSIONADOS" -eq "$N_ARCHIVOS" ] || falla "hay $N_ARCHIVOS archivos en la copia pero solo $N_VERSIONADOS versionados"
[ -z "$(git -C "$SALIDA" status --porcelain)" ] || falla 'el repositorio de la entrega quedó con cambios sin confirmar'
[ -z "$(git -C "$SALIDA" remote)" ] || falla 'el repositorio de la entrega no debe tener remotos'

printf '  Commit:   %s\n' "$(git -C "$SALIDA" log -1 --format='%h  %an <%ae>  %s' avance)"
printf '  Ramas:    %s\n' "$(git -C "$SALIDA" for-each-ref --format='%(refname:short)' refs/heads | tr '\n' ' ')"
printf '  Archivos: %s versionados\n' "$N_VERSIONADOS"

# ------------------------------------------------------------------ comandos para subir

titulo 'Entrega preparada. Para subirla al GitLab del evento (NO se ha ejecutado nada de esto):'
cat <<FIN

  cd "$SALIDA"
  git remote add gitlab <URL>
  git push gitlab avance
FIN
[ "$FINAL" -eq 1 ] && printf '  git push gitlab terminado\n'
cat <<'FIN'

  <URL> es la dirección del proyecto en el GitLab del evento (botón "Clone").
  Si el proyecto de GitLab ya tiene historial en esas ramas, el push será rechazado:
  no lo fuerce; consulte scripts/README-entrega.md (sección "Si GitLab ya tiene historial").
FIN
