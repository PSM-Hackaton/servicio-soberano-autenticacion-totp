# Funciones comunes de la preparación de la entrega (sh POSIX). No se ejecuta: se carga con
#   DIR_SCRIPT=...; . "$DIR_SCRIPT/entrega-comun.sh"
# desde preparar-entrega.sh, subir-por-etapas.sh y sincronizar-gitlab.sh.
#
# Variables que usa o define:
#   DIR_SCRIPT (entrada)   carpeta scripts/ del repositorio
#   RAIZ, HERRAMIENTAS, EXCLUSIONES, ETAPAS   rutas del repositorio y de los archivos de apoyo
#   PERMITIDOS             lista de hallazgos aceptados (vacía si no hay)
#   AUTOR_NOMBRE, AUTOR_CORREO   persona del equipo configurada en el repositorio original
#   TMP                    carpeta temporal (la crea entrega_temporales y se borra al salir)

LIMITE_PALABRAS='claude|anthropic|gemini|chatgpt|openai|copilot|co-authored-by|\[bot\]|noreply'

titulo() { printf '\n== %s\n' "$1"; }
falla() { printf '\nERROR: %s\n' "$1" >&2; exit 1; }

# ------------------------------------------------------------------ entorno

# Comprueba git y Node.js 22+, y fija RAIZ, HERRAMIENTAS, EXCLUSIONES y ETAPAS a partir de DIR_SCRIPT.
entrega_entorno() {
  command -v git >/dev/null 2>&1 || falla 'no se encontró git'
  command -v node >/dev/null 2>&1 || falla 'no se encontró node (se requiere Node.js 22 o superior)'
  version_node=$(node -p 'process.versions.node.split(".")[0]')
  [ "$version_node" -ge 22 ] || falla "se requiere Node.js 22 o superior (hay $(node --version))"
  RAIZ=$(git -C "$DIR_SCRIPT" rev-parse --show-toplevel) || falla 'el script debe estar dentro del repositorio'
  HERRAMIENTAS="$DIR_SCRIPT/entrega-herramientas.mjs"
  EXCLUSIONES="$DIR_SCRIPT/exclusiones-entrega.txt"
  ETAPAS="$DIR_SCRIPT/etapas-entrega.txt"
  [ -f "$HERRAMIENTAS" ] || falla "no existe $HERRAMIENTAS"
  [ -f "$EXCLUSIONES" ] || falla "no existe $EXCLUSIONES"
}

# Ruta absoluta de un archivo o carpeta cuyo directorio padre existe (o se crea).
entrega_absoluta() {
  mkdir -p -- "$(dirname -- "$1")"
  printf '%s/%s\n' "$(CDPATH='' cd -- "$(dirname -- "$1")" && pwd)" "$(basename -- "$1")"
}

# Normaliza PERMITIDOS a ruta absoluta (si se indicó) y comprueba que existe.
entrega_permitidos() {
  [ -n "${PERMITIDOS:-}" ] || { PERMITIDOS=; return 0; }
  [ -f "$PERMITIDOS" ] || falla "no existe la lista de permitidos $PERMITIDOS"
  PERMITIDOS=$(entrega_absoluta "$PERMITIDOS")
}

# La carpeta $1 no puede ser el repositorio, estar dentro de él ni contenerlo.
entrega_validar_salida() {
  case "$1/" in
    "$RAIZ"/*) falla "la carpeta de salida ($1) no puede estar dentro del repositorio ($RAIZ)" ;;
  esac
  case "$RAIZ/" in
    "$1"/*) falla "la carpeta de salida ($1) no puede contener el repositorio" ;;
  esac
  [ "$1" != "/" ] && [ "$1" != "${HOME:-/}" ] || falla "carpeta de salida no permitida: $1"
}

# Prepara la carpeta de salida $1 (vacía). Con $2 = 1 borra una entrega anterior (repositorio con rama avance).
entrega_preparar_salida() {
  if [ -e "$1" ] && [ -n "$(ls -A -- "$1" 2>/dev/null)" ]; then
    [ "$2" -eq 1 ] || falla "la carpeta de salida ya existe y no está vacía: $1 (use --forzar para rehacerla)"
    if [ -d "$1/.git" ] && git -C "$1" rev-parse --verify --quiet refs/heads/avance >/dev/null; then
      rm -rf -- "$1"
    else
      falla "--forzar solo borra entregas anteriores; $1 no lo parece. Bórrela a mano si está seguro."
    fi
  fi
  mkdir -p -- "$1"
}

# 0 si "$1 $2" (nombre y correo) parece una persona del equipo, no una cuenta automática o una herramienta.
entrega_identidad_valida() {
  [ -n "$1" ] && [ -n "$2" ] || return 1
  ! printf '%s %s\n' "$1" "$2" | grep -Eiq "$LIMITE_PALABRAS"
}

# 0 si el texto $1 (mensaje de commit) no contiene autoría o menciones no permitidas.
entrega_texto_valido() {
  ! printf '%s\n' "$1" | grep -Eiq "$LIMITE_PALABRAS"
}

# Persona del equipo configurada en el repositorio original: AUTOR_NOMBRE y AUTOR_CORREO.
entrega_autor_repositorio() {
  AUTOR_NOMBRE=$(git -C "$RAIZ" config user.name || true)
  AUTOR_CORREO=$(git -C "$RAIZ" config user.email || true)
  [ -n "$AUTOR_NOMBRE" ] && [ -n "$AUTOR_CORREO" ] \
    || falla 'configure el autor en el repositorio: git config user.name "Nombre Apellido" y git config user.email "correo@dominio"'
  entrega_identidad_valida "$AUTOR_NOMBRE" "$AUTOR_CORREO" \
    || falla "el autor configurado ($AUTOR_NOMBRE <$AUTOR_CORREO>) no parece una persona del equipo"
}

# Commit completo de la referencia $1 (falla si no existe).
entrega_commit() {
  git -C "$RAIZ" rev-parse --verify --quiet "$1^{commit}" || falla "la referencia '$1' no existe"
}

# Carpeta temporal TMP, borrada al salir.
entrega_temporales() {
  TMP=$(mktemp -d "${TMPDIR:-/tmp}/$1.XXXXXX")
  trap 'rm -rf -- "$TMP"' EXIT
  trap 'exit 130' INT TERM
}

# ------------------------------------------------------------------ copia limpia

# 1. Exporta el árbol del commit $1 (sin historial) a la carpeta $2.
entrega_exportar() {
  git -C "$RAIZ" archive --format=tar "$1" | tar -x -f - -C "$2"
}

# 2. Borra de $1 lo excluido y deja la lista de rutas borradas en $2.
entrega_excluir() {
  node "$HERRAMIENTAS" excluir "$1" "$EXCLUSIONES" > "$2"
}

# 3. Revisa enlaces y menciones a lo excluido ($2 = lista de excluidos); corrige README.md y ARCHITECTURE.md.
entrega_ajustar() {
  node "$HERRAMIENTAS" ajustar "$1" "$2"
}

# 1+2+3 en silencio: copia limpia del commit $1 en la carpeta $2 (debe existir y estar vacía).
# El informe queda en $2.registro fuera de la copia (avisos de enlaces, lista de excluidos).
entrega_copia_limpia() {
  entrega_exportar "$1" "$2"
  entrega_excluir "$2" "$2.excluidos" || falla "no se pudieron aplicar las exclusiones a $2"
  entrega_ajustar "$2" "$2.excluidos" > "$2.registro" 2>&1 || { cat "$2.registro" >&2; falla "no se pudo ajustar $2"; }
}

# 4. Verificaciones de limpieza sobre la carpeta $1 (opciones extra en $2, p. ej. --sin-readme).
entrega_verificar() {
  # shellcheck disable=SC2086 # $2 es una opción opcional sin espacios
  node "$HERRAMIENTAS" verificar "$1" ${PERMITIDOS:+"$PERMITIDOS"} ${2:-}
}

# ------------------------------------------------------------------ pruebas aisladas

_resumen_pruebas() {
  total=$(sed -n 's/^ℹ tests \([0-9]*\).*/\1/p' "$1" | tail -n 1)
  ok=$(sed -n 's/^ℹ pass \([0-9]*\).*/\1/p' "$1" | tail -n 1)
  mal=$(sed -n 's/^ℹ fail \([0-9]*\).*/\1/p' "$1" | tail -n 1)
  printf '%s pruebas, %s correctas, %s fallidas' "${total:-?}" "${ok:-?}" "${mal:-?}"
}

_pruebas_node() {
  # node --test con los *.test.js / *.test.mjs de tests/ del componente actual.
  set --
  for f in tests/*.test.js tests/*.test.mjs; do
    [ -f "$f" ] && set -- "$@" "$f"
  done
  [ $# -gt 0 ] || { echo 'No hay archivos de prueba en tests/'; return 1; }
  node --test --test-reporter=spec "$@"
}

_ejecutar_pruebas() {
  # $1 = carpeta de pruebas, $2 = componente; el resto, la orden a ejecutar dentro de él
  base=$1; componente=$2; shift 2
  registro="$base.$(printf '%s' "$componente" | tr '/' '-').log"
  if [ ! -d "$base/$componente" ]; then
    printf '  FALLA  %s: no existe la carpeta\n' "$componente"; FALLOS_PRUEBAS=$((FALLOS_PRUEBAS + 1)); return 0
  fi
  if (cd "$base/$componente" && "$@") < /dev/null > "$registro" 2>&1; then
    printf '  OK     %-22s %s\n' "$componente" "$(_resumen_pruebas "$registro")"
  else
    printf '  FALLA  %-22s %s\n' "$componente" "$(_resumen_pruebas "$registro")"
    tail -n 40 "$registro" | sed 's/^/           | /'
    FALLOS_PRUEBAS=$((FALLOS_PRUEBAS + 1))
  fi
}

# 5. Pruebas de todos los componentes e instalación mínima sobre una COPIA de la carpeta $1
#    (sin .git), en la carpeta de trabajo $2 (debe estar dentro de TMP). Devuelve 1 si algo falla.
entrega_probar() {
  origen=$1; trabajo=$2
  rm -rf -- "$trabajo"; mkdir -p -- "$trabajo/copia" "$trabajo/env"
  (cd "$origen" && tar -c -f - --exclude=./.git .) | tar -x -f - -C "$trabajo/copia"
  FALLOS_PRUEBAS=0
  _ejecutar_pruebas "$trabajo/copia" backend npm test --silent
  for componente in authenticator-app sdk demo-portal-tramites attack-lab; do
    _ejecutar_pruebas "$trabajo/copia" "$componente" _pruebas_node
  done
  # Instalación mínima: generar el .env con secretos aleatorios en una ruta temporal.
  if (cd "$trabajo/copia/backend" && node scripts/generar-env.js --salida "$trabajo/env/.env") < /dev/null > "$trabajo/env.log" 2>&1; then
    node "$HERRAMIENTAS" env "$trabajo/env/.env" || FALLOS_PRUEBAS=$((FALLOS_PRUEBAS + 1))
  else
    printf '  FALLA  node scripts/generar-env.js\n'; sed 's/^/           | /' "$trabajo/env.log"
    FALLOS_PRUEBAS=$((FALLOS_PRUEBAS + 1))
  fi
  rm -rf -- "$trabajo"
  [ "$FALLOS_PRUEBAS" -eq 0 ]
}

# ------------------------------------------------------------------ repositorio de la entrega

# git sobre el repositorio de la entrega $1, sin hooks, sin firma y sin plantillas de mensaje.
entrega_git() {
  carpeta=$1; shift
  git -C "$carpeta" -c core.hooksPath=/dev/null -c commit.gpgsign=false -c commit.template= "$@"
}

# Commit en el repositorio $1 con el mensaje $2 y el autor "$3" <$4>; quien confirma es AUTOR_NOMBRE/CORREO
# (la persona que ejecuta el script). La fecha es la hora real. Falla si autor o mensaje no son válidos.
entrega_confirmar_commit() {
  entrega_identidad_valida "$3" "$4" || falla "autor no permitido para un commit de la entrega: $3 <$4>"
  entrega_texto_valido "$2" || falla "el mensaje del commit contiene texto no permitido: $2"
  GIT_AUTHOR_NAME=$3 GIT_AUTHOR_EMAIL=$4 \
  GIT_COMMITTER_NAME=$AUTOR_NOMBRE GIT_COMMITTER_EMAIL=$AUTOR_CORREO \
    entrega_git "$1" commit --quiet --no-verify -m "$2"
}

# Pide confirmación (leída de la entrada estándar) y ejecuta "git push gitlab <rama $2>" en el repositorio $1.
# Solo la respuesta exacta SI sube; cualquier otra lo omite (los push son acumulativos: el siguiente
# de la misma rama incluye lo omitido). Nunca fuerza. Devuelve 1 si el push falla.
entrega_subir_rama() {
  printf '\n  Comando: git push gitlab %s\n' "$2"
  printf '  Escriba SI para ejecutarlo (otra respuesta lo omite): '
  respuesta=
  IFS= read -r respuesta || true
  if [ "$respuesta" = SI ]; then
    printf '\n'
    git -C "$1" push gitlab "$2" || return 1
    SUBIDAS="${SUBIDAS:-}$2 "
  else
    printf '\n  Omitido: no se subió la rama %s.\n' "$2"
    OMITIDAS="${OMITIDAS:-}$2 "
  fi
}

# Archivo de estado de la sincronización, DENTRO de .git de la copia de entrega: nunca se versiona ni
# llega a GitHub ni a GitLab. Formato: líneas "clave=valor" (ultimo=<commit de GitHub ya sincronizado>).
entrega_archivo_estado() { printf '%s/.git/entrega-sincronizacion\n' "$1"; }

entrega_guardar_estado() {
  {
    printf '# Estado de la sincronización GitHub -> copia de entrega (no se versiona)\n'
    printf 'ultimo=%s\n' "$2"
    printf 'resumen=%s\n' "$(git -C "$RAIZ" log -1 --format='%h %s' "$2" | tr '\n' ' ')"
    printf 'fecha=%s\n' "$(date '+%Y-%m-%d %H:%M:%S %z')"
  } > "$(entrega_archivo_estado "$1")"
}

entrega_leer_estado() {
  archivo=$(entrega_archivo_estado "$1")
  [ -f "$archivo" ] || return 1
  sed -n 's/^ultimo=//p' "$archivo" | tail -n 1
}
