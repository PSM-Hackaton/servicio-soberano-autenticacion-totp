#!/bin/sh
# Prepara la ENTREGA LIMPIA para el GitLab del evento, sin subir nada.
#
#   1. Exporta el árbol de una referencia git (sin historial) a una carpeta nueva.
#   2. Quita el material interno (scripts/exclusiones-entrega.txt).
#   3. Revisa enlaces y menciones a lo excluido; corrige README.md y ARCHITECTURE.md en la copia.
#   4. Verifica la copia: cadenas prohibidas, rutas /home/, secretos, tamaño, README de la plantilla del evento.
#   5. Ejecuta las pruebas de todos los componentes y la instalación mínima en una copia temporal.
#   6. Crea en la carpeta de salida un repositorio git nuevo (rama avance; terminado con --final)
#      con un único commit e imprime los comandos para subirlo. No añade remotos ni hace push.
#      Con --sin-repositorio se detiene tras el paso 5 (solo la copia limpia verificada).
#
# Uso: sh scripts/preparar-entrega.sh [--ref REF] [--salida DIR] [--final] [--forzar] [--permitidos ARCHIVO]
#                                      [--sin-repositorio]
# Requisitos: sh POSIX, git y Node.js 22 o superior. Sin dependencias externas.
# Las funciones de cada paso están en scripts/entrega-comun.sh (compartidas con la subida por etapas).

set -eu

MENSAJE_COMMIT='Entrega: Servicio Soberano de Autenticación Multifactorial basado en Tiempo'

uso() {
  cat <<'FIN'
Uso: sh scripts/preparar-entrega.sh [opciones]

  --ref REF            referencia git a exportar (rama, etiqueta o commit). Por defecto: HEAD
  --salida DIR         carpeta de salida (no debe existir o debe estar vacía).
                       Por defecto: ../entrega-gitlab respecto a la raíz del repositorio
  --final              crea también la rama "terminado" (entrega final) en el mismo commit
  --forzar             borra la carpeta de salida si ya existe (solo si es una entrega anterior)
  --permitidos ARCH    lista de hallazgos aceptados (formato: "marcas|rutas|secretos <ruta>")
  --sin-repositorio    deja solo la copia limpia verificada y probada, sin crear el repositorio git
  -h, --help           muestra esta ayuda

No ejecuta git push ni configura remotos: al final imprime los comandos para hacerlo.
FIN
}

DIR_SCRIPT=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=scripts/entrega-comun.sh
. "$DIR_SCRIPT/entrega-comun.sh"

# ------------------------------------------------------------------ argumentos

REF=HEAD
SALIDA=
FINAL=0
FORZAR=0
PERMITIDOS=
SIN_REPOSITORIO=0
while [ $# -gt 0 ]; do
  case "$1" in
    --ref) [ $# -ge 2 ] || falla 'falta el valor de --ref'; REF=$2; shift 2 ;;
    --salida) [ $# -ge 2 ] || falla 'falta el valor de --salida'; SALIDA=$2; shift 2 ;;
    --final) FINAL=1; shift ;;
    --forzar) FORZAR=1; shift ;;
    --permitidos) [ $# -ge 2 ] || falla 'falta el valor de --permitidos'; PERMITIDOS=$2; shift 2 ;;
    --sin-repositorio) SIN_REPOSITORIO=1; shift ;;
    -h|--help) uso; exit 0 ;;
    *) uso >&2; falla "opción desconocida: $1" ;;
  esac
done
[ "$SIN_REPOSITORIO" -eq 0 ] || [ "$FINAL" -eq 0 ] || falla '--final y --sin-repositorio no se pueden combinar'

# ------------------------------------------------------------------ entorno

entrega_entorno
entrega_permitidos
[ -n "$SALIDA" ] || SALIDA="$RAIZ/../entrega-gitlab"
SALIDA=$(entrega_absoluta "$SALIDA")
entrega_validar_salida "$SALIDA"
# Autor: persona del equipo configurada en el repositorio original.
entrega_autor_repositorio

COMMIT=$(entrega_commit "$REF") || exit 1
COMMIT_CORTO=$(git -C "$RAIZ" rev-parse --short "$COMMIT")

entrega_temporales preparar-entrega

printf 'Preparación de la entrega\n'
printf '  Repositorio: %s\n' "$RAIZ"
printf '  Referencia:  %s (%s)\n' "$REF" "$COMMIT_CORTO"
printf '  Salida:      %s\n' "$SALIDA"
printf '  Autor:       %s <%s>\n' "$AUTOR_NOMBRE" "$AUTOR_CORREO"
if [ "$SIN_REPOSITORIO" -eq 1 ]; then
  printf '  Ramas:       ninguna (--sin-repositorio)\n'
else
  printf '  Ramas:       avance%s\n' "$([ "$FINAL" -eq 1 ] && printf ' y terminado' || true)"
fi
if [ "$REF" = HEAD ] && [ -n "$(git -C "$RAIZ" status --porcelain --untracked-files=no)" ]; then
  printf '  AVISO: hay cambios sin commit en el repositorio; la entrega solo incluye lo confirmado en %s.\n' "$COMMIT_CORTO"
fi

# ------------------------------------------------------------------ 1. exportar

titulo '1. Exportación con git archive (sin historial)'
entrega_preparar_salida "$SALIDA" "$FORZAR"
entrega_exportar "$COMMIT" "$SALIDA"
printf '  %s archivos exportados desde %s\n' "$(find "$SALIDA" -type f | wc -l | tr -d ' ')" "$COMMIT_CORTO"

# ------------------------------------------------------------------ 2. exclusiones

titulo '2. Exclusión de material interno'
entrega_excluir "$SALIDA" "$TMP/excluidos.txt"
if [ -s "$TMP/excluidos.txt" ]; then
  sed 's/^/  - /' "$TMP/excluidos.txt"
  printf '  %s archivo(s) excluido(s)\n' "$(wc -l < "$TMP/excluidos.txt" | tr -d ' ')"
else
  printf '  Nada que excluir.\n'
fi

# ------------------------------------------------------------------ 3. enlaces

titulo '3. Enlaces y menciones a material excluido'
entrega_ajustar "$SALIDA" "$TMP/excluidos.txt"

# ------------------------------------------------------------------ 4. verificaciones

titulo '4. Verificaciones de limpieza'
entrega_verificar "$SALIDA" || falla "la copia no está limpia; revise los hallazgos (la copia queda en $SALIDA para inspección)"

# ------------------------------------------------------------------ 5. pruebas aisladas

titulo '5. Pruebas e instalación mínima sobre una copia aislada'
entrega_probar "$SALIDA" "$TMP/pruebas" \
  || falla "$FALLOS_PRUEBAS comprobación(es) de pruebas fallaron; la entrega no funciona aislada (copia en $SALIDA)"

# La copia de salida no debe haber cambiado con las pruebas (se ejecutaron en otra carpeta).
entrega_verificar "$SALIDA" > /dev/null || falla 'la copia cambió durante las pruebas; repita la preparación'

if [ "$SIN_REPOSITORIO" -eq 1 ]; then
  titulo "Copia limpia verificada y probada en $SALIDA (sin repositorio git: --sin-repositorio)"
  exit 0
fi

# ------------------------------------------------------------------ 6. repositorio nuevo

titulo '6. Repositorio git nuevo de la entrega'
git init --quiet --template= -b avance "$SALIDA"
# --force: la copia ya está filtrada; todo lo que contiene debe quedar versionado.
entrega_git "$SALIDA" add --all --force .
entrega_confirmar_commit "$SALIDA" "$MENSAJE_COMMIT" "$AUTOR_NOMBRE" "$AUTOR_CORREO"
[ "$FINAL" -eq 1 ] && entrega_git "$SALIDA" branch terminado avance
# Autor del equipo también para commits posteriores en esta carpeta (p. ej. ramas de Merge Request).
git -C "$SALIDA" config user.name "$AUTOR_NOMBRE"
git -C "$SALIDA" config user.email "$AUTOR_CORREO"

# Comprobaciones del repositorio creado.
N_COMMITS=$(git -C "$SALIDA" rev-list --count avance)
[ "$N_COMMITS" -eq 1 ] || falla "se esperaba un único commit y hay $N_COMMITS"
entrega_historial_valido "$SALIDA" -1 avance || falla 'el commit contiene autoría o texto no permitido'
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
  Para la subida progresiva por ramas de trabajo use scripts/subir-por-etapas.sh (día 1)
  y scripts/sincronizar-gitlab.sh (días siguientes).
FIN
