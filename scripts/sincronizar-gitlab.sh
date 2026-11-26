#!/bin/sh
# SINCRONIZACIÓN CONTINUA (día 2 en adelante): lleva a la copia local de la entrega los commits nuevos
# de GitHub, UNO POR UNO, con el mismo mensaje y el mismo autor (hora real), filtrando lo excluido.
#
#   1. Comprueba que la copia de entrega (creada por subir-por-etapas.sh) está limpia, en la rama
#      local "integracion", y que su contenido es exactamente la versión limpia de --desde.
#   2. Recorre la historia principal de GitHub entre --desde y --hasta (primer padre, del más antiguo
#      al más reciente):
#        - commit normal: la entrega pasa a ser la versión limpia de ese commit (exportar, excluir,
#          ajustar), con su mensaje y su autor;
#        - merge (p. ej. "Integrar la rama laya"): primero se aplican, uno por uno y con su autor, los
#          commits de la rama integrada; después, si el merge añade algo más, un commit con su mensaje.
#      Los commits que solo tocan material excluido no generan commit en la entrega.
#   3. Antes de cada commit verifica el árbol resultante (rastros de herramientas, rutas /home/,
#      secretos, archivos sensibles, tamaño, README de 6 apartados) y ejecuta todas las pruebas.
#   4. Cada commit mueve la rama de trabajo de su autor (diego o laya) por avance rápido, igual que en
#      subir-por-etapas.sh. Con --subir ofrece "git push gitlab <rama>" y solo lo ejecuta si se escribe SI.
#   5. Guarda el último commit de GitHub sincronizado en .git/entrega-sincronizacion de la copia de
#      entrega (nunca se versiona); la siguiente ejecución continúa desde ahí sin --desde.
#
# Uso: sh scripts/sincronizar-gitlab.sh --entrega DIR [--desde REF] [--hasta REF] [opciones]
# Requisitos: sh POSIX, git y Node.js 22 o superior. Sin dependencias externas.

set -eu

# Autores de GitHub cuyos commits van a la rama laya (nombre o correo, sin distinguir mayúsculas).
PATRON_LAYA='laya|lya0509'

uso() {
  cat <<'FIN'
Uso: sh scripts/sincronizar-gitlab.sh --entrega DIR [opciones]

  --entrega DIR         copia local de la entrega (repositorio creado por subir-por-etapas.sh)
  --desde REF           último commit de GitHub ya sincronizado. Por defecto: el guardado en
                        DIR/.git/entrega-sincronizacion por la ejecución anterior
  --hasta REF           commit o rama de GitHub hasta donde sincronizar. Por defecto: HEAD
  --autor-laya "N <c>"  identidad con la que firmar los commits de Juan Laya en la entrega
                        (por defecto, la del commit original)
  --permitidos ARCH     lista de hallazgos aceptados (como en preparar-entrega.sh)
  --subir               tras cada commit, ofrece "git push gitlab <rama>" (el remoto gitlab debe existir)
  --plan                solo muestra los commits que se sincronizarían, sin cambiar nada
  -h, --help            muestra esta ayuda

La confirmación de cada push se lee de la entrada estándar: solo "SI" (en mayúsculas) sube.
FIN
}

DIR_SCRIPT=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=scripts/entrega-comun.sh
. "$DIR_SCRIPT/entrega-comun.sh"

# ------------------------------------------------------------------ argumentos

ENTREGA=
DESDE=
HASTA=HEAD
AUTOR_LAYA=
PERMITIDOS=
SUBIR=0
SOLO_PLAN=0
while [ $# -gt 0 ]; do
  case "$1" in
    --entrega) [ $# -ge 2 ] || falla 'falta el valor de --entrega'; ENTREGA=$2; shift 2 ;;
    --desde) [ $# -ge 2 ] || falla 'falta el valor de --desde'; DESDE=$2; shift 2 ;;
    --hasta) [ $# -ge 2 ] || falla 'falta el valor de --hasta'; HASTA=$2; shift 2 ;;
    --autor-laya) [ $# -ge 2 ] || falla 'falta el valor de --autor-laya'; AUTOR_LAYA=$2; shift 2 ;;
    --permitidos) [ $# -ge 2 ] || falla 'falta el valor de --permitidos'; PERMITIDOS=$2; shift 2 ;;
    --subir) SUBIR=1; shift ;;
    --plan) SOLO_PLAN=1; shift ;;
    -h|--help) uso; exit 0 ;;
    *) uso >&2; falla "opción desconocida: $1" ;;
  esac
done
[ -n "$ENTREGA" ] || { uso >&2; falla 'falta --entrega DIR'; }

LAYA_NOMBRE=
LAYA_CORREO=
if [ -n "$AUTOR_LAYA" ]; then
  LAYA_NOMBRE=$(printf '%s\n' "$AUTOR_LAYA" | sed -n 's/^\(.*[^ ]\) *<\([^<> ]*@[^<> ]*\)>$/\1/p')
  LAYA_CORREO=$(printf '%s\n' "$AUTOR_LAYA" | sed -n 's/^\(.*[^ ]\) *<\([^<> ]*@[^<> ]*\)>$/\2/p')
  [ -n "$LAYA_NOMBRE" ] && [ -n "$LAYA_CORREO" ] || falla "--autor-laya no tiene el formato \"Nombre Apellido <correo>\": $AUTOR_LAYA"
fi

# ------------------------------------------------------------------ entorno y comprobaciones

entrega_entorno
entrega_permitidos
[ -d "$ENTREGA/.git" ] || falla "$ENTREGA no es una copia de entrega (falta .git); créela con subir-por-etapas.sh"
ENTREGA=$(CDPATH='' cd -- "$ENTREGA" && pwd)
entrega_validar_salida "$ENTREGA"
entrega_autor_repositorio
[ "$(git -C "$ENTREGA" symbolic-ref --quiet --short HEAD || true)" = integracion ] \
  || falla "la copia de entrega debe estar en la rama local integracion (git -C \"$ENTREGA\" switch integracion)"
[ -z "$(git -C "$ENTREGA" status --porcelain)" ] || falla "la copia de entrega tiene cambios sin confirmar: $ENTREGA"
if [ "$SUBIR" -eq 1 ]; then
  git -C "$ENTREGA" remote get-url gitlab >/dev/null 2>&1 \
    || falla "--subir requiere el remoto gitlab en la copia de entrega: git -C \"$ENTREGA\" remote add gitlab <URL>"
fi

if [ -z "$DESDE" ]; then
  DESDE=$(entrega_leer_estado "$ENTREGA") \
    || falla "no hay estado de sincronización en $(entrega_archivo_estado "$ENTREGA"); indique --desde <ref>"
fi
C_DESDE=$(entrega_commit "$DESDE") || exit 1
C_HASTA=$(entrega_commit "$HASTA") || exit 1
git -C "$RAIZ" merge-base --is-ancestor "$C_DESDE" "$C_HASTA" \
  || falla "--desde ($DESDE) no es un antecesor de --hasta ($HASTA)"

entrega_temporales sincronizar-gitlab
mkdir -p "$TMP/arboles"

printf 'Sincronización GitHub -> copia de entrega\n'
printf '  Repositorio: %s\n' "$RAIZ"
printf '  Entrega:     %s\n' "$ENTREGA"
printf '  Desde:       %s\n' "$(git -C "$RAIZ" log -1 --format='%h %s' "$C_DESDE")"
printf '  Hasta:       %s (%s)\n' "$(git -C "$RAIZ" log -1 --format='%h %s' "$C_HASTA")" "$HASTA"
printf '  Ejecuta:     %s <%s>\n' "$AUTOR_NOMBRE" "$AUTOR_CORREO"
if [ "$SUBIR" -eq 1 ]; then
  printf '  Modo:        --subir: se pedirá SI antes de cada push a %s\n' "$(git -C "$ENTREGA" remote get-url gitlab)"
else
  printf '  Modo:        solo preparar (sin --subir no se ejecuta ningún push)\n'
fi

# ------------------------------------------------------------------ funciones

# Árbol git (en el repositorio de la entrega) de la versión limpia del commit $1 de GitHub.
arbol_limpio() {
  if [ ! -f "$TMP/arboles/$1.arbol" ]; then
    copia="$TMP/arboles/$1"
    mkdir -p "$copia"
    entrega_copia_limpia "$1" "$copia"
    rm -f "$TMP/arboles/indice"
    GIT_INDEX_FILE="$TMP/arboles/indice" git -C "$copia" --git-dir="$ENTREGA/.git" --work-tree="$copia" add --all --force .
    GIT_INDEX_FILE="$TMP/arboles/indice" git -C "$copia" --git-dir="$ENTREGA/.git" write-tree > "$TMP/arboles/$1.arbol"
    rm -rf -- "$copia" "$copia.excluidos" "$copia.registro"
  fi
  cat "$TMP/arboles/$1.arbol"
}

# Rama de trabajo de un autor de GitHub ("nombre correo" en $1).
rama_de() {
  if printf '%s\n' "$1" | grep -Eiq "$PATRON_LAYA"; then echo laya; else echo diego; fi
}

describir() { git -C "$RAIZ" log -1 --format='%h  %an  %s' "$1"; }

# Verifica el árbol preparado en la entrega y lo confirma con el mensaje y el autor del commit $1 de GitHub.
confirmar_como() {
  original=$1
  nombre=$(git -C "$RAIZ" log -1 --format='%an' "$original")
  correo=$(git -C "$RAIZ" log -1 --format='%ae' "$original")
  rama=$(rama_de "$nombre $correo")
  if [ "$rama" = laya ] && [ -n "$LAYA_NOMBRE" ]; then nombre=$LAYA_NOMBRE; correo=$LAYA_CORREO; fi
  # Mensaje original sin líneas de coautoría (no se publican).
  mensaje=$(git -C "$RAIZ" log -1 --format='%B' "$original" | grep -Eiv '^[[:space:]]*co-authored-by:' || true)
  entrega_identidad_valida "$nombre" "$correo" || {
    entrega_git "$ENTREGA" reset --quiet --hard HEAD
    falla "el autor de $(describir "$original") no es válido para la entrega ($nombre <$correo>); use --autor-laya si es de Juan Laya"
  }
  entrega_texto_valido "$mensaje" || {
    entrega_git "$ENTREGA" reset --quiet --hard HEAD
    falla "el mensaje de $(describir "$original") contiene texto no permitido; corríjalo en GitHub o sincronice a mano"
  }
  if ! entrega_verificar "$ENTREGA" > "$TMP/verificacion.log"; then
    cat "$TMP/verificacion.log"
    entrega_git "$ENTREGA" reset --quiet --hard HEAD
    falla "la versión limpia tras $(describir "$original") no pasa las verificaciones; no se confirma nada"
  fi
  printf '    Verificaciones: OK\n'
  if ! entrega_probar "$ENTREGA" "$TMP/pruebas" > "$TMP/pruebas.log" 2>&1; then
    cat "$TMP/pruebas.log"
    entrega_git "$ENTREGA" reset --quiet --hard HEAD
    falla "las pruebas fallan tras $(describir "$original"); no se confirma nada"
  fi
  printf '    Pruebas: OK (%s)\n' "$(grep -c '^  OK' "$TMP/pruebas.log" | tr -d ' ') comprobaciones"
  entrega_confirmar_commit "$ENTREGA" "$mensaje" "$nombre" "$correo"
  entrega_git "$ENTREGA" branch --force "$rama" HEAD
  N_CREADOS=$((N_CREADOS + 1))
  printf '    Commit: %s  ->  rama %s\n' "$(git -C "$ENTREGA" log -1 --format='%h  %an <%ae>  %s' HEAD)" "$rama"
  case " $RAMAS_TOCADAS " in *" $rama "*) ;; *) RAMAS_TOCADAS="$RAMAS_TOCADAS $rama" ;; esac
  if [ "$SUBIR" -eq 1 ]; then
    entrega_subir_rama "$ENTREGA" "$rama" <&3 || falla "falló git push gitlab $rama; revise el remoto (no se fuerza nunca)"
  else
    printf '    Se subiría con: git push gitlab %s   (solo con --subir)\n' "$rama"
  fi
}

# Commit de la historia principal: la entrega pasa a ser la versión limpia de $1.
sincronizar_completo() {
  arbol=$(arbol_limpio "$1") || exit 1
  entrega_git "$ENTREGA" read-tree -u --reset "$arbol"
  if entrega_git "$ENTREGA" diff --cached --quiet HEAD; then
    printf '    Sin cambios en la entrega (solo material excluido o ya incorporado).\n'
  else
    confirmar_como "$1"
  fi
}

# Commit de una rama integrada por un merge: se aplica solo su diferencia (versión limpia de su padre -> la suya).
sincronizar_diferencia() {
  antes=$(arbol_limpio "$1^") || exit 1
  despues=$(arbol_limpio "$1") || exit 1
  if [ "$antes" = "$despues" ]; then
    printf '    Sin cambios en la entrega (solo material excluido).\n'; return 0
  fi
  entrega_git "$ENTREGA" diff --binary "$antes" "$despues" > "$TMP/cambios.patch"
  if ! entrega_git "$ENTREGA" apply --3way --index "$TMP/cambios.patch" > "$TMP/apply.log" 2>&1; then
    entrega_git "$ENTREGA" reset --quiet --hard HEAD
    printf '    AVISO: no se puede aplicar por separado (choca con el estado actual de la entrega);\n'
    printf '           sus cambios llegarán con el commit del merge que lo integra.\n'
    return 0
  fi
  if entrega_git "$ENTREGA" diff --cached --quiet HEAD; then
    printf '    Sin cambios en la entrega (ya incorporados).\n'
  else
    confirmar_como "$1"
  fi
}

# ------------------------------------------------------------------ plan

titulo '1. Punto de partida'
BASE=$(arbol_limpio "$C_DESDE") || exit 1
if [ "$BASE" != "$(git -C "$ENTREGA" rev-parse 'HEAD^{tree}')" ]; then
  falla "la copia de entrega no coincide con la versión limpia de $(git -C "$RAIZ" log -1 --format='%h' "$C_DESDE"); revise --desde (o el estado guardado)"
fi
printf '  OK     la entrega coincide con la versión limpia de %s\n' "$(describir "$C_DESDE")"

titulo '2. Commits a sincronizar (historia principal de GitHub, del más antiguo al más reciente)'
git -C "$RAIZ" rev-list --first-parent --reverse "$C_DESDE..$C_HASTA" > "$TMP/principales.txt"
if [ ! -s "$TMP/principales.txt" ]; then
  printf '  Nada que sincronizar: %s ya está en la entrega.\n' "$HASTA"
  exit 0
fi
while IFS= read -r C; do
  printf '  %s\n' "$(describir "$C")"
  if [ -n "$(git -C "$RAIZ" rev-list --min-parents=2 --max-count=1 "$C^!" )" ]; then
    git -C "$RAIZ" rev-list --reverse --topo-order --no-merges "$C^1..$C^2" | while IFS= read -r X; do
      printf '      + %s\n' "$(describir "$X")"
    done
  fi
done < "$TMP/principales.txt"
[ "$SOLO_PLAN" -eq 0 ] || exit 0

# ------------------------------------------------------------------ sincronización

titulo '3. Sincronización (verificación y pruebas antes de cada commit)'
N_CREADOS=0
RAMAS_TOCADAS=
SUBIDAS=
OMITIDAS=
exec 3<&0
while IFS= read -r C; do
  if [ -n "$(git -C "$RAIZ" rev-list --min-parents=2 --max-count=1 "$C^!")" ]; then
    git -C "$RAIZ" rev-list --reverse --topo-order --no-merges "$C^1..$C^2" > "$TMP/laterales.txt"
    while IFS= read -r X; do
      printf '\n  %s   (de la rama integrada)\n' "$(describir "$X")"
      sincronizar_diferencia "$X"
    done < "$TMP/laterales.txt"
  fi
  printf '\n  %s\n' "$(describir "$C")"
  sincronizar_completo "$C"
  entrega_guardar_estado "$ENTREGA" "$C"
done < "$TMP/principales.txt"

# ------------------------------------------------------------------ comprobación final

titulo '4. Comprobación final'
FINAL=$(arbol_limpio "$C_HASTA") || exit 1
[ "$FINAL" = "$(git -C "$ENTREGA" rev-parse 'HEAD^{tree}')" ] || falla 'la entrega no coincide con la versión limpia de --hasta'
[ -z "$(git -C "$ENTREGA" status --porcelain)" ] || falla 'la copia de entrega quedó con cambios sin confirmar'
printf '  OK     %s commit(s) nuevos; la entrega coincide con la versión limpia de %s\n' "$N_CREADOS" "$(git -C "$RAIZ" log -1 --format='%h' "$C_HASTA")"
printf '  Estado guardado: ultimo=%s\n' "$(git -C "$RAIZ" log -1 --format='%h' "$C_HASTA")"
printf '  Ramas: %s\n' "$(git -C "$ENTREGA" for-each-ref --format='%(refname:short)=%(objectname:short)' refs/heads | tr '\n' ' ')"
if [ "$SUBIR" -eq 1 ]; then
  printf '  Subidas: %s\n' "${SUBIDAS:-ninguna}"
  [ -z "$OMITIDAS" ] || printf '  Omitidas (no se subieron): %s\n' "$OMITIDAS"
fi

titulo 'Siguientes pasos (NO se ha ejecutado nada de esto)'
[ "$SUBIR" -eq 1 ] || for R in $RAMAS_TOCADAS; do printf '  git -C "%s" push gitlab %s\n' "$ENTREGA" "$R"; done
cat <<'FIN'
  Al cierre del día: Merge Request de la rama de trabajo más adelantada hacia avance en GitLab
  (Code > Merge requests > New merge request; sin "Squash commits").
  Entrega final, tras el code freeze: Merge Request de avance hacia terminado, con el README de
  6 apartados verificado (sh scripts/preparar-entrega.sh --final lo comprueba).
FIN
