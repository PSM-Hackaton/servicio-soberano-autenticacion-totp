#!/bin/sh
# Merge Request de una rama personal hacia "desarrollo" en el GitLab del evento, por la API.
#
# Sin --ejecutar (por defecto) NO llama a la API: muestra la petición exacta (curl) que se haría, con el
# token como "$GITLAB_TOKEN". Con --ejecutar la envía, tras comprobar que no hay ya un Merge Request
# abierto de la misma rama hacia el mismo destino.
#
# Siempre pide remove_source_branch=false y squash=false: el proyecto borra la rama de origen al fusionar
# si no se indica lo contrario, y las ramas personales (diego, laya) siguen recibiendo etapas después.
#
# El token se lee SOLO de la variable de entorno GITLAB_TOKEN y se envía como cabecera; nunca se escribe
# en archivos, remotos ni en la salida.
#
# Uso: sh scripts/mr-gitlab.sh --origen RAMA --titulo "Etapa N · ..." [opciones]
# Requisitos: sh POSIX y curl (node solo para leer la respuesta con --ejecutar).

set -eu

uso() {
  cat <<'FIN'
Uso: sh scripts/mr-gitlab.sh --origen RAMA --titulo TEXTO [opciones]

  --origen RAMA        rama personal de origen (diego, laya)
  --titulo TEXTO       título del Merge Request (p. ej. "Etapa 3 · Núcleo criptográfico propio...")
  --descripcion TEXTO  descripción (Markdown). Por defecto, una línea con el título
  --issue N            añade "Closes #N" a la descripción (issue de la etapa)
  --destino RAMA       rama de destino. Por defecto: la de scripts/gitlab-evento.txt (desarrollo)
  --revisor ID         id numérico de GitLab de quien revisa. Por defecto: el de la rama en gitlab-evento.txt
  --proyecto ID        id numérico del proyecto. Por defecto: el de gitlab-evento.txt
  --url URL            dirección del GitLab. Por defecto: la de gitlab-evento.txt
  --config ARCH        archivo de datos del proyecto. Por defecto: scripts/gitlab-evento.txt
  --ejecutar           envía la petición (requiere GITLAB_TOKEN en el entorno)
  -h, --help           muestra esta ayuda
FIN
}

falla() { printf '\nERROR: %s\n' "$1" >&2; exit 1; }

DIR_SCRIPT=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
CONFIG="$DIR_SCRIPT/gitlab-evento.txt"
ORIGEN=; TITULO=; DESCRIPCION=; ISSUE=; DESTINO=; REVISOR=; PROYECTO=; URL=; EJECUTAR=0
while [ $# -gt 0 ]; do
  case "$1" in
    --origen) [ $# -ge 2 ] || falla 'falta el valor de --origen'; ORIGEN=$2; shift 2 ;;
    --titulo) [ $# -ge 2 ] || falla 'falta el valor de --titulo'; TITULO=$2; shift 2 ;;
    --descripcion) [ $# -ge 2 ] || falla 'falta el valor de --descripcion'; DESCRIPCION=$2; shift 2 ;;
    --issue) [ $# -ge 2 ] || falla 'falta el valor de --issue'; ISSUE=$2; shift 2 ;;
    --destino) [ $# -ge 2 ] || falla 'falta el valor de --destino'; DESTINO=$2; shift 2 ;;
    --revisor) [ $# -ge 2 ] || falla 'falta el valor de --revisor'; REVISOR=$2; shift 2 ;;
    --proyecto) [ $# -ge 2 ] || falla 'falta el valor de --proyecto'; PROYECTO=$2; shift 2 ;;
    --url) [ $# -ge 2 ] || falla 'falta el valor de --url'; URL=$2; shift 2 ;;
    --config) [ $# -ge 2 ] || falla 'falta el valor de --config'; CONFIG=$2; shift 2 ;;
    --ejecutar) EJECUTAR=1; shift ;;
    -h|--help) uso; exit 0 ;;
    *) uso >&2; falla "opción desconocida: $1" ;;
  esac
done

# Valor de "clave [subclave] valor" en el archivo de datos (primera coincidencia).
dato() {
  [ -f "$CONFIG" ] || return 0
  if [ $# -eq 1 ]; then
    awk -v k="$1" '$1 == k { sub(/^[^ \t]+[ \t]+/, ""); print; exit }' "$CONFIG"
  else
    awk -v k="$1" -v s="$2" '$1 == k && $2 == s { sub(/^[^ \t]+[ \t]+[^ \t]+[ \t]+/, ""); print; exit }' "$CONFIG"
  fi
}

[ -n "$ORIGEN" ] || { uso >&2; falla 'falta --origen'; }
[ -n "$TITULO" ] || { uso >&2; falla 'falta --titulo'; }
[ -n "$DESTINO" ] || DESTINO=$(dato destino)
[ -n "$PROYECTO" ] || PROYECTO=$(dato proyecto)
[ -n "$URL" ] || URL=$(dato url)
[ -n "$REVISOR" ] || REVISOR=$(dato revisor "$ORIGEN")
[ -n "$DESTINO" ] || falla 'falta la rama de destino (--destino o "destino" en el archivo de datos)'
[ -n "$PROYECTO" ] || falla 'falta el id del proyecto (--proyecto o "proyecto" en el archivo de datos)'
[ -n "$URL" ] || falla 'falta la dirección del GitLab (--url o "url" en el archivo de datos)'
case "$PROYECTO" in *[!0-9]*) falla "el id del proyecto debe ser numérico: $PROYECTO" ;; esac
case "$REVISOR" in *[!0-9]*) falla "el id del revisor debe ser numérico: $REVISOR" ;; esac
[ "$ORIGEN" != "$DESTINO" ] || falla 'la rama de origen y la de destino son la misma'
URL=${URL%/}

# Sin menciones a herramientas ni coautorías en lo que se publica.
for texto in "$TITULO" "$DESCRIPCION"; do
  if printf '%s\n' "$texto" | grep -Eiq 'claude|anthropic|gemini|chatgpt|openai|copilot|co-authored-by|\[bot\]'; then
    falla "el título o la descripción contienen texto no permitido: $texto"
  fi
done

[ -n "$DESCRIPCION" ] || DESCRIPCION=$TITULO
[ -z "$ISSUE" ] || DESCRIPCION=$(printf '%s\n\nCloses #%s' "$DESCRIPCION" "$ISSUE")

API="$URL/api/v4/projects/$PROYECTO/merge_requests"

# Muestra la petición sin el token (para revisarla o ejecutarla a mano).
mostrar() {
  printf 'curl --fail-with-body -sS -X POST "%s" \\\n' "$API"
  printf '  -H "PRIVATE-TOKEN: $GITLAB_TOKEN" \\\n'
  printf '  --data-urlencode "source_branch=%s" \\\n' "$ORIGEN"
  printf '  --data-urlencode "target_branch=%s" \\\n' "$DESTINO"
  printf "  --data-urlencode 'title=%s' \\\\\n" "$(printf '%s' "$TITULO" | sed "s/'/'\\\\''/g")"
  printf "  --data-urlencode 'description=%s' \\\\\n" "$(printf '%s' "$DESCRIPCION" | sed "s/'/'\\\\''/g")"
  [ -z "$REVISOR" ] || printf '  --data-urlencode "reviewer_ids[]=%s" \\\n' "$REVISOR"
  printf '  --data-urlencode "remove_source_branch=false" \\\n'
  printf '  --data-urlencode "squash=false"\n'
}

if [ "$EJECUTAR" -eq 0 ]; then
  printf 'Merge Request %s -> %s en el proyecto %s (NO se envía: falta --ejecutar)\n\n' "$ORIGEN" "$DESTINO" "$PROYECTO"
  mostrar
  printf '\nPara enviarlo, repita la misma orden añadiendo --ejecutar, con el token solo en el entorno:\n'
  printf '  GITLAB_TOKEN=<token> sh scripts/mr-gitlab.sh ... --ejecutar\n'
  exit 0
fi

command -v curl >/dev/null 2>&1 || falla 'no se encontró curl'
[ -n "${GITLAB_TOKEN:-}" ] || falla 'defina GITLAB_TOKEN en el entorno (no se acepta como argumento)'

# ¿Ya hay un Merge Request abierto de esta rama hacia el destino?
existente=$(curl --fail-with-body -sS -G "$API" -H "PRIVATE-TOKEN: $GITLAB_TOKEN" \
  --data-urlencode state=opened --data-urlencode "source_branch=$ORIGEN" --data-urlencode "target_branch=$DESTINO") \
  || falla 'no se pudo consultar la API de GitLab'
abiertos=$(printf '%s' "$existente" | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{const a=JSON.parse(s);console.log(a.map(m=>`!${m.iid} ${m.web_url}`).join(" "))})')
if [ -n "$abiertos" ]; then
  printf 'Ya hay un Merge Request abierto de %s hacia %s: %s\n' "$ORIGEN" "$DESTINO" "$abiertos"
  printf 'Los commits nuevos de la rama se añaden a ese Merge Request al hacer push; no se crea otro.\n'
  exit 0
fi

set -- --data-urlencode "source_branch=$ORIGEN" --data-urlencode "target_branch=$DESTINO" \
  --data-urlencode "title=$TITULO" --data-urlencode "description=$DESCRIPCION" \
  --data-urlencode remove_source_branch=false --data-urlencode squash=false
[ -z "$REVISOR" ] || set -- "$@" --data-urlencode "reviewer_ids[]=$REVISOR"
respuesta=$(curl --fail-with-body -sS -X POST "$API" -H "PRIVATE-TOKEN: $GITLAB_TOKEN" "$@") \
  || { printf '%s\n' "$respuesta" >&2; falla 'GitLab rechazó la petición'; }
printf '%s' "$respuesta" | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{const m=JSON.parse(s);console.log(`Creado !${m.iid}: ${m.web_url}\n  ${m.source_branch} -> ${m.target_branch}; borrar rama de origen al fusionar: ${m.force_remove_source_branch ? "sí (revíselo)" : "no"}`)})'
