#!/bin/sh
# Instala los ganchos de git del equipo (scripts/hooks/: pre-commit, commit-msg, pre-push) con
# git config core.hooksPath. Idempotente: si ya están instalados, no cambia nada.
#
#   sh scripts/instalar-hooks.sh                 en este repositorio (ruta relativa: vale para cada clon)
#   sh scripts/instalar-hooks.sh --repo DIR      en otro repositorio, p. ej. la copia de la entrega
#                                                (../entrega-gitlab); usa la ruta absoluta de scripts/hooks
#   sh scripts/instalar-hooks.sh --quitar [--repo DIR]   vuelve a los ganchos por defecto de git
#
# Requisitos: sh POSIX, git y Node.js 22. Sin dependencias externas.

set -eu

falla() { printf 'instalar-hooks: %s\n' "$1" >&2; exit 1; }

DIR_SCRIPT=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
RAIZ_PROPIA=$(git -C "$DIR_SCRIPT" rev-parse --show-toplevel) || falla 'scripts/ no está dentro de un repositorio git'
REPO=
QUITAR=0
while [ $# -gt 0 ]; do
  case "$1" in
    --repo) [ $# -ge 2 ] || falla 'falta el valor de --repo'; REPO=$2; shift 2 ;;
    --quitar) QUITAR=1; shift ;;
    -h|--help) sed -n '2,10p' "$0"; exit 0 ;;
    *) falla "opción desconocida: $1" ;;
  esac
done

if [ -z "$REPO" ]; then
  REPO=$RAIZ_PROPIA
  VALOR=scripts/hooks
else
  REPO=$(git -C "$REPO" rev-parse --show-toplevel) || falla "no es un repositorio git: $REPO"
  VALOR=$DIR_SCRIPT/hooks
  [ "$REPO" = "$RAIZ_PROPIA" ] && VALOR=scripts/hooks
fi

ACTUAL=$(git -C "$REPO" config --get core.hooksPath || true)

if [ "$QUITAR" -eq 1 ]; then
  if [ -z "$ACTUAL" ]; then printf 'No había ganchos configurados en %s.\n' "$REPO"; exit 0; fi
  git -C "$REPO" config --unset core.hooksPath
  printf 'Ganchos desinstalados en %s (antes: %s).\n' "$REPO" "$ACTUAL"
  exit 0
fi

command -v node >/dev/null 2>&1 || falla 'se necesita Node.js 22 en el PATH (los ganchos lo usan)'
for g in pre-commit commit-msg pre-push; do
  [ -f "$DIR_SCRIPT/hooks/$g" ] || falla "falta scripts/hooks/$g"
  [ -x "$DIR_SCRIPT/hooks/$g" ] || chmod +x "$DIR_SCRIPT/hooks/$g"
done

if [ "$ACTUAL" = "$VALOR" ]; then
  printf 'Los ganchos ya estaban instalados en %s (core.hooksPath=%s). Nada que hacer.\n' "$REPO" "$VALOR"
  exit 0
fi
[ -n "$ACTUAL" ] && printf 'AVISO: core.hooksPath valía «%s»; se sustituye.\n' "$ACTUAL"
git -C "$REPO" config core.hooksPath "$VALOR"

# Los ganchos propios que hubiera en .git/hooks dejan de ejecutarse: se avisa.
DIR_GIT=$(git -C "$REPO" rev-parse --git-common-dir)
case "$DIR_GIT" in /*) ;; *) DIR_GIT=$REPO/$DIR_GIT ;; esac
for f in "$DIR_GIT"/hooks/*; do
  [ -f "$f" ] || continue
  case "$f" in *.sample) continue ;; esac
  printf 'AVISO: %s ya no se ejecutará (core.hooksPath apunta a %s).\n' "$f" "$VALOR"
done

printf 'Ganchos instalados en %s: core.hooksPath=%s (pre-commit, commit-msg, pre-push).\n' "$REPO" "$VALOR"
printf 'Emergencias: SALTAR_VERIFICACION=1 git push … omite solo verificar-todo.js (anótelo en el Merge Request).\n'
