#!/bin/sh
# Ejecuta las pruebas unitarias puras de TotpEngineTest sobre JVM con kotlinc (sin Android SDK ni Gradle).
# Uso: sh mobile-android/probar-motor.sh  (o ./mobile-android/probar-motor.sh)

set -eu

DIR_SCRIPT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$DIR_SCRIPT"

if ! command -v kotlinc >/dev/null 2>&1 || ! command -v java >/dev/null 2>&1; then
  cat <<'EOF' >&2
No se encontró `kotlinc` y/o `java` en el PATH.

Este módulo (`mobile-android/`) es un prototipo de hoja de ruta (no compilable con Gradle todavía).
Para ejecutar las pruebas unitarias puras (`TotpEngineTest`: RFC 6238, cédula V/E, otpauth:// y PIN):
  1. Instale OpenJDK 17+ (`java`) y el compilador Kotlin (`kotlinc` 1.9+).
  2. Ejecute nuevamente: ./mobile-android/probar-motor.sh
EOF
  exit 0
fi

mkdir -p build
OUT_JAR="build/totp-tests.jar"

echo "Compilando clases puras de mobile-android/ con kotlinc..."
kotlinc \
  app/src/main/java/ve/psmhackaton/totpsoberano/core/TotpEngine.kt \
  app/src/main/java/ve/psmhackaton/totpsoberano/core/CedulaValidator.kt \
  app/src/main/java/ve/psmhackaton/totpsoberano/core/OtpAuthParser.kt \
  app/src/main/java/ve/psmhackaton/totpsoberano/security/PinManager.kt \
  app/src/test/java/ve/psmhackaton/totpsoberano/core/TotpEngineTest.kt \
  -include-runtime -d "$OUT_JAR"

echo "Ejecutando TotpEngineTest..."
java -cp "$OUT_JAR" ve.psmhackaton.totpsoberano.core.TotpEngineTestKt
