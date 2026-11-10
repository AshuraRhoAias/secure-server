#!/usr/bin/env bash
# Publica las últimas líneas de un registro como UNA anotación de error del job.
# Las anotaciones se leen con la API pública de check-runs (sin iniciar sesión), a diferencia de los registros completos.
#   annotate-log.sh <archivo|-> <título> [líneas=60]
set -u
src="${1:--}"
title="${2:-registro}"
lines="${3:-60}"
if [ "$src" = "-" ]; then input=$(cat); else input=$(cat "$src" 2>/dev/null || echo "(sin registro: $src)"); fi
msg=$(printf '%s\n' "$input" \
  | tr -d '\015' \
  | sed 's/\x1b\[[0-9;]*[A-Za-z]//g' \
  | tail -n "$lines" \
  | cut -c1-250 \
  | awk '{ gsub(/%/, "%25"); printf "%s%%0A", $0 }')
title=$(printf '%s' "$title" | tr -d ':,\n')
echo "::error title=${title}::${msg}"
