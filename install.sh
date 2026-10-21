#!/usr/bin/env bash
# Instalador para Linux/macOS — delega en install.js (Node).
# Uso: ./install.sh            (interactivo; igualmente preguntará Linux/Windows)
#      ./install.sh --yes      (acepta el toolset de seguridad)
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if ! command -v node >/dev/null 2>&1; then
  echo "✖  Node.js no está instalado. Instálalo (>=18) desde https://nodejs.org" >&2
  exit 1
fi
exec node "$DIR/install.js" --os linux "$@"
