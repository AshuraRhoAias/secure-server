#!/usr/bin/env bash
# Compatibilidad: el instalador ahora es instalar.sh (menú Windows / Linux / macOS con Node, MariaDB y ClamAV)
exec bash "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/instalar.sh" "$@"
