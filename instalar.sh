#!/usr/bin/env bash
# Instalador de secure-server (Linux y macOS). Abre el menú (1 Windows, 2 Linux, 3 macOS) e instala los requisitos del
# sistema elegido. En Windows: doble clic en instalar.cmd. En macOS también: doble clic en instalar.command.
#   bash instalar.sh                       menú
#   bash instalar.sh --sistema linux --si  sin preguntar (el resto de opciones pasa al instalador elegido)
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

case "$(uname -s)" in
    Linux*) detectado=linux ;;
    Darwin*) detectado=macos ;;
    MINGW* | MSYS* | CYGWIN*) detectado=windows ;;
    *) detectado=desconocido ;;
esac

sistema=""
if [ "${1:-}" = "--sistema" ]; then sistema="${2:-}"; shift 2 || shift $#; fi

if [ -z "$sistema" ]; then
    [ -t 1 ] && clear
    cat <<EOF

  ╔══════════════════════════════════════════════╗
  ║        Instalador de secure-server           ║
  ╚══════════════════════════════════════════════╝

  ¿En qué sistema quieres instalar?

    1) Windows   Node.js, MariaDB, ClamAV y npm con winget
    2) Linux     Debian/Ubuntu (apt), Fedora/RHEL (dnf), Arch (pacman)
    3) macOS     con Homebrew
    0) Salir

  Sistema detectado: $detectado

EOF
    while :; do
        read -rp "  Elige una opción [1-3]: " op || exit 1
        case "$op" in
            1) sistema=windows; break ;;
            2) sistema=linux; break ;;
            3) sistema=macos; break ;;
            0) exit 0 ;;
            *) echo "  Opción no válida: escribe 1, 2, 3 o 0." ;;
        esac
    done
fi

otro_equipo() {
    echo
    echo "  Estás en $detectado: el instalador de $1 se ejecuta en un equipo $1."
    echo "  Copia el proyecto allí y lanza: $2"
    exit 1
}

case "$sistema" in
    linux) [ "$detectado" = linux ] || otro_equipo Linux "bash instalar.sh  (opción 2)"
        exec bash "$DIR/instalador/linux.sh" "$@" ;;
    macos) [ "$detectado" = macos ] || otro_equipo macOS "doble clic en instalar.command  (o bash instalar.sh, opción 3)"
        exec bash "$DIR/instalador/macos.sh" "$@" ;;
    windows) [ "$detectado" = windows ] || otro_equipo Windows "doble clic en instalar.cmd  (opción 1)"
        # Git Bash en Windows: se delega en el instalador de PowerShell
        exec powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$(cygpath -w "$DIR/instalador/windows.ps1")" "$@" ;;
    *) echo "Sistema no válido: '$sistema' (usa windows, linux o macos)" >&2; exit 2 ;;
esac
