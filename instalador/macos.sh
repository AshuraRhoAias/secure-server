#!/usr/bin/env bash
# Instalador de secure-server para macOS (Apple Silicon e Intel), con Homebrew.
# Lo lanza el menú (doble clic en instalar.command, o bash instalar.sh → 3) o directamente:
#   bash instalador/macos.sh [--si] [--sin-mariadb] [--sin-clamav] [--sin-npm]
# Instala lo que falte: Node.js 22, MariaDB, ClamAV (clamd y freshclam como agentes de launchd del usuario; clamd escucha en
# su socket Unix y en 127.0.0.1:3310, nunca hacia fuera) y las dependencias de npm. Idempotente; registro en instalador/registros/.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SI=0 MARIADB=1 CLAMAV=1 NPM=1
for a in "$@"; do
    case "$a" in
        --si | -y) SI=1 ;;
        --sin-mariadb) MARIADB=0 ;;
        --sin-clamav) CLAMAV=0 ;;
        --sin-npm) NPM=0 ;;
        -h | --help) sed -n '2,7p' "$0"; exit 0 ;;
        *) echo "Opción desconocida: $a" >&2; exit 2 ;;
    esac
done
# shellcheck source=instalador/comun.sh
source "$ROOT/instalador/comun.sh"
iniciar_registro macos
[ "$(id -u)" -ne 0 ] || fallo "No lo ejecutes con sudo: Homebrew y los agentes de launchd son del usuario."

printf '\n  ╔══════════════════════════════════════════════╗\n'
printf '  ║    secure-server · instalación para macOS    ║\n'
printf '  ╚══════════════════════════════════════════════╝\n'

# ------------------------------------------------------------------ Homebrew
paso "Homebrew"
if ! command -v brew >/dev/null; then
    for b in /opt/homebrew/bin/brew /usr/local/bin/brew; do [ -x "$b" ] && eval "$("$b" shellenv)" && break; done
fi
if ! command -v brew >/dev/null; then
    preguntar "No está Homebrew. ¿Instalarlo con su instalador oficial (brew.sh)?" s || fallo "Homebrew es necesario: https://brew.sh"
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    for b in /opt/homebrew/bin/brew /usr/local/bin/brew; do [ -x "$b" ] && eval "$("$b" shellenv)" && break; done
    command -v brew >/dev/null || fallo "Homebrew no quedó en el PATH: abre otra Terminal y repite."
fi
ok "$(brew --version | head -1)"
P="$(brew --prefix)"
brew_instalar() { brew list --formula "$1" >/dev/null 2>&1 || brew install "$1"; }

# ------------------------------------------------------------------ Node.js
paso "Node.js (>= 22)"
if node_ok; then ok "Node $(node -v) ya instalado"
else
    brew_instalar node@22
    brew link --overwrite --force node@22 >/dev/null
    hash -r
    node_ok || fallo "Node 22 instalado pero no está en el PATH: añade $P/opt/node@22/bin a tu PATH y repite."
    ok "Node $(node -v) instalado"
fi

# ------------------------------------------------------------------ MariaDB
if [ "$MARIADB" = 1 ]; then
    paso "MariaDB"
    brew_instalar mariadb
    brew services start mariadb >/dev/null && ok "MariaDB en marcha (brew services)"
    if preguntar "¿Crear las bases y el usuario de PRUEBAS (database/setup-local.sql)?" n; then
        # Homebrew crea una cuenta de MariaDB con tu usuario de macOS (entra por socket, sin contraseña)
        if mariadb <"$ROOT/database/setup-local.sql" 2>/dev/null || mariadb -uroot -p <"$ROOT/database/setup-local.sql"; then
            ok "bases de prueba y usuario sec listos"
        else aviso "no se pudo ejecutar setup-local.sql"; fi
    fi
fi

# ------------------------------------------------------------------ ClamAV
CLAM_RC=0
if [ "$CLAMAV" = 1 ]; then
    paso "ClamAV (antivirus de las subidas)"
    brew_instalar clamav
    ok "$(clamscan --version | cut -d/ -f1)"
    ETC="$P/etc/clamav" DB="$P/var/lib/clamav" RUN="$P/var/run/clamav" LOGS="$P/var/log/clamav"
    mkdir -p "$ETC" "$DB" "$RUN" "$LOGS"
    MARCA="# Generado por secure-server (instalador/macos.sh). Se puede volver a generar ejecutando el instalador."
    escribir_conf() {
        if [ -f "$1" ] && [ "$(head -1 "$1")" != "$MARCA" ]; then
            cp "$1" "$1.bak-$(date +%Y%m%d%H%M%S)" && aviso "tu configuración anterior de $(basename "$1") queda en .bak"
        fi
        { echo "$MARCA"; cat; } >"$1"
    }
    escribir_conf "$ETC/freshclam.conf" <<EOF
DatabaseDirectory $DB
UpdateLogFile $LOGS/freshclam.log
DatabaseMirror database.clamav.net
EOF
    escribir_conf "$ETC/clamd.conf" <<EOF
DatabaseDirectory $DB
LocalSocket $RUN/clamd.sock
# Solo en local: el servidor se conecta a 127.0.0.1:3310 (CLAMAV_HOST / CLAMAV_PORT) o a CLAMAV_SOCKET
TCPSocket 3310
TCPAddr 127.0.0.1
# Igual que CLAMAV_MAX_BYTES del servidor
StreamMaxLength 25M
MaxThreads 4
LogFile $LOGS/clamd.log
Foreground yes
EOF
    ok "clamd.conf y freshclam.conf en $ETC"

    echo "  Descargando firmas (freshclam; la primera vez son ~300 MB)..."
    freshclam --config-file="$ETC/freshclam.conf" || aviso "freshclam terminó con error; se usan las firmas que haya"

    # Agentes de launchd: clamd siempre en marcha; freshclam cada 2 horas
    AG="$HOME/Library/LaunchAgents"
    mkdir -p "$AG"
    agente() { # etiqueta, segundos (0 = siempre en marcha), programa y argumentos
        local label="$1" intervalo="$2"; shift 2
        local plist="$AG/$label.plist" args=""
        for x in "$@"; do args="$args<string>$x</string>"; done
        cat >"$plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>$label</string>
  <key>ProgramArguments</key><array>$args</array>
  $(if [ "$intervalo" = 0 ]; then echo '<key>RunAtLoad</key><true/><key>KeepAlive</key><true/>'; else echo "<key>StartInterval</key><integer>$intervalo</integer>"; fi)
  <key>StandardErrorPath</key><string>$LOGS/$label.err</string>
</dict></plist>
EOF
        launchctl bootout "gui/$(id -u)" "$plist" 2>/dev/null || true
        launchctl bootstrap "gui/$(id -u)" "$plist"
    }
    agente com.secure-server.clamd 0 "$P/sbin/clamd" -c "$ETC/clamd.conf"
    agente com.secure-server.freshclam 7200 "$P/bin/freshclam" --config-file="$ETC/freshclam.conf"
    ok "clamd arranca con tu sesión; freshclam cada 2 horas (~/Library/LaunchAgents/com.secure-server.*)"
    verificar_clamav "$LOGS/clamd.log" || CLAM_RC=1
fi

# ------------------------------------------------------------------ npm
[ "$NPM" = 1 ] && instalar_npm macos

paso "Listo"
ok "Instalación para macOS terminada."
echo "  Siguiente:  revisa .env  ·  npm start  ·  pruebas: npm run test:all"
echo "  Antivirus en el servidor: FILE_SCAN=required (clamd en 127.0.0.1:3310)"
exit "$CLAM_RC"
