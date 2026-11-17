#!/usr/bin/env bash
# Instalador de secure-server para LINUX: Debian/Ubuntu (apt), Fedora/RHEL (dnf) y Arch (pacman).
# Lo lanza el menú (bash instalar.sh → 2) o directamente:
#   bash instalador/linux.sh [--si] [--sin-mariadb] [--sin-clamav] [--sin-npm]
# Instala lo que falte: Node.js >= 22, MariaDB, ClamAV (clamd + freshclam como servicios systemd; clamd escucha en su socket
# Unix y en 127.0.0.1:3310, nunca hacia fuera) y las dependencias de npm. Idempotente; registro en instalador/registros/.
# Se ejecuta como usuario normal: pide sudo solo para los paquetes y servicios del sistema.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SI=0 MARIADB=1 CLAMAV=1 NPM=1
for a in "$@"; do
    case "$a" in
        --si | -y) SI=1 ;;
        --sin-mariadb) MARIADB=0 ;;
        --sin-clamav) CLAMAV=0 ;;
        --sin-npm) NPM=0 ;;
        -h | --help) sed -n '2,8p' "$0"; exit 0 ;;
        *) echo "Opción desconocida: $a" >&2; exit 2 ;;
    esac
done
# shellcheck source=instalador/comun.sh
source "$ROOT/instalador/comun.sh"
iniciar_registro linux

SUDO=""
[ "$(id -u)" -eq 0 ] || SUDO="sudo"

printf '\n  ╔══════════════════════════════════════════════╗\n'
printf '  ║    secure-server · instalación para Linux    ║\n'
printf '  ╚══════════════════════════════════════════════╝\n'

paso "Gestor de paquetes"
if command -v apt-get >/dev/null; then PM=apt
elif command -v dnf >/dev/null; then PM=dnf
elif command -v pacman >/dev/null; then PM=pacman
else fallo "No encuentro apt, dnf ni pacman: instala a mano Node >= 22, MariaDB y ClamAV (ver docs/INSTALL.md)."
fi
ok "$PM"
instalar() {
    case "$PM" in
        apt) $SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "$@" ;;
        dnf) $SUDO dnf install -y "$@" ;;
        pacman) $SUDO pacman -S --needed --noconfirm "$@" ;;
    esac
}
case "$PM" in
    apt) $SUDO apt-get update -qq && instalar ca-certificates curl gnupg ;;
    dnf) instalar curl ;;
    pacman) instalar curl ;; # Arch: sin -Sy suelto (actualizaciones parciales); si falla, "pacman -Syu" antes
esac

# ------------------------------------------------------------------ Node.js
paso "Node.js (>= 22)"
if node_ok; then ok "Node $(node -v) ya instalado"
else
    case "$PM" in
        apt) # Repositorio oficial de NodeSource con su clave (sin "curl | bash")
            $SUDO install -d -m 0755 /etc/apt/keyrings
            curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | $SUDO gpg --dearmor --yes -o /etc/apt/keyrings/nodesource.gpg
            echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_22.x nodistro main" |
                $SUDO tee /etc/apt/sources.list.d/nodesource.list >/dev/null
            $SUDO apt-get update -qq && instalar nodejs ;;
        dnf) instalar nodejs npm || true
            node_ok || { $SUDO dnf module reset -y nodejs && $SUDO dnf module install -y nodejs:22/common; } ;;
        pacman) instalar nodejs npm ;;
    esac
    node_ok || fallo "No se pudo instalar Node >= 22: instálalo a mano (https://nodejs.org) y repite."
    ok "Node $(node -v) instalado"
fi

# ------------------------------------------------------------------ MariaDB
if [ "$MARIADB" = 1 ]; then
    paso "MariaDB"
    if command -v mariadb >/dev/null || command -v mysql >/dev/null; then ok "cliente $(mariadb --version 2>/dev/null || mysql --version) ya instalado"
    else
        case "$PM" in
            apt) instalar mariadb-server mariadb-client ;;
            dnf) instalar mariadb-server ;;
            pacman) instalar mariadb
                [ -d /var/lib/mysql/mysql ] || $SUDO mariadb-install-db --user=mysql --basedir=/usr --datadir=/var/lib/mysql ;;
        esac
        ok "MariaDB instalado"
    fi
    if systemctl list-unit-files mariadb.service >/dev/null 2>&1; then
        $SUDO systemctl enable --now mariadb && ok "servicio mariadb en marcha"
    fi
    if preguntar "¿Crear las bases y el usuario de PRUEBAS (database/setup-local.sql)?" n; then
        # En Debian/Ubuntu/Arch el root de MariaDB entra por socket con sudo (sin contraseña)
        if $SUDO mariadb <"$ROOT/database/setup-local.sql" 2>/dev/null || mariadb -uroot -p <"$ROOT/database/setup-local.sql"; then
            ok "bases de prueba y usuario sec listos"
        else aviso "no se pudo ejecutar setup-local.sql"; fi
    fi
fi

# ------------------------------------------------------------------ ClamAV
CLAM_RC=0
if [ "$CLAMAV" = 1 ]; then
    paso "ClamAV (antivirus de las subidas)"
    case "$PM" in
        apt) instalar clamav clamav-daemon clamav-freshclam
            CONF=/etc/clamav/clamd.conf FCONF=/etc/clamav/freshclam.conf SVC=clamav-daemon FSVC=clamav-freshclam SOCK="" ;;
        dnf) instalar clamav clamd clamav-update
            CONF=/etc/clamd.d/scan.conf FCONF=/etc/freshclam.conf SVC=clamd@scan FSVC=clamav-freshclam SOCK=/run/clamd.scan/clamd.sock ;;
        pacman) instalar clamav
            CONF=/etc/clamav/clamd.conf FCONF=/etc/clamav/freshclam.conf SVC=clamav-daemon FSVC=clamav-freshclam SOCK=/run/clamav/clamd.ctl ;;
    esac
    ok "ClamAV $(clamscan --version 2>/dev/null | cut -d/ -f1)"

    for f in "$CONF" "$FCONF"; do conf_sin_example "$f" "$SUDO"; done
    [ -n "$SOCK" ] && conf_poner "$CONF" LocalSocket "$SOCK" "$SUDO"   # Debian ya lo trae (/var/run/clamav/clamd.ctl)
    conf_poner "$CONF" TCPSocket 3310 "$SUDO"
    conf_poner "$CONF" TCPAddr 127.0.0.1 "$SUDO"                       # solo en local, nunca hacia fuera
    conf_poner "$CONF" StreamMaxLength 25M "$SUDO"                     # = CLAMAV_MAX_BYTES del servidor
    # Debian/Ubuntu arrancan clamd por activación de socket: el puerto TCP se declara también en la unidad .socket
    if systemctl cat clamav-daemon.socket >/dev/null 2>&1; then
        $SUDO install -d /etc/systemd/system/clamav-daemon.socket.d
        printf '[Socket]\nListenStream=127.0.0.1:3310\n' | $SUDO tee /etc/systemd/system/clamav-daemon.socket.d/secure-server.conf >/dev/null
        $SUDO systemctl daemon-reload
    fi
    ok "clamd escucha en su socket Unix y en 127.0.0.1:3310 ($CONF)"

    echo "  Descargando firmas (freshclam; la primera vez son ~300 MB)..."
    $SUDO systemctl stop "$FSVC" 2>/dev/null || true
    $SUDO freshclam || aviso "freshclam terminó con error (¿límite del servidor de firmas?); se usan las que haya"
    $SUDO systemctl enable --now "$FSVC" 2>/dev/null && ok "freshclam actualizará las firmas solo" || aviso "sin servicio $FSVC: programa \"freshclam\" en cron"
    if systemctl cat clamav-daemon.socket >/dev/null 2>&1; then $SUDO systemctl enable --now clamav-daemon.socket; $SUDO systemctl restart clamav-daemon.socket; fi
    $SUDO systemctl enable "$SVC" && $SUDO systemctl restart "$SVC"
    ok "servicio $SVC en marcha"
    verificar_clamav "journalctl -u $SVC" || CLAM_RC=1
fi

# ------------------------------------------------------------------ npm
[ "$NPM" = 1 ] && instalar_npm linux

paso "Listo"
ok "Instalación para Linux terminada."
echo "  Siguiente:  revisa .env  ·  npm start  ·  pruebas: npm run test:all"
echo "  Antivirus en el servidor: FILE_SCAN=required (clamd en 127.0.0.1:3310, o CLAMAV_SOCKET con el socket Unix)"
exit "$CLAM_RC"
