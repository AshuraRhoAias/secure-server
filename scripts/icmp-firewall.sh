#!/usr/bin/env bash
# Reglas de firewall contra exfiltración por ICMP (ping -p / túneles ICMP).
#
#   scripts/icmp-firewall.sh               # DRY-RUN: solo muestra los comandos (por defecto)
#   sudo scripts/icmp-firewall.sh --apply  # aplica las reglas (iptables / ip6tables)
#   sudo scripts/icmp-firewall.sh --remove # las elimina
#   sudo scripts/icmp-firewall.sh --apply --sysctl   # además desactiva ping sin privilegios
#
# Política que aplica:
#   SALIDA   echo-request SOLO hacia los destinos de ICMP_ALLOWED_DESTS, con tamaño estándar
#            (ping por defecto) y límite de tasa. Todo lo demás se registra y se descarta.
#            Con la lista vacía (por defecto) un servidor comprometido NO puede emitir pings.
#   ENTRADA  echo-request con tamaño estándar y límite de tasa (o descartados del todo con
#            ICMP_ALLOW_INBOUND_PING=0). echo-reply no solicitados se descartan.
#
# Variables:
#   ICMP_ALLOWED_DESTS="1.1.1.1 8.8.8.8"   destinos permitidos (IPv4/IPv6, separados por espacios o comas)
#   ICMP_ALLOW_INBOUND_PING=1              1 = permitir pings entrantes limitados; 0 = descartarlos
#   ICMP_OUT_RATE=6/min  ICMP_IN_RATE=5/sec
#
# Con 6 pings/min y solo hacia destinos propios de confianza, el atacante no tiene a dónde enviar
# datos ni ancho de banda para hacerlo. Todas las reglas viven en cadenas propias (ICMP_GUARD_*):
# --remove las quita sin tocar el resto del firewall.
#
# Límites: no inspecciona el contenido del payload (para eso está scripts/icmpMonitor.js) y no
# cubre FORWARD (si esta máquina es un router, replica las reglas allí).

set -euo pipefail

MODE="dry-run"
APPLY_SYSCTL=0
for arg in "$@"; do
    case "$arg" in
        --apply)  MODE="apply" ;;
        --remove) MODE="remove" ;;
        --dry-run) MODE="dry-run" ;;
        --sysctl) APPLY_SYSCTL=1 ;;
        *) echo "Uso: $0 [--dry-run|--apply|--remove] [--sysctl]" >&2; exit 1 ;;
    esac
done

ALLOWED_DESTS="${ICMP_ALLOWED_DESTS:-}"
ALLOW_INBOUND="${ICMP_ALLOW_INBOUND_PING:-1}"
OUT_RATE="${ICMP_OUT_RATE:-6/min}"
IN_RATE="${ICMP_IN_RATE:-5/sec}"

if [[ "$MODE" != "dry-run" && "$EUID" -ne 0 ]]; then
    echo "❌ --apply y --remove requieren root" >&2
    exit 1
fi

# Los valores acaban como argumentos de iptables: validar formato
[[ "$OUT_RATE" =~ ^[0-9]+/(sec|min|hour)$ ]] || { echo "ICMP_OUT_RATE inválido" >&2; exit 1; }
[[ "$IN_RATE"  =~ ^[0-9]+/(sec|min|hour)$ ]] || { echo "ICMP_IN_RATE inválido" >&2; exit 1; }
[[ "$ALLOW_INBOUND" =~ ^[01]$ ]] || { echo "ICMP_ALLOW_INBOUND_PING debe ser 0 o 1" >&2; exit 1; }

run() {
    if [[ "$MODE" == "dry-run" ]]; then
        echo "+ $*"
    else
        "$@"
    fi
}

# Igual que run, pero tolera el fallo (regla/cadena que aún no existe)
run_quiet() {
    if [[ "$MODE" == "dry-run" ]]; then
        echo "+ $* (ignorar si no existe)"
    else
        "$@" 2>/dev/null || true
    fi
}

split_dests() {
    echo "${ALLOWED_DESTS//,/ }"
}

# remove_family <cmd> <proto> <type-opt>
remove_family() {
    local cmd="$1" proto="$2" typeopt="$3"
    # Quitar todas las copias de cada salto (por si se aplicó varias veces)
    if [[ "$MODE" == "dry-run" ]]; then
        echo "+ $cmd -D OUTPUT -p $proto $typeopt -j ICMP_GUARD_OUT (hasta que no queden)"
        echo "+ $cmd -D INPUT -p $proto $typeopt -j ICMP_GUARD_IN (hasta que no queden)"
        echo "+ $cmd -D INPUT -p $proto ${typeopt/request/reply} -m conntrack ! --ctstate ESTABLISHED,RELATED -j DROP (hasta que no queden)"
    else
        while $cmd -D OUTPUT -p "$proto" $typeopt -j ICMP_GUARD_OUT 2>/dev/null; do :; done
        while $cmd -D INPUT -p "$proto" $typeopt -j ICMP_GUARD_IN 2>/dev/null; do :; done
        while $cmd -D INPUT -p "$proto" ${typeopt/request/reply} -m conntrack ! --ctstate ESTABLISHED,RELATED -j DROP 2>/dev/null; do :; done
    fi
    run_quiet "$cmd" -F ICMP_GUARD_OUT
    run_quiet "$cmd" -X ICMP_GUARD_OUT
    run_quiet "$cmd" -F ICMP_GUARD_IN
    run_quiet "$cmd" -X ICMP_GUARD_IN
}

# apply_family <cmd> <proto> <type-opt> <min-len> <max-len> <v6?>
apply_family() {
    local cmd="$1" proto="$2" typeopt="$3" min_len="$4" max_len="$5" want_v6="$6"

    remove_family "$cmd" "$proto" "$typeopt"   # idempotente: empezar limpio

    # --- Salida
    run "$cmd" -N ICMP_GUARD_OUT
    local dest is_v6
    for dest in $(split_dests); do
        [[ "$dest" =~ ^[0-9a-fA-F:.]+(/[0-9]+)?$ ]] || { echo "Destino inválido: $dest" >&2; exit 1; }
        is_v6=0; [[ "$dest" == *:* ]] && is_v6=1
        [[ "$is_v6" == "$want_v6" ]] || continue
        run "$cmd" -A ICMP_GUARD_OUT -d "$dest" -m length --length "$min_len:$max_len" \
            -m limit --limit "$OUT_RATE" --limit-burst 6 -j ACCEPT
    done
    run "$cmd" -A ICMP_GUARD_OUT -m limit --limit 5/min -j LOG --log-prefix "ICMP_GUARD_DROP_OUT: " --log-level 4
    run "$cmd" -A ICMP_GUARD_OUT -j DROP
    run "$cmd" -I OUTPUT 1 -p "$proto" $typeopt -j ICMP_GUARD_OUT

    # --- Entrada
    run "$cmd" -N ICMP_GUARD_IN
    if [[ "$ALLOW_INBOUND" == "1" ]]; then
        run "$cmd" -A ICMP_GUARD_IN -m length --length "$min_len:$max_len" \
            -m limit --limit "$IN_RATE" --limit-burst 10 -j ACCEPT
    fi
    run "$cmd" -A ICMP_GUARD_IN -m limit --limit 5/min -j LOG --log-prefix "ICMP_GUARD_DROP_IN: " --log-level 4
    run "$cmd" -A ICMP_GUARD_IN -j DROP
    run "$cmd" -I INPUT 1 -p "$proto" $typeopt -j ICMP_GUARD_IN
    # echo-reply que no responden a un ping nuestro: canal de retorno de un atacante
    run "$cmd" -I INPUT 1 -p "$proto" ${typeopt/request/reply} -m conntrack ! --ctstate ESTABLISHED,RELATED -j DROP
}

configure() {
    local action="$1"
    if command -v iptables >/dev/null 2>&1 || [[ "$MODE" == "dry-run" ]]; then
        echo "# IPv4"
        # Paquete de ping por defecto: 20 (IP) + 8 (ICMP) + 56 (datos) = 84 bytes
        if [[ "$action" == "apply" ]]; then
            apply_family iptables icmp "--icmp-type echo-request" 28 84 0
        else
            remove_family iptables icmp "--icmp-type echo-request"
        fi
    else
        echo "⚠️ iptables no encontrado: se omite IPv4"
    fi

    if command -v ip6tables >/dev/null 2>&1 || [[ "$MODE" == "dry-run" ]]; then
        echo "# IPv6"
        # ICMPv6 por defecto: 40 (IPv6) + 8 (ICMPv6) + 56 (datos) = 104 bytes
        if [[ "$action" == "apply" ]]; then
            apply_family ip6tables ipv6-icmp "--icmpv6-type echo-request" 48 104 1
        else
            remove_family ip6tables ipv6-icmp "--icmpv6-type echo-request"
        fi
    else
        echo "⚠️ ip6tables no encontrado: se omite IPv6"
    fi
}

echo "🛡️ ICMP guard — modo: $MODE"
echo "   Destinos permitidos: ${ALLOWED_DESTS:-<ninguno: toda la salida ICMP echo se descarta>}"

case "$MODE" in
    remove) configure remove ;;
    *)      configure apply ;;
esac

if [[ "$MODE" != "remove" ]]; then
    echo
    echo "# Ping sin privilegios (el atacante sin root no podrá lanzar ping):"
    if [[ "$APPLY_SYSCTL" == "1" ]]; then
        run sysctl -w net.ipv4.ping_group_range="1 0"
        echo "   Para que persista: echo 'net.ipv4.ping_group_range = 1 0' | sudo tee /etc/sysctl.d/90-icmp-guard.conf"
    else
        echo "   Recomendado: sysctl -w net.ipv4.ping_group_range=\"1 0\"   (o pasa --sysctl con --apply)"
    fi
fi

if [[ "$MODE" == "dry-run" ]]; then
    echo
    echo "ℹ️ Dry-run: no se ha modificado nada. Revisa los comandos y aplica con --apply."
fi
