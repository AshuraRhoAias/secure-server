#!/usr/bin/env bash
# Bloqueo de red durante una migración/rotación de claves.
#
#   MAINTENANCE_ADMIN_IPS="203.0.113.10" sudo scripts/maintenance-firewall.sh --apply [--ttl 120]
#   sudo scripts/maintenance-firewall.sh --remove
#   scripts/maintenance-firewall.sh                  # DRY-RUN (por defecto): solo muestra los comandos
#
# Qué hace (IPv4 e IPv6, en una cadena propia MAINT_GUARD):
#   - Descarta TODAS las conexiones entrantes NUEVAS, salvo desde loopback y desde MAINTENANCE_ADMIN_IPS.
#   - Mantiene las conexiones ya establecidas (tu sesión SSH, las respuestas de la base de datos).
#   - No toca el tráfico saliente.
#
# Salvaguardas contra quedarte fuera de la máquina:
#   - --apply exige MAINTENANCE_ADMIN_IPS (o --allow-lockout si tienes acceso por consola).
#   - --ttl N (por defecto 120): las reglas se eliminan solas a los N minutos aunque el proceso
#     que las aplicó haya muerto. --ttl 0 lo desactiva.
#   - --remove es idempotente y quita solo sus cadenas.
#
# Esto complementa el modo mantenimiento de la aplicación (que responde 503 a todo); no apaga ni
# bloquea la máquina: no se puede bloquear "todo" sin perder también el acceso del administrador.

set -euo pipefail

MODE="dry-run"
TTL_MINUTES=120
ALLOW_LOCKOUT=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --apply)  MODE="apply" ;;
        --remove) MODE="remove" ;;
        --dry-run) MODE="dry-run" ;;
        --allow-lockout) ALLOW_LOCKOUT=1 ;;
        --ttl) shift; TTL_MINUTES="${1:-}" ;;
        *) echo "Uso: $0 [--dry-run|--apply|--remove] [--ttl MINUTOS] [--allow-lockout]" >&2; exit 1 ;;
    esac
    shift
done

[[ "$TTL_MINUTES" =~ ^[0-9]+$ ]] || { echo "--ttl debe ser un número de minutos" >&2; exit 1; }

ADMIN_IPS="${MAINTENANCE_ADMIN_IPS:-}"
ADMIN_IPS="${ADMIN_IPS//,/ }"
for ip in $ADMIN_IPS; do
    [[ "$ip" =~ ^[0-9a-fA-F:.]+(/[0-9]+)?$ ]] || { echo "IP de administración inválida: $ip" >&2; exit 1; }
done

if [[ "$MODE" != "dry-run" && "$EUID" -ne 0 ]]; then
    echo "❌ --apply y --remove requieren root" >&2
    exit 1
fi

if [[ "$MODE" == "apply" && -z "$ADMIN_IPS" && "$ALLOW_LOCKOUT" -ne 1 ]]; then
    echo "❌ Sin MAINTENANCE_ADMIN_IPS te quedarías sin acceso remoto. Define tus IPs o usa --allow-lockout (solo con acceso por consola)." >&2
    exit 1
fi

run() {
    if [[ "$MODE" == "dry-run" ]]; then echo "+ $*"; else "$@"; fi
}

run_quiet() {
    if [[ "$MODE" == "dry-run" ]]; then echo "+ $* (ignorar si no existe)"; else "$@" 2>/dev/null || true; fi
}

remove_family() {
    local cmd="$1"
    if [[ "$MODE" == "dry-run" ]]; then
        echo "+ $cmd -D INPUT -j MAINT_GUARD (hasta que no queden)"
    else
        while $cmd -D INPUT -j MAINT_GUARD 2>/dev/null; do :; done
    fi
    run_quiet "$cmd" -F MAINT_GUARD
    run_quiet "$cmd" -X MAINT_GUARD
}

apply_family() {
    local cmd="$1" want_v6="$2" ip is_v6

    remove_family "$cmd"   # idempotente

    run "$cmd" -N MAINT_GUARD
    run "$cmd" -A MAINT_GUARD -i lo -j ACCEPT
    run "$cmd" -A MAINT_GUARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    for ip in $ADMIN_IPS; do
        is_v6=0; [[ "$ip" == *:* ]] && is_v6=1
        [[ "$is_v6" == "$want_v6" ]] || continue
        run "$cmd" -A MAINT_GUARD -s "$ip" -j ACCEPT
    done
    run "$cmd" -A MAINT_GUARD -m limit --limit 5/min -j LOG --log-prefix "MAINT_GUARD_DROP: " --log-level 4
    run "$cmd" -A MAINT_GUARD -j DROP
    run "$cmd" -I INPUT 1 -j MAINT_GUARD
}

configure() {
    local action="$1" cmd
    for cmd in iptables ip6tables; do
        if ! command -v "$cmd" >/dev/null 2>&1 && [[ "$MODE" != "dry-run" ]]; then
            echo "⚠️ $cmd no encontrado: se omite"
            continue
        fi
        echo "# $cmd"
        if [[ "$action" == "apply" ]]; then
            apply_family "$cmd" "$([[ "$cmd" == ip6tables ]] && echo 1 || echo 0)"
        else
            remove_family "$cmd"
        fi
    done
}

echo "🔒 Bloqueo de mantenimiento — modo: $MODE"

case "$MODE" in
    remove)
        configure remove
        echo "✅ Reglas de mantenimiento eliminadas"
        ;;
    *)
        echo "   IPs de administración permitidas: ${ADMIN_IPS:-<ninguna>}"
        configure apply

        if [[ "$MODE" == "apply" ]]; then
            echo "✅ Entrada bloqueada (excepto loopback, conexiones establecidas y administradores)"
            if [[ "$TTL_MINUTES" -gt 0 ]]; then
                SELF="$(readlink -f "$0")"
                nohup setsid bash -c "sleep $((TTL_MINUTES * 60)); '$SELF' --remove" >/dev/null 2>&1 &
                echo "⏱️ Las reglas se eliminarán solas en $TTL_MINUTES min (--ttl 0 para desactivarlo)"
            fi
        else
            echo
            echo "ℹ️ Dry-run: no se ha modificado nada."
        fi
        ;;
esac
