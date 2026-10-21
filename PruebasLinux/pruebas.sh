#!/usr/bin/env bash
# =============================================================================
# PruebasLinux — Lanzador principal del entorno de pruebas de seguridad (lab).
#
# Entorno DEFENSIVO, no destructivo, para sistemas propios o autorizados.
# Independiente del código del proyecto: sólo lo LEE para análisis estático.
#
# Uso:
#   ./pruebas.sh                      Menú interactivo
#   ./pruebas.sh --diagnose           Diagnóstico del entorno (herramientas)
#   ./pruebas.sh --list               Lista todas las opciones con su número
#   ./pruebas.sh --run N [N ...]      Ejecuta opción(es) por número
#   ./pruebas.sh --category C         Ejecuta toda una categoría (1-15)
#   ./pruebas.sh --safe-all           Ejecuta el perfil seguro (local/INFO/LOW)
#   ./pruebas.sh --report             Exporta MD+JSON+CSV de lo ejecutado
#
# Opciones:
#   --target HOST     Objetivo (def. 127.0.0.1)
#   --url URL         URL base para web/API (def. http://127.0.0.1:3000)
#   --yes             Asume "sí" en confirmaciones de objetivo externo
#   --no-color        Desactiva color
#   -h | --help       Ayuda
# =============================================================================

set -o pipefail
PL_SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Bash 4+ (arrays asociativos)
if (( BASH_VERSINFO[0] < 4 )); then
  echo "Se requiere Bash 4 o superior." >&2; exit 1
fi

# --- Pre-parseo de flags que afectan a la carga (color, target, url, yes) ----
for a in "$@"; do
  case "$a" in
    --no-color) export NO_COLOR=1 ;;
  esac
done

# shellcheck source=lib/core.sh
source "$PL_SELF_DIR/lib/core.sh"
# shellcheck source=lib/report.sh
source "$PL_SELF_DIR/lib/report.sh"
# shellcheck source=lib/ui.sh
source "$PL_SELF_DIR/lib/ui.sh"

# --- Carga de módulos (auto-descubrimiento, orden alfabético) ----------------
load_modules() {
  local m
  for m in "$PL_MODULES_DIR"/*.sh; do
    [[ -f "$m" ]] || continue
    # shellcheck disable=SC1090
    source "$m"
  done
}
load_modules

usage() { sed -n '2,40p' "$PL_SELF_DIR/pruebas.sh" | sed 's/^# \{0,1\}//'; }

# --- Parseo de argumentos ----------------------------------------------------
ACTION="menu"; RUN_IDS=(); CAT=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --diagnose)  ACTION="diagnose" ;;
    --list)      ACTION="list" ;;
    --safe-all)  ACTION="safe" ;;
    --report)    ACTION="report" ;;
    --run)       ACTION="run"; shift; while [[ $# -gt 0 && "$1" =~ ^[0-9]+$ ]]; do RUN_IDS+=("$1"); shift; done; continue ;;
    --category)  ACTION="category"; CAT="$2"; shift ;;
    --target)    TARGET="$2"; shift ;;
    --url)       BASE_URL="$2"; shift ;;
    --yes)       ASSUME_YES=1 ;;
    --no-color)  : ;;
    -h|--help)   usage; exit 0 ;;
    *) err "Argumento desconocido: $1"; usage; exit 2 ;;
  esac
  shift
done

# Validaciones de entrada de alto nivel
valid_target "$TARGET" || { err "Objetivo inválido: $TARGET"; exit 2; }

info "PruebasLinux iniciado — log de sesión: $PL_LOG_FILE"

case "$ACTION" in
  diagnose) diagnose_env ;;
  list)     ui_list_all ;;
  safe)     run_safe_all; report_markdown; m_scorecard 2>/dev/null || true ;;
  report)   report_all ;;
  run)
    (( ${#RUN_IDS[@]} == 0 )) && { err "Indica al menos un número: --run N"; exit 2; }
    for id in "${RUN_IDS[@]}"; do run_option "$id"; done
    report_have_results && report_markdown
    ;;
  category)
    is_int "$CAT" && [[ -n "${CAT_LABEL[$CAT]:-}" ]] || { err "Categoría inválida: $CAT (1-15)"; exit 2; }
    run_category "$CAT"; report_markdown
    ;;
  menu)     ui_main_menu ;;
esac
