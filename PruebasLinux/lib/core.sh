#!/usr/bin/env bash
# core.sh — Núcleo del entorno PruebasLinux
# Proporciona: rutas, logging con fecha/hora, registro de opciones (registry),
# comprobación de dependencias, validación de entradas, ejecución segura con
# captura de resultados para los informes, y manejo de cancelación (Ctrl-C).
#
# Requiere Bash 4+ (arrays asociativos). No modifica ni depende del código del
# proyecto; sólo lo lee para análisis estático.

set -o pipefail

# --------------------------------------------------------------------------
# Rutas base
# --------------------------------------------------------------------------
PL_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PL_DIR="$(cd "$PL_LIB_DIR/.." && pwd)"
REPO_DIR="$(cd "$PL_DIR/.." && pwd)"
PL_MODULES_DIR="$PL_DIR/modules"
PL_LOG_DIR="$PL_DIR/logs"
PL_REPORT_DIR="$PL_DIR/reports"
mkdir -p "$PL_LOG_DIR" "$PL_REPORT_DIR"

# Objetivo por defecto: el propio equipo (laboratorio aislado).
TARGET="${PL_TARGET:-127.0.0.1}"
# URL base para pruebas web/API (servidor local del proyecto, puerto 3000).
BASE_URL="${PL_BASE_URL:-http://127.0.0.1:3000}"

# Sesión de ejecución (fecha/hora) para logs e informes.
PL_RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
PL_LOG_FILE="$PL_LOG_DIR/run_${PL_RUN_ID}.log"

# --------------------------------------------------------------------------
# Colores (se desactivan si no hay TTY o NO_COLOR)
# --------------------------------------------------------------------------
if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
  C_RESET=$'\033[0m'; C_BOLD=$'\033[1m'; C_DIM=$'\033[2m'
  C_RED=$'\033[31m'; C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'
  C_BLUE=$'\033[34m'; C_CYAN=$'\033[36m'; C_MAGENTA=$'\033[35m'
else
  C_RESET=; C_BOLD=; C_DIM=; C_RED=; C_GREEN=; C_YELLOW=; C_BLUE=; C_CYAN=; C_MAGENTA=
fi

# --------------------------------------------------------------------------
# Logging
# --------------------------------------------------------------------------
_ts() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }

log()  { printf '%s\n' "$*"; printf '[%s] %s\n' "$(_ts)" "$(printf '%s' "$*" | sed 's/\x1b\[[0-9;]*m//g')" >> "$PL_LOG_FILE"; }
info() { log "${C_CYAN}ℹ${C_RESET}  $*"; }
ok()   { log "${C_GREEN}✔${C_RESET}  $*"; }
warn() { log "${C_YELLOW}⚠${C_RESET}  $*"; }
err()  { log "${C_RED}✖${C_RESET}  $*"; }
hr()   { log "${C_DIM}----------------------------------------------------------------${C_RESET}"; }

# --------------------------------------------------------------------------
# Registro de opciones (registry)
# Cada opción se registra con: categoría, nombre, descripción, requisitos
# (comandos, separados por coma), nivel de riesgo y función a ejecutar.
# El numerado es automático según el orden de carga.
# --------------------------------------------------------------------------
declare -a OPT_CAT OPT_NAME OPT_DESC OPT_REQ OPT_RISK OPT_FUNC
OPT_COUNT=0

# Categorías (código -> etiqueta), orden estable 1..15
declare -A CAT_LABEL
CAT_LABEL[1]="Reconocimiento de red y descubrimiento de servicios"
CAT_LABEL[2]="Análisis de puertos y protocolos"
CAT_LABEL[3]="Auditoría de DNS, HTTP, HTTPS y TLS"
CAT_LABEL[4]="Detección y evaluación de vulnerabilidades conocidas"
CAT_LABEL[5]="Auditoría de configuraciones de servidores"
CAT_LABEL[6]="Análisis de permisos y seguridad del sistema Linux"
CAT_LABEL[7]="Revisión de dependencias, paquetes y librerías"
CAT_LABEL[8]="Análisis estático y dinámico de código"
CAT_LABEL[9]="Pruebas de aplicaciones web y API"
CAT_LABEL[10]="Auditoría de bases de datos"
CAT_LABEL[11]="Análisis de contenedores Docker y sus imágenes"
CAT_LABEL[12]="Detección de secretos expuestos y configuraciones inseguras"
CAT_LABEL[13]="Pruebas de autenticación, sesiones y autorización"
CAT_LABEL[14]="Evaluación de registros, trazabilidad y monitorización"
CAT_LABEL[15]="Generación de informes técnicos y recomendaciones"

# reg <catnum> "Nombre" "Descripción" "req1,req2" "RIESGO" nombre_funcion
reg() {
  OPT_COUNT=$((OPT_COUNT + 1))
  OPT_CAT[$OPT_COUNT]="$1"
  OPT_NAME[$OPT_COUNT]="$2"
  OPT_DESC[$OPT_COUNT]="$3"
  OPT_REQ[$OPT_COUNT]="$4"
  OPT_RISK[$OPT_COUNT]="$5"
  OPT_FUNC[$OPT_COUNT]="$6"
}

# --------------------------------------------------------------------------
# Dependencias
# --------------------------------------------------------------------------
# Helpers de salida para las funciones de módulo (su stdout lo captura tee).
say()  { printf '%s\n' "$*"; }
good() { printf '  [OK] %s\n' "$*"; }
flag() { printf '  [!]  %s\n' "$*"; }
note() { printf '  %s\n' "$*"; }

have_cmd() { command -v "$1" >/dev/null 2>&1; }

# Comprueba rápido si una URL HTTP está accesible (evita esperar timeouts largos
# cuando el servidor del proyecto no está arrancado).
http_reachable() { curl -sS -o /dev/null --connect-timeout 2 --max-time 4 "${1:-$BASE_URL}" 2>/dev/null; }

# Sugerencia de instalación por comando (Debian/Ubuntu + pip).
install_hint() {
  case "$1" in
    nmap)           echo "apt-get install -y nmap" ;;
    sslscan)        echo "apt-get install -y sslscan" ;;
    nikto)          echo "apt-get install -y nikto" ;;
    whatweb)        echo "apt-get install -y whatweb" ;;
    tcpdump)        echo "apt-get install -y tcpdump" ;;
    shellcheck)     echo "apt-get install -y shellcheck" ;;
    sqlite3)        echo "apt-get install -y sqlite3" ;;
    dig|host)       echo "apt-get install -y dnsutils" ;;
    ping)           echo "apt-get install -y iputils-ping" ;;
    traceroute)     echo "apt-get install -y traceroute" ;;
    mtr)            echo "apt-get install -y mtr-tiny" ;;
    ss|netstat)     echo "apt-get install -y net-tools iproute2" ;;
    whois)          echo "apt-get install -y whois" ;;
    bandit)         echo "pip3 install bandit" ;;
    pip-audit)      echo "pip3 install pip-audit" ;;
    detect-secrets) echo "pip3 install detect-secrets" ;;
    yamllint)       echo "pip3 install yamllint" ;;
    wafw00f)        echo "pip3 install wafw00f" ;;
    semgrep)        echo "pip3 install semgrep" ;;
    gitleaks)       echo "descarga binario: https://github.com/gitleaks/gitleaks/releases" ;;
    trivy)          echo "https://aquasecurity.github.io/trivy (apt repo o binario)" ;;
    hadolint)       echo "descarga binario: https://github.com/hadolint/hadolint/releases" ;;
    docker)         echo "apt-get install -y docker.io" ;;
    node|npm)       echo "https://nodejs.org (>=18)" ;;
    *)              echo "instala el paquete que provee '$1'" ;;
  esac
}

# Devuelve lista de comandos ausentes (de una lista CSV). Vacío = todo presente.
missing_reqs() {
  local csv="$1" c missing=""
  [[ -z "$csv" ]] && { echo ""; return; }
  IFS=',' read -r -a _reqs <<< "$csv"
  for c in "${_reqs[@]}"; do
    c="${c// /}"
    [[ -z "$c" ]] && continue
    have_cmd "$c" || missing+="$c "
  done
  echo "${missing% }"
}

# --------------------------------------------------------------------------
# Validación de entradas
# --------------------------------------------------------------------------
is_int() { [[ "$1" =~ ^[0-9]+$ ]]; }

# Valida host/IP/hostname razonable (evita inyección en comandos).
valid_target() {
  [[ "$1" =~ ^[A-Za-z0-9._:-]+$ ]]
}

valid_port() {
  is_int "$1" && (( $1 >= 1 && $1 <= 65535 ))
}

# Pide un objetivo validado (uso interactivo). Eco a stdout del valor aceptado.
prompt_target() {
  local def="${1:-$TARGET}" ans
  read -r -p "Objetivo [host/IP] (enter = $def): " ans
  ans="${ans:-$def}"
  if valid_target "$ans"; then echo "$ans"; else echo "$def"; fi
}

# --------------------------------------------------------------------------
# Confirmación para pruebas que tocan la red de un objetivo externo.
# En laboratorio aislado el objetivo por defecto es local; cualquier objetivo
# distinto de localhost exige confirmación explícita, salvo en modo --yes.
# --------------------------------------------------------------------------
ASSUME_YES="${PL_YES:-0}"
confirm_target() {
  local t="$1"
  case "$t" in
    127.0.0.1|localhost|::1|0.0.0.0) return 0 ;;
  esac
  [[ "$ASSUME_YES" == "1" ]] && return 0
  local ans
  warn "El objetivo '$t' no es local. Ejecuta pruebas sólo sobre sistemas propios o autorizados."
  read -r -p "¿Confirmas que tienes autorización para auditar '$t'? [s/N]: " ans
  [[ "$ans" =~ ^[sSyY]$ ]]
}

# --------------------------------------------------------------------------
# Ejecución de una opción con captura de resultado para informes.
# Variables de resultado de la última corrida (consumidas por report.sh):
#   RES_IDS, RES_NAME, RES_STATUS, RES_RC, RES_RISK, RES_START, RES_DUR, RES_NOTE
# --------------------------------------------------------------------------
declare -a RES_IDS RES_NAME RES_STATUS RES_RC RES_RISK RES_START RES_DUR RES_NOTE

_CANCELLED=0
_on_cancel() { _CANCELLED=1; warn "Cancelando prueba en curso…"; }

record_result() {
  local n="${#RES_IDS[@]}"
  RES_IDS[$n]="$1"; RES_NAME[$n]="$2"; RES_STATUS[$n]="$3"
  RES_RC[$n]="$4"; RES_RISK[$n]="$5"; RES_START[$n]="$6"
  RES_DUR[$n]="$7"; RES_NOTE[$n]="$8"
}

# run_option <N>
run_option() {
  local id="$1"
  if ! is_int "$id" || (( id < 1 || id > OPT_COUNT )); then
    err "Opción inválida: $id"; return 2
  fi
  local name="${OPT_NAME[$id]}" req="${OPT_REQ[$id]}" risk="${OPT_RISK[$id]}" func="${OPT_FUNC[$id]}"
  local miss; miss="$(missing_reqs "$req")"
  local start; start="$(_ts)"
  local t0=$SECONDS

  hr
  log "${C_BOLD}[$id] ${name}${C_RESET}  ${C_DIM}(riesgo: ${risk})${C_RESET}"
  log "${C_DIM}${OPT_DESC[$id]}${C_RESET}"

  if [[ -n "$miss" ]]; then
    local c hints=""
    for c in $miss; do hints+="  - $c: $(install_hint "$c")"$'\n'; done
    warn "Dependencias ausentes: $miss"
    log  "Para habilitar esta prueba instala:"
    log  "$hints"
    record_result "$id" "$name" "OMITIDA (dependencia ausente)" "-" "$risk" "$start" "0s" "faltan: $miss"
    return 3
  fi

  _CANCELLED=0
  trap _on_cancel INT
  local rc=0
  # La salida de la herramienta se muestra y se anexa al log de la sesión.
  "$func" 2>&1 | tee -a "$PL_LOG_FILE"
  rc=${PIPESTATUS[0]}
  trap - INT

  local dur=$((SECONDS - t0))
  if (( _CANCELLED == 1 )); then
    warn "Prueba [$id] cancelada por el usuario."
    record_result "$id" "$name" "CANCELADA" "$rc" "$risk" "$start" "${dur}s" "cancelada por el usuario"
    return 130
  fi
  if (( rc == 0 )); then
    ok "Prueba [$id] finalizada (rc=0) en ${dur}s"
    record_result "$id" "$name" "OK" "$rc" "$risk" "$start" "${dur}s" ""
  else
    warn "Prueba [$id] finalizada con hallazgos/errores (rc=$rc) en ${dur}s"
    record_result "$id" "$name" "CON HALLAZGOS/ERROR" "$rc" "$risk" "$start" "${dur}s" ""
  fi
  return $rc
}

# Ejecuta todas las opciones de una categoría.
run_category() {
  local cat="$1" i
  for (( i=1; i<=OPT_COUNT; i++ )); do
    [[ "${OPT_CAT[$i]}" == "$cat" ]] && run_option "$i"
  done
}

# Ejecuta todas las opciones de riesgo INFO/LOCAL/LOW sobre localhost/repo (perfil seguro).
# Excluye la categoría 15 (meta: informes/agregados) para no re-entrar en sí misma.
run_safe_all() {
  local i
  for (( i=1; i<=OPT_COUNT; i++ )); do
    [[ "${OPT_CAT[$i]}" == "15" ]] && continue
    case "${OPT_RISK[$i]}" in
      INFO|LOCAL|LOW) run_option "$i" ;;
    esac
  done
}

# --------------------------------------------------------------------------
# Diagnóstico del entorno: inventario de dependencias (disponibles/ausentes).
# --------------------------------------------------------------------------
ALL_TOOLS="nmap sslscan nikto whatweb tcpdump shellcheck sqlite3 dig host ping traceroute mtr ss netstat whois openssl curl wget node npm go docker bandit pip-audit detect-secrets yamllint wafw00f semgrep gitleaks trivy hadolint jq python3 git"

diagnose_env() {
  hr
  log "${C_BOLD}Diagnóstico del entorno PruebasLinux${C_RESET}"
  log "Fecha: $(_ts)   Host: $(uname -n)   SO: $(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-$(uname -s)}")"
  log "Kernel: $(uname -r)   Usuario: $(id -un) (uid=$(id -u))"
  log "Objetivo por defecto: $TARGET   URL base: $BASE_URL"
  hr
  local present=0 absent=0 t
  for t in $ALL_TOOLS; do
    if have_cmd "$t"; then
      ok "$(printf '%-16s %s' "$t" "$(command -v "$t")")"
      present=$((present+1))
    else
      warn "$(printf '%-16s AUSENTE  → %s' "$t" "$(install_hint "$t")")"
      absent=$((absent+1))
    fi
  done
  hr
  info "Herramientas disponibles: $present   ausentes: $absent"
  info "Opciones registradas: $OPT_COUNT en ${#CAT_LABEL[@]} categorías"
}
