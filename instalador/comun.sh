# Funciones comunes de instalador/linux.sh e instalador/macos.sh (se carga con "source"; no se ejecuta sola).
# Espera: ROOT (raíz del proyecto) y SI (1 = no preguntar, usar las respuestas por defecto).

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    _c=$'\033[36m' _v=$'\033[32m' _a=$'\033[33m' _r=$'\033[31m' _n=$'\033[0m'
else
    _c='' _v='' _a='' _r='' _n=''
fi
paso() { printf '\n%s==> %s%s\n' "$_c" "$*" "$_n"; }
ok() { printf '  %s✔%s %s\n' "$_v" "$_n" "$*"; }
aviso() { printf '  %s⚠%s %s\n' "$_a" "$_n" "$*"; }
fallo() { printf '  %s✖ %s%s\n' "$_r" "$*" "$_n" >&2; exit 1; }

# preguntar "texto" s|n  → 0 si la respuesta es sí. Con --si devuelve la respuesta por defecto.
preguntar() {
    local r
    if [ "${SI:-0}" = 1 ]; then [ "$2" = s ]; return; fi
    read -rp "  $1 [$([ "$2" = s ] && echo S/n || echo s/N)]: " r || true
    r="${r:-$2}"
    [[ "$r" =~ ^([sSyY]|[sS][iíIÍ]|yes)$ ]]
}

node_ok() { command -v node >/dev/null 2>&1 && [ "$(node -p 'process.versions.node.split(".")[0]')" -ge 22 ]; }

# Registro de la instalación en instalador/registros/ (además de la pantalla)
iniciar_registro() {
    mkdir -p "$ROOT/instalador/registros"
    REGISTRO="$ROOT/instalador/registros/$1-$(date +%Y%m%d-%H%M%S).log"
    exec > >(tee -a "$REGISTRO") 2>&1
    trap 'echo; echo "  Registro: $REGISTRO"' EXIT
}

# conf_poner ARCHIVO CLAVE VALOR [sudo]: deja UNA línea activa "CLAVE VALOR" en un .conf de ClamAV (idempotente)
conf_poner() {
    local f="$1" k="$2" v="$3" s="${4:-}"
    $s sed -i.bak -E "/^[[:space:]]*$k([[:space:]]|$)/d" "$f" && $s rm -f "$f.bak"
    echo "$k $v" | $s tee -a "$f" >/dev/null
}
# "Example" en la primera línea útil impide arrancar a clamd/freshclam: se comenta
conf_sin_example() { $2 sed -i.bak -E 's/^[[:space:]]*Example/#Example/' "$1" && $2 rm -f "$1.bak"; }

# Paso de npm común a Linux y macOS (install.js: npm ci + .env); el toolset de PruebasLinux lo pregunta install.js
instalar_npm() {
    paso "Dependencias del proyecto (npm)"
    (cd "$ROOT" && node instalador/install.js --os "$1" $([ "${SI:-0}" = 1 ] && echo --no-tools)) || fallo "install.js falló"
    if preguntar "¿Instalar también la interfaz web (web/)?" s; then
        (cd "$ROOT/web" && npm ci --no-audit --no-fund) && ok "dependencias de web/ instaladas" || aviso "npm ci en web/ falló"
    fi
}

verificar_clamav() {
    echo "  Esperando a que clamd cargue las firmas (hasta 3 minutos)..."
    node "$ROOT/instalador/verificar-clamav.js" --esperar 180 || { aviso "clamd no respondió bien: revisa su registro ($1)"; return 1; }
}
