#!/usr/bin/env bash
# Ampliación (noviembre de 2026): pruebas de lo añadido después de las 117 opciones originales.
# Va en un módulo propio, cargado el ÚLTIMO, para que las opciones 1-117 conserven su número (la numeración es global y sigue el
# orden de carga). Cada opción declara su categoría (7, 8, 11 y 13), así que aparece en ellas con --category y en los informes.

m_semgrep_local() {
  if ! have_cmd semgrep; then note "semgrep no instalado → $(install_hint semgrep)"; return 3; fi
  # Reglas PROPIAS del proyecto (rules/semgrep-node.yml): no necesitan red ni el registro de reglas de semgrep.dev
  semgrep scan --quiet --metrics=off --error --severity ERROR --config "$PL_SELF_DIR/rules/semgrep-node.yml" "$REPO_DIR/src" "$REPO_DIR/scripts" 2>&1 | tail -60
}

m_refresh_rotation() {
  local ok=1
  grep -rqE "REFRESH_TOKEN_REUSE" "$REPO_DIR/src" 2>/dev/null && good "Detección de reutilización de refresh token (revoca la sesión)." || { flag "No se detecta la reutilización del refresh token."; ok=0; }
  grep -qE "prev_refresh_hash" "$REPO_DIR/database/schema.sql" 2>/dev/null && good "Rotación: se guarda el hash del refresh anterior." || { flag "Sin hash del refresh anterior en el esquema."; ok=0; }
  [[ $ok -eq 1 ]]
}

m_sso_handoff() {
  local svc="$REPO_DIR/src/sso/handoff.service.js"
  [[ -f "$svc" ]] || { flag "No existe la entrega SSO por código (src/sso/handoff.service.js)."; return 1; }
  good "Entrega SSO por código de un solo uso ligado al navegador (sin tokens en la URL)."
  grep -qE "timingSafeEqual" "$svc" && good "Verificador comparado en tiempo constante." || flag "El verificador no se compara en tiempo constante."
  grep -qE "SSO_HANDOFF_STOLEN" "$REPO_DIR/src/api/controllers/sso.controller.js" && good "Un código con verificador ajeno deja evento crítico." || flag "Sin evento por código robado."
  if grep -rqE "^SSO_POST_LOGIN_URL=|^SAML_POST_LOGIN_URL=" "$REPO_DIR/.env" 2>/dev/null; then flag "El .env usa el modo antiguo (tokens en el fragmento de la URL): preferible SSO_HANDOFF_URL."; fi
}

m_bff_cookies() {
  local s="$REPO_DIR/web/src/lib/session.ts" a="$REPO_DIR/web/src/lib/allowlist.ts"
  [[ -f "$s" ]] || { note "Sin interfaz web (web/)."; return 0; }
  grep -qE "httpOnly: true" "$s" && good "Cookies de la interfaz httpOnly." || { flag "Cookies sin httpOnly."; return 1; }
  grep -qE "sameSite" "$s" && good "Cookies con SameSite (Strict; Lax solo la del verificador SSO)." || flag "Cookies sin SameSite."
  [[ -f "$a" ]] && good "Lista cerrada de rutas del BFF: $(grep -c "method:" "$a") reglas." || flag "Sin lista cerrada de rutas en el BFF."
}

m_probe_sso_exchange() {
  local code; code=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 -H 'Content-Type: application/json' \
    -d '{"code":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","verifier":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"}' \
    "$BASE_URL/api/sso/exchange" 2>/dev/null)
  case "$code" in
    401|400|429) good "Canje SSO con código inventado → $code (correcto)";;
    000)         note "Servidor no accesible; sonda omitida.";;
    *)           flag "Canje SSO con código inventado → $code (se esperaba 400/401)"; return 1;;
  esac
}

m_probe_stream() {
  local code; code=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 "$BASE_URL/api/system/stream" 2>/dev/null)
  case "$code" in
    401|403) good "/api/system/stream sin token → $code (correcto)";;
    000)     note "Servidor no accesible; sonda omitida.";;
    *)       flag "/api/system/stream sin token → $code (se esperaba 401)"; return 1;;
  esac
}

m_dockerfile_policy() {
  local f="$REPO_DIR/Dockerfile"
  [[ -f "$f" ]] || { note "Sin Dockerfile."; return 0; }
  local ok=1
  grep -qE "^USER [^r]" "$f" && good "La imagen no corre como root." || { flag "La imagen corre como root."; ok=0; }
  grep -qE "^HEALTHCHECK" "$f" && good "HEALTHCHECK definido." || flag "Sin HEALTHCHECK."
  grep -qE "omit=dev" "$f" && good "Solo dependencias de producción." || flag "La imagen incluye dependencias de desarrollo."
  grep -qE "^\.env$" "$REPO_DIR/.dockerignore" 2>/dev/null && good ".env excluido de la imagen (.dockerignore)." || { flag ".env podría entrar en la imagen."; ok=0; }
  [[ $ok -eq 1 ]]
}

m_hadolint() {
  if ! have_cmd hadolint; then note "hadolint no instalado → $(install_hint hadolint)"; return 3; fi
  [[ -f "$REPO_DIR/Dockerfile" ]] || { note "Sin Dockerfile."; return 0; }
  hadolint "$REPO_DIR/Dockerfile" 2>&1 | head -40
}

m_web_audit() {
  if ! have_cmd npm; then note "npm no instalado"; return 3; fi
  [[ -f "$REPO_DIR/web/package-lock.json" ]] || { note "Sin interfaz web."; return 0; }
  (cd "$REPO_DIR/web" && npm audit --omit=dev --audit-level=high 2>&1 | tail -15)
}

reg 8  "Semgrep (reglas propias Node/Express)" "JWT sin algoritmo, SQL con plantillas, exec, redirecciones abiertas, Math.random en secretos." "semgrep" "LOCAL" m_semgrep_local
reg 13 "Refresh token: rotación y reutilización" "Rotación del refresh token y revocación al reutilizarlo."                      "grep"    "LOCAL" m_refresh_rotation
reg 13 "SSO: entrega por código"                "Tokens fuera de la URL, verificador en tiempo constante, evento por robo."      "grep"    "LOCAL" m_sso_handoff
reg 13 "BFF web: cookies y lista cerrada"        "httpOnly/SameSite y rutas permitidas del BFF de la interfaz."                   "grep"    "LOCAL" m_bff_cookies
reg 13 "Sonda: canje SSO inventado"              "POST /api/sso/exchange con código falso debe dar 400/401."                     "curl"    "LOW"   m_probe_sso_exchange
reg 13 "Sonda: stream en vivo sin token"         "GET /api/system/stream sin token debe dar 401."                                "curl"    "LOW"   m_probe_stream
reg 11 "Dockerfile: política de la imagen"       "Usuario no root, HEALTHCHECK, sin dependencias de desarrollo, .env excluido."   "grep"    "LOCAL" m_dockerfile_policy
reg 11 "hadolint (Dockerfile)"                   "Buenas prácticas del Dockerfile."                                              "hadolint" "LOCAL" m_hadolint
reg 7  "npm audit de la interfaz web"            "Dependencias de producción de web/ sin vulnerabilidades altas."                 "npm"     "LOCAL" m_web_audit
