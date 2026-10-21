#!/usr/bin/env bash
# Categoría 13 — Pruebas de autenticación, sesiones y autorización (estática + sondas locales).

m_jwt_config() {
  local f="$REPO_DIR/src/security/secure-auth.service.js"
  [[ -f "$f" ]] || { note "No se encuentra el servicio de autenticación."; return 0; }
  grep -nE "expiresIn|jwt\.(sign|verify)|algorithm" "$f" || note "Sin configuración JWT evidente."
  local exp; exp=$(grep -oE "expiresIn:\s*'[^']+'" "$f" | head -1)
  [[ -n "$exp" ]] && note "Expiración de token: $exp"
  grep -qE "algorithm" "$f" && good "Se especifica algoritmo." || flag "No se fija 'algorithms' en verify (riesgo de confusión de algoritmo si se admite 'none')."
}
m_pw_hash() {
  if grep -rqE "bcrypt|argon2|scrypt" "$REPO_DIR/src" 2>/dev/null; then good "Uso de hashing fuerte de contraseñas (bcrypt/argon2/scrypt)."; else flag "No se detecta hashing fuerte de contraseñas."; return 1; fi
}
m_session_audit() {
  grep -rnE "cookie|session|httpOnly|sameSite|secure" "$REPO_DIR/src" 2>/dev/null | grep -v node_modules | head -20 || note "Sin configuración de cookies/sesión evidente (API basada en Bearer token)."
}
m_bruteforce_cfg() {
  if grep -rqiE "MAX_FAILED_ATTEMPTS|rate.?limit|lockout|bloqueo" "$REPO_DIR/src" "$REPO_DIR/.env.example" 2>/dev/null; then good "Hay protección contra fuerza bruta/rate limiting configurada."; else flag "No se detecta protección contra fuerza bruta."; return 1; fi
}
m_authz_mw() {
  if grep -rqE "requireRole|role\.middleware|authorize|isAdmin" "$REPO_DIR/src" 2>/dev/null; then good "Middleware de autorización por rol presente."; grep -rnE "requireRole\(" "$REPO_DIR/src" 2>/dev/null | head; else flag "No se detecta control de autorización por rol."; return 1; fi
}
m_2fa() {
  if grep -rqiE "speakeasy|totp|otpauth|qrcode" "$REPO_DIR/src" "$REPO_DIR/package.json" 2>/dev/null; then good "Soporte de 2FA/TOTP detectado (speakeasy/qrcode)."; else note "Sin soporte 2FA evidente."; fi
}
m_authz_probe() {
  # Sonda local: endpoint admin sin token debe denegar.
  local code; code=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 "$BASE_URL/api/system/status" 2>/dev/null)
  case "$code" in
    401|403) good "/api/system/status sin token → $code (correcto)";;
    000)     note "Servidor no accesible; sonda omitida.";;
    *)       flag "/api/system/status sin token → $code (se esperaba 401/403)"; return 1;;
  esac
}

reg 13 "Configuración JWT"          "Expiración y fijación de algoritmo."                "grep" "LOCAL" m_jwt_config
reg 13 "Hashing de contraseñas"     "bcrypt/argon2/scrypt en el código."                 "grep" "LOCAL" m_pw_hash
reg 13 "Auditoría de sesiones/cookies" "Flags de cookies y gestión de sesión."           "grep" "LOCAL" m_session_audit
reg 13 "Protección fuerza bruta"    "Rate limiting / bloqueo de cuentas."                "grep" "LOCAL" m_bruteforce_cfg
reg 13 "Autorización por rol"       "Middleware requireRole/authorize."                  "grep" "LOCAL" m_authz_mw
reg 13 "Soporte 2FA/TOTP"           "Detecta speakeasy/qrcode."                          "grep" "INFO"  m_2fa
reg 13 "Sonda autorización (admin)" "Endpoint admin sin token debe dar 401/403."         "curl" "LOW"   m_authz_probe
