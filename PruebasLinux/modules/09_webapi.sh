#!/usr/bin/env bash
# Categoría 9 — Pruebas de aplicaciones web y API (contra $BASE_URL, local).
# No destructivas: peticiones acotadas; nunca fuerza bruta real.

m_health() {
  http_reachable || { note "Servidor no accesible en $BASE_URL (arráncalo con 'npm start'); prueba omitida."; return 0; }

  local code; code=$(curl -sS -o /tmp/pl_h.$$ -w '%{http_code}' --connect-timeout 2 --max-time 6 "$BASE_URL/health" 2>/dev/null)
  if [[ "$code" == "200" ]]; then good "/health → 200"; cat /tmp/pl_h.$$; else flag "/health → $code (¿servidor arrancado con 'npm start'?)"; rm -f /tmp/pl_h.$$; return 1; fi
  rm -f /tmp/pl_h.$$
}
m_unauth() {
  http_reachable || { note "Servidor no accesible en $BASE_URL (arráncalo con 'npm start'); prueba omitida."; return 0; }

  local code; code=$(curl -sS -o /dev/null -w '%{http_code}' --connect-timeout 2 --max-time 6 "$BASE_URL/api/notes" 2>/dev/null)
  case "$code" in
    401|403) good "/api/notes sin token → $code (protegido correctamente)";;
    000)     flag "No se pudo contactar el servidor ($BASE_URL)."; return 1;;
    *)       flag "/api/notes sin token → $code (se esperaba 401/403)"; return 1;;
  esac
}
m_ratelimit() {
  http_reachable || { note "Servidor no accesible en $BASE_URL (arráncalo con 'npm start'); prueba omitida."; return 0; }

  local i codes=""
  for i in $(seq 1 12); do
    codes+="$(curl -sS -o /dev/null -w '%{http_code} ' --connect-timeout 2 --max-time 4 -X POST "$BASE_URL/api/auth/login" -H 'Content-Type: application/json' -d '{"username":"pl_probe","password":"x"}' 2>/dev/null)"
  done
  say "Códigos de 12 intentos: $codes"
  grep -q '429' <<<"$codes" && good "Rate limiting activo (aparece 429)." || { note "No se observó 429 en 12 intentos (revisa el umbral configurado)."; return 1; }
}
m_badjson() {
  http_reachable || { note "Servidor no accesible en $BASE_URL (arráncalo con 'npm start'); prueba omitida."; return 0; }

  local code; code=$(curl -sS -o /dev/null -w '%{http_code}' --connect-timeout 2 --max-time 6 -X POST "$BASE_URL/api/auth/login" -H 'Content-Type: application/json' -d '{bad json' 2>/dev/null)
  [[ "$code" == "400" ]] && good "JSON malformado → 400 (validación correcta)." || { flag "JSON malformado → $code (se esperaba 400)."; return 1; }
}
m_cors() {
  http_reachable || { note "Servidor no accesible en $BASE_URL (arráncalo con 'npm start'); prueba omitida."; return 0; }

  local h; h=$(curl -sS -D - -o /dev/null --connect-timeout 2 --max-time 6 -H 'Origin: https://evil.example' "$BASE_URL/health" 2>/dev/null | grep -i '^access-control-allow-origin:')
  if grep -iq 'evil.example\|\*' <<<"$h"; then flag "CORS refleja/permite origen arbitrario: $h"; return 1; else good "CORS no refleja el origen malicioso."; fi
}
m_api_headers() {
  http_reachable || { note "Servidor no accesible en $BASE_URL (arráncalo con 'npm start'); prueba omitida."; return 0; }
 curl -sS -D - -o /dev/null --connect-timeout 2 --max-time 6 "$BASE_URL/health" 2>/dev/null | grep -iE '^(x-|strict-|content-security)' || { note "Sin cabeceras de seguridad extra en /health."; return 0; }; }
m_err_leak() {
  http_reachable || { note "Servidor no accesible en $BASE_URL (arráncalo con 'npm start'); prueba omitida."; return 0; }
 curl -sS --connect-timeout 2 --max-time 6 "$BASE_URL/api/notes/not-a-number" 2>/dev/null | head -5 | grep -iqE 'at .*\.js:|stack|SequelizeError|SyntaxError' && { flag "Respuesta de error con posible traza interna."; return 1; } || good "Error sin traza interna visible."; }

reg 9 "Endpoint /health"           "Comprueba disponibilidad del servidor."              "curl" "LOW" m_health
reg 9 "Acceso no autenticado"      "/api/notes sin token debe dar 401/403."              "curl" "LOW" m_unauth
reg 9 "Rate limiting en login"     "12 intentos: espera ver 429."                        "curl" "LOW" m_ratelimit
reg 9 "Validación de entrada"      "JSON malformado debe dar 400."                       "curl" "LOW" m_badjson
reg 9 "Política CORS"              "Origen malicioso no debe reflejarse."                "curl" "LOW" m_cors
reg 9 "Cabeceras de seguridad API" "Cabeceras extra en respuestas de API."               "curl" "LOW" m_api_headers
reg 9 "Fuga de errores en API"     "El error de ID inválido no debe filtrar traza."      "curl" "LOW" m_err_leak
