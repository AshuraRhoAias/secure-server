#!/usr/bin/env bash
# Categoría 5 — Auditoría de configuraciones de servidores (web).

m_whatweb()     { confirm_target "$TARGET" || return 2; whatweb --no-errors -a 3 "$BASE_URL" 2>&1; }
m_server_hdr()  { curl -sS -D - -o /dev/null --connect-timeout 2 --max-time 6 "$BASE_URL" 2>/dev/null | grep -iE '^(server|x-powered-by):' && flag "El servidor revela software/versión (considera ocultarlo)." || { good "No se revela Server/X-Powered-By."; }; }
m_dir_listing() {
  local rc=0 p
  for p in / /files/ /uploads/ /static/ /backup/; do
    local code; code=$(curl -sS -o /tmp/pl_dl.$$ -w '%{http_code}' --connect-timeout 2 --max-time 5 "$BASE_URL$p" 2>/dev/null)
    if grep -qi 'Index of' /tmp/pl_dl.$$ 2>/dev/null; then flag "Posible listado de directorios en $p (HTTP $code)"; rc=1; else note "$p → HTTP $code"; fi
  done
  rm -f /tmp/pl_dl.$$; return $rc
}
m_exposed()     {
  local rc=0 p
  for p in /.env /.git/config /package.json /.git/HEAD /config.js /docker-compose.yml; do
    local code; code=$(curl -sS -o /dev/null -w '%{http_code}' --connect-timeout 2 --max-time 5 "$BASE_URL$p" 2>/dev/null)
    if [[ "$code" == "200" ]]; then flag "Archivo sensible accesible: $p (HTTP 200)"; rc=1; else note "$p → HTTP $code"; fi
  done
  return $rc
}
m_error_page()  { curl -sS -i --connect-timeout 2 --max-time 6 "$BASE_URL/__pl_noexiste_$RANDOM" 2>/dev/null | head -20 | grep -iqE 'stack|at .*\.js:|Error:' && { flag "La página de error parece filtrar detalles internos."; return 1; } || good "La página de error no filtra traza visible."; }
m_trace()       { local m; m=$(curl -sS -i -X TRACE --connect-timeout 2 --max-time 6 "$BASE_URL" 2>/dev/null | head -1); grep -qi '200' <<<"$m" && { flag "Método TRACE habilitado (riesgo XST)."; return 1; } || good "TRACE no habilitado."; }
m_cookie_flags(){
  local sc; sc=$(curl -sS -D - -o /dev/null --connect-timeout 2 --max-time 6 "$BASE_URL" 2>/dev/null | grep -i '^set-cookie:')
  [[ -z "$sc" ]] && { note "El endpoint raíz no fija cookies."; return 0; }
  say "$sc"
  local rc=0
  grep -iq 'HttpOnly' <<<"$sc" || { flag "Falta HttpOnly en alguna cookie"; rc=1; }
  grep -iq 'Secure'   <<<"$sc" || { flag "Falta Secure en alguna cookie"; rc=1; }
  grep -iq 'SameSite' <<<"$sc" || { flag "Falta SameSite en alguna cookie"; rc=1; }
  return $rc
}

reg 5 "Fingerprint web (whatweb)"      "Tecnologías del servidor y la app."                 "whatweb" "LOW"  m_whatweb
reg 5 "Divulgación Server/X-Powered-By" "Detecta cabeceras que revelan software."           "curl"    "LOW"  m_server_hdr
reg 5 "Listado de directorios"         "Busca 'Index of' en rutas comunes."                 "curl"    "LOW"  m_dir_listing
reg 5 "Archivos sensibles expuestos"   "Prueba .env, .git, package.json, etc. vía HTTP."    "curl"    "LOW"  m_exposed
reg 5 "Fuga en páginas de error"       "Comprueba si el 404/500 revela trazas."             "curl"    "LOW"  m_error_page
reg 5 "Método TRACE (XST)"             "Detecta TRACE habilitado."                          "curl"    "LOW"  m_trace
reg 5 "Flags de cookies"               "Secure/HttpOnly/SameSite en Set-Cookie."            "curl"    "LOW"  m_cookie_flags
