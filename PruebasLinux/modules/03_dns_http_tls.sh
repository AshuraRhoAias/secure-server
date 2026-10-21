#!/usr/bin/env bash
# Categoría 3 — Auditoría de DNS, HTTP, HTTPS y TLS.
# Las pruebas HTTP/TLS usan $BASE_URL o $TARGET:443 según corresponda.

_host_of_url() { echo "$1" | sed -E 's#^[a-z]+://##; s#/.*$##; s#:.*$##'; }

m_dig_a()     { dig +noall +answer "$TARGET" A; }
m_dig_mx()    { dig +noall +answer "$TARGET" MX; }
m_dig_txt()   { dig +noall +answer "$TARGET" TXT; }
m_dig_ns()    { dig +noall +answer "$TARGET" NS; }
m_dig_trace() { dig +trace "$TARGET" | head -40; }
m_dnssec()   { dig +dnssec +noall +answer "$TARGET" | grep -qi rrsig && good "DNSSEC presente (RRSIG)" || { note "Sin registros RRSIG visibles."; return 1; }; }
m_axfr()     {
  local ns; ns=$(dig +short NS "$TARGET" | head -1)
  [[ -z "$ns" ]] && { note "Sin NS para $TARGET"; return 1; }
  note "Intentando transferencia de zona contra $ns (debe fallar en servidores bien configurados)…"
  if dig AXFR "$TARGET" "@$ns" | grep -q 'Transfer failed\|connection timed out\|; <<>>'; then good "Transferencia de zona RECHAZADA (correcto)."; else flag "Posible transferencia de zona permitida — revisar."; return 1; fi
}
m_http_headers() { curl -sS -D - -o /dev/null --connect-timeout 2 --max-time 6 "$BASE_URL" || { flag "No se pudo contactar $BASE_URL"; return 1; }; }
m_sec_headers()  {
  local h; h=$(curl -sS -D - -o /dev/null --connect-timeout 2 --max-time 6 "$BASE_URL" 2>/dev/null) || { flag "No se pudo contactar $BASE_URL"; return 1; }
  local rc=0
  for hdr in "Strict-Transport-Security" "Content-Security-Policy" "X-Frame-Options" "X-Content-Type-Options" "Referrer-Policy"; do
    if grep -iq "^$hdr:" <<<"$h"; then good "$hdr presente"; else flag "$hdr AUSENTE"; rc=1; fi
  done
  return $rc
}
m_http_methods() { curl -sS -i -X OPTIONS --connect-timeout 2 --max-time 6 "$BASE_URL" | grep -i '^allow:' || { note "El servidor no anuncia métodos vía OPTIONS."; return 0; }; }
m_tls_cert()     { local h; h=$(_host_of_url "$BASE_URL"); echo | openssl s_client -connect "$h:443" -servername "$h" 2>/dev/null | openssl x509 -noout -subject -issuer -dates 2>/dev/null || { note "Sin TLS en $h:443 (esperable en lab HTTP)."; return 1; }; }
m_tls_expiry()   {
  local h; h=$(_host_of_url "$BASE_URL")
  local end; end=$(echo | openssl s_client -connect "$h:443" -servername "$h" 2>/dev/null | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)
  [[ -z "$end" ]] && { note "Sin certificado TLS en $h:443."; return 1; }
  good "Expira: $end"
}
m_sslscan()      { local h; h=$(_host_of_url "$BASE_URL"); sslscan --no-colour "$h:443" 2>&1 || { note "sslscan no pudo conectar a $h:443."; return 1; }; }
m_tls_versions() {
  local h; h=$(_host_of_url "$BASE_URL") v
  for v in tls1 tls1_1 tls1_2 tls1_3; do
    if echo | openssl s_client -connect "$h:443" -"$v" 2>/dev/null | grep -q "BEGIN CERTIFICATE"; then
      case "$v" in tls1|tls1_1) flag "$v ACEPTADO (protocolo obsoleto)";; *) good "$v aceptado";; esac
    else note "$v no negociado"; fi
  done
}
m_weak_ciphers() { confirm_target "$TARGET" || return 2; nmap -Pn --script ssl-enum-ciphers -p 443 "$(_host_of_url "$BASE_URL")" 2>&1; }
m_redirects()    { curl -sS -I -L --connect-timeout 2 --max-time 8 "$BASE_URL" | grep -iE '^(HTTP/|location:)' || { note "Sin redirecciones."; return 0; }; }

reg 3 "DNS: registros A"           "Resolución de direcciones A del objetivo."            "dig"    "INFO" m_dig_a
reg 3 "DNS: registros MX"          "Servidores de correo del dominio."                    "dig"    "INFO" m_dig_mx
reg 3 "DNS: registros TXT"         "SPF/DKIM/DMARC y otros TXT."                           "dig"    "INFO" m_dig_txt
reg 3 "DNS: registros NS"          "Servidores de nombres autoritativos."                 "dig"    "INFO" m_dig_ns
reg 3 "DNS: traza de resolución"   "dig +trace (delegación completa)."                    "dig"    "LOW"  m_dig_trace
reg 3 "DNSSEC: comprobar RRSIG"    "Verifica firmas DNSSEC."                              "dig"    "INFO" m_dnssec
reg 3 "Transferencia de zona (AXFR)" "Comprueba que AXFR esté correctamente denegada."    "dig"    "LOW"  m_axfr
reg 3 "HTTP: cabeceras de respuesta" "Cabeceras HTTP del servidor (curl -I)."             "curl"   "LOW"  m_http_headers
reg 3 "HTTP: cabeceras de seguridad" "HSTS, CSP, X-Frame-Options, etc."                   "curl"   "LOW"  m_sec_headers
reg 3 "HTTP: métodos permitidos"   "Métodos anunciados vía OPTIONS."                      "curl"   "LOW"  m_http_methods
reg 3 "TLS: datos del certificado" "Subject/Issuer/validez del certificado."              "openssl" "LOW" m_tls_cert
reg 3 "TLS: caducidad del certificado" "Fecha de expiración del certificado."             "openssl" "LOW" m_tls_expiry
reg 3 "TLS: auditoría con sslscan" "Protocolos y cifrados soportados."                    "sslscan" "MEDIUM" m_sslscan
reg 3 "TLS: versiones aceptadas"   "Comprueba TLS 1.0–1.3 (marca obsoletos)."             "openssl" "LOW" m_tls_versions
reg 3 "TLS: cifrados débiles (nmap)" "ssl-enum-ciphers sobre el puerto 443."              "nmap"   "MEDIUM" m_weak_ciphers
reg 3 "HTTP: cadena de redirecciones" "Sigue redirecciones y muestra Location."           "curl"   "LOW"  m_redirects
