#!/usr/bin/env bash
# Categoría 4 — Detección y evaluación de vulnerabilidades conocidas.
# Pruebas NO destructivas (scripts "safe"/detección). Sólo objetivos autorizados.

_host_of_url() { echo "$1" | sed -E 's#^[a-z]+://##; s#/.*$##; s#:.*$##'; }

m_nmap_vuln()  { confirm_target "$TARGET" || return 2; nmap -Pn --script "vuln and safe" -F "$TARGET" 2>&1; }
m_nikto()      {
  confirm_target "$TARGET" || return 2
  nikto -host "$BASE_URL" -maxtime 120 2>&1 || { note "nikto terminó con avisos; revisa la salida."; return 1; }
}
m_http_enum()  { confirm_target "$TARGET" || return 2; nmap -Pn --script http-enum -p 80,443,3000 "$TARGET" 2>&1; }
m_heartbleed() { confirm_target "$TARGET" || return 2; nmap -Pn --script ssl-heartbleed -p 443 "$(_host_of_url "$BASE_URL")" 2>&1; }
m_http_vulns() { confirm_target "$TARGET" || return 2; nmap -Pn --script "http-vuln* and safe" -p 80,443,3000 "$TARGET" 2>&1; }

reg 4 "Scripts de vulnerabilidad (nmap vuln+safe)" "NSE 'vuln' no intrusivos sobre top-100." "nmap"  "MEDIUM" m_nmap_vuln
reg 4 "Escaneo web con Nikto"       "Comprobaciones conocidas del servidor web (máx 120s)." "nikto" "MEDIUM" m_nikto
reg 4 "Enumeración HTTP (http-enum)" "Descubre rutas/paneles conocidos."                    "nmap"  "MEDIUM" m_http_enum
reg 4 "Comprobar Heartbleed"        "Detecta CVE-2014-0160 en TLS (no explota)."            "nmap"  "MEDIUM" m_heartbleed
reg 4 "Vulnerabilidades HTTP (http-vuln)" "Scripts http-vuln* seguros de nmap."             "nmap"  "MEDIUM" m_http_vulns
