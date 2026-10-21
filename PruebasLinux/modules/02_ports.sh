#!/usr/bin/env bash
# Categoría 2 — Análisis de puertos y protocolos.

m_nmap_version()  { confirm_target "$TARGET" || return 2; nmap -Pn -sV --version-light "$TARGET"; }
m_nmap_os()       { confirm_target "$TARGET" || return 2; nmap -Pn -O "$TARGET" 2>&1 || { note "La detección de SO suele requerir privilegios root y host alcanzable."; return 1; }; }
m_nmap_top20()    { confirm_target "$TARGET" || return 2; nmap -Pn --top-ports 20 "$TARGET"; }
m_nmap_udp()      { confirm_target "$TARGET" || return 2; nmap -Pn -sU --top-ports 20 "$TARGET" 2>&1 || { note "El escaneo UDP puede requerir root."; return 1; }; }
m_nmap_range()    {
  confirm_target "$TARGET" || return 2
  local r="${PL_PORT_RANGE:-1-1024}"
  if [[ ! "$r" =~ ^[0-9]+(-[0-9]+)?$ ]]; then flag "Rango inválido: $r"; return 2; fi
  nmap -Pn -p "$r" "$TARGET"
}
m_nmap_banner()   { confirm_target "$TARGET" || return 2; nmap -Pn -sV --script=banner --top-ports 50 "$TARGET"; }
m_nmap_default()  { confirm_target "$TARGET" || return 2; nmap -Pn -sC -F "$TARGET"; }
m_tcp_check()     {
  confirm_target "$TARGET" || return 2
  local p="${PL_PORT:-3000}"
  valid_port "$p" || { flag "Puerto inválido: $p"; return 2; }
  if timeout 3 bash -c ">/dev/tcp/$TARGET/$p" 2>/dev/null; then good "Puerto $p ABIERTO en $TARGET"; else note "Puerto $p cerrado/filtrado en $TARGET"; fi
}
m_local_ports()   { if have_cmd ss; then ss -tlnp; else netstat -tlnp 2>/dev/null; fi; }

reg 2 "Detección de servicios/versión (nmap -sV)" "Identifica servicios y versiones en puertos abiertos." "nmap" "MEDIUM" m_nmap_version
reg 2 "Detección de SO (nmap -O)"        "Huella del sistema operativo (requiere root)."              "nmap" "MEDIUM" m_nmap_os
reg 2 "Top-20 puertos (nmap)"            "Escaneo rápido de los 20 puertos más usados."               "nmap" "MEDIUM" m_nmap_top20
reg 2 "Escaneo UDP top-20 (nmap)"        "Puertos UDP comunes (requiere root)."                       "nmap" "MEDIUM" m_nmap_udp
reg 2 "Rango de puertos personalizado"   "Escanea PL_PORT_RANGE (por defecto 1-1024)."                "nmap" "MEDIUM" m_nmap_range
reg 2 "Banner grabbing (nmap)"           "Captura banners de servicios (top-50)."                     "nmap" "MEDIUM" m_nmap_banner
reg 2 "Scripts seguros por defecto (nmap -sC)" "NSE 'default' sobre top-100."                         "nmap" "MEDIUM" m_nmap_default
reg 2 "Comprobar un puerto TCP (bash)"   "Prueba PL_PORT (def. 3000) con /dev/tcp."                   ""     "LOW"  m_tcp_check
reg 2 "Puertos TCP locales en escucha"   "Lista puertos TCP locales y proceso."                       "ss"   "INFO" m_local_ports
