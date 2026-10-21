#!/usr/bin/env bash
# Categoría 1 — Reconocimiento de red y descubrimiento de servicios.
# Todas las pruebas usan $TARGET (por defecto 127.0.0.1, laboratorio local).

m_ping_host()      { confirm_target "$TARGET" || return 2; ping -c 3 -W 2 "$TARGET"; }
m_nmap_discovery() { confirm_target "$TARGET" || return 2; nmap -sn "$TARGET"; }
m_nmap_fast()      { confirm_target "$TARGET" || return 2; nmap -Pn -F "$TARGET"; }
m_nmap_top1000()   { confirm_target "$TARGET" || return 2; nmap -Pn --top-ports 1000 "$TARGET"; }
m_traceroute()     { confirm_target "$TARGET" || return 2; traceroute -m 15 "$TARGET"; }
m_mtr()            { confirm_target "$TARGET" || return 2; mtr -r -c 5 "$TARGET"; }
m_resolve()        { getent hosts "$TARGET" || { flag "Sin resolución para $TARGET"; return 1; }; }
m_whois()          { if have_cmd whois; then whois "$TARGET"; else flag "whois no instalado"; return 3; fi; }
m_arp_neigh()      { if have_cmd ip; then ip neigh show; else arp -a 2>/dev/null || { flag "ip/arp no disponibles"; return 3; }; fi; }
m_local_listen()   { if have_cmd ss; then ss -tulpn; else netstat -tulpn 2>/dev/null; fi; }

reg 1 "Ping al objetivo"                 "Comprueba si el host responde a ICMP (3 paquetes)."            "ping"        "LOW"  m_ping_host
reg 1 "Descubrimiento de hosts (nmap -sn)" "Ping scan sin escaneo de puertos."                           "nmap"        "LOW"  m_nmap_discovery
reg 1 "Escaneo rápido de puertos (nmap -F)" "Top-100 puertos TCP más comunes."                           "nmap"        "MEDIUM" m_nmap_fast
reg 1 "Escaneo top-1000 (nmap)"          "Los 1000 puertos TCP más frecuentes."                          "nmap"        "MEDIUM" m_nmap_top1000
reg 1 "Traceroute"                       "Ruta de red hasta el objetivo (máx 15 saltos)."                "traceroute"  "LOW"  m_traceroute
reg 1 "MTR (traceroute + pérdidas)"      "Informe de latencia y pérdida por salto."                      "mtr"         "LOW"  m_mtr
reg 1 "Resolución de nombre"             "Resolución directa del host/IP del objetivo."                  "getent"      "INFO" m_resolve
reg 1 "WHOIS del objetivo"               "Información de registro del dominio/IP."                        "whois"       "LOW"  m_whois
reg 1 "Vecinos de red (ARP)"             "Tabla ARP/neighbors local."                                    "ip"          "INFO" m_arp_neigh
reg 1 "Servicios locales a la escucha"   "Puertos abiertos locales y su proceso (ss/netstat)."           "ss"          "INFO" m_local_listen
