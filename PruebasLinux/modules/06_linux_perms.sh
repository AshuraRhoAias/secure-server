#!/usr/bin/env bash
# Categoría 6 — Análisis de permisos y seguridad del sistema Linux.
# Las comprobasiones de repo se limitan a $REPO_DIR (no tocan nada fuera).

m_ww_repo()   {
  local f; f=$(find "$REPO_DIR" -path "$REPO_DIR/node_modules" -prune -o -type f -perm -0002 -print 2>/dev/null)
  if [[ -n "$f" ]]; then flag "Archivos world-writable en el repo:"; say "$f"; return 1; else good "Sin archivos world-writable en el repo."; fi
}
m_suid()      { find / -xdev -perm -4000 -type f 2>/dev/null | head -50; note "(SUID encontrados; revisa binarios inesperados)"; }
m_sgid()      { find / -xdev -perm -2000 -type f 2>/dev/null | head -50; note "(SGID encontrados)"; }
m_env_perms() {
  local e="$REPO_DIR/.env"
  [[ -f "$e" ]] || { note "No hay .env en el repo (bien si está fuera del control de versiones)."; return 0; }
  local m; m=$(stat -c '%a' "$e")
  say ".env permisos: $m  propietario: $(stat -c '%U:%G' "$e")"
  if [[ "$m" =~ ^6[04]0$|^400$ ]]; then good "Permisos restrictivos ($m)."; else flag "Permisos de .env demasiado abiertos ($m); recomendado 600."; return 1; fi
}
m_777()       {
  local f; f=$(find "$REPO_DIR" -path "$REPO_DIR/node_modules" -prune -o -type f -perm 0777 -print 2>/dev/null)
  if [[ -n "$f" ]]; then flag "Archivos 777:"; say "$f"; return 1; else good "Sin archivos 777 en el repo."; fi
}
m_dotfiles()  {
  local rc=0 f
  for f in .env .env.local .npmrc id_rsa .ssh; do
    if [[ -e "$REPO_DIR/$f" ]]; then
      if git -C "$REPO_DIR" ls-files --error-unmatch "$f" >/dev/null 2>&1; then flag "$f está EN control de versiones"; rc=1; else good "$f presente pero fuera de git"; fi
    fi
  done
  return $rc
}
m_umask()     { local u; u=$(umask); say "umask actual: $u"; [[ "$u" =~ ^0?0[27]7$ ]] && good "umask restrictiva." || { flag "umask poco restrictiva ($u); recomendado 027/077."; return 1; }; }
m_path_w()    {
  # Peligroso = escribible por grupo u otros (bits de permiso), no por el efectivo
  # -w (que para root es siempre verdadero). Evita falsos positivos como root.
  local rc=0 d dirs perm go
  IFS=':' read -r -a dirs <<<"$PATH"
  for d in "${dirs[@]}"; do
    [[ -d "$d" ]] || continue
    if [[ "$d" == "." ]]; then flag "PATH contiene '.' (directorio actual): riesgo de ejecución."; rc=1; continue; fi
    perm=$(stat -c '%a' "$d" 2>/dev/null); perm="000${perm}"; perm="${perm: -3}"
    go="${perm:1}"   # bits de grupo y otros
    if [[ "$go" =~ [2367] ]]; then flag "Directorio de PATH escribible por grupo/otros ($perm): $d"; rc=1; fi
  done
  (( rc==0 )) && good "PATH sin directorios escribibles por grupo/otros."
  return $rc
}
m_sshd()      {
  local f=/etc/ssh/sshd_config
  [[ -r "$f" ]] || { note "sshd_config no legible/ausente."; return 0; }
  local rc=0
  grep -Eiq '^\s*PermitRootLogin\s+(yes|without-password)' "$f" && { flag "PermitRootLogin permisivo"; rc=1; } || good "PermitRootLogin restringido o por defecto"
  grep -Eiq '^\s*PasswordAuthentication\s+yes' "$f" && { flag "PasswordAuthentication yes (preferible solo claves)"; rc=1; }
  return $rc
}
m_oskern()    { . /etc/os-release 2>/dev/null; say "SO: ${PRETTY_NAME:-desconocido}"; say "Kernel: $(uname -r)"; note "Compara con avisos de seguridad del proveedor para versiones EOL."; }

reg 6 "World-writable en el repo"    "Archivos escribibles por cualquiera dentro del repo." ""       "LOCAL" m_ww_repo
reg 6 "Binarios SUID del sistema"    "Lista binarios con bit SUID."                         "find"   "LOCAL" m_suid
reg 6 "Binarios SGID del sistema"    "Lista binarios con bit SGID."                         "find"   "LOCAL" m_sgid
reg 6 "Permisos de .env"             "Verifica que .env tenga permisos restrictivos."       "stat"   "LOCAL" m_env_perms
reg 6 "Archivos con permisos 777"    "Busca 777 en el repo."                                "find"   "LOCAL" m_777
reg 6 "Secretos/dotfiles en git"     "Comprueba que .env/.ssh no estén versionados."        "git"    "LOCAL" m_dotfiles
reg 6 "Comprobar umask"              "umask actual del entorno."                            ""       "INFO"  m_umask
reg 6 "PATH escribible"              "Directorios de PATH escribibles por terceros."        ""       "LOCAL" m_path_w
reg 6 "Endurecimiento de SSHD"       "Revisa sshd_config (root login, passwords)."          ""       "LOCAL" m_sshd
reg 6 "Versión de SO y kernel"       "Muestra SO/kernel para contraste con CVEs/EOL."       ""       "INFO"  m_oskern
