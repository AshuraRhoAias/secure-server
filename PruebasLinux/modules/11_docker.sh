#!/usr/bin/env bash
# Categoría 11 — Análisis de contenedores Docker e imágenes.

_dockerfiles() { find "$REPO_DIR" -path "$REPO_DIR/node_modules" -prune -o -iname 'Dockerfile*' -type f -print 2>/dev/null; }

m_dockerfile_present() {
  local f; f="$(_dockerfiles)"
  if [[ -n "$f" ]]; then good "Dockerfile(s) encontrados:"; say "$f"; else note "El proyecto no incluye Dockerfile."; return 0; fi
}
m_dockerfile_lint() {
  local f found=0 rc=0
  while IFS= read -r f; do
    found=1; say "== ${f#$REPO_DIR/}"
    grep -qiE '^\s*USER\s+' "$f" && good "Declara USER (no root)." || { flag "No declara USER: el contenedor correría como root."; rc=1; }
    grep -qiE ':latest' "$f" && { flag "Usa tag ':latest' (no reproducible)."; rc=1; } || good "Sin ':latest'."
    grep -qiE 'ADD\s+https?://' "$f" && { flag "ADD con URL remota (preferible COPY/validar)."; rc=1; }
    grep -qiE '(secret|password|token|key)\s*=' "$f" && { flag "Posible secreto embebido en el Dockerfile."; rc=1; }
  done < <(_dockerfiles)
  (( found==0 )) && { note "Sin Dockerfile que analizar."; return 0; }
  return $rc
}
m_docker_images() { if have_cmd docker && docker info >/dev/null 2>&1; then docker images 2>&1 | head -20; else note "Docker no disponible o sin daemon en el lab."; return 3; fi; }
m_trivy_fs() { if have_cmd trivy; then trivy fs --quiet --scanners vuln "$REPO_DIR" 2>&1 | head -60; else note "trivy no instalado → $(install_hint trivy)"; return 3; fi; }
m_trivy_image() {
  if ! have_cmd trivy; then note "trivy no instalado → $(install_hint trivy)"; return 3; fi
  local img="${PL_IMAGE:-}"; [[ -z "$img" ]] && { note "Define PL_IMAGE=<imagen> para escanear."; return 0; }
  trivy image --quiet "$img" 2>&1 | head -60
}
m_dockerignore() { if [[ -f "$REPO_DIR/.dockerignore" ]]; then good ".dockerignore presente."; grep -qE '^\.env|node_modules' "$REPO_DIR/.dockerignore" && good "Ignora .env/node_modules." || flag ".dockerignore no excluye .env/node_modules."; else [[ -n "$(_dockerfiles)" ]] && { flag "Hay Dockerfile pero falta .dockerignore."; return 1; } || note "Sin Docker en el proyecto."; fi; }
m_compose() { local c; c=$(find "$REPO_DIR" -maxdepth 2 -iname 'docker-compose*.y*ml' 2>/dev/null); [[ -z "$c" ]] && { note "Sin docker-compose."; return 0; }; say "$c"; grep -niE 'privileged:\s*true|network_mode:\s*host|:/var/run/docker.sock' $c && { flag "Configuración de compose potencialmente peligrosa."; return 1; } || good "compose sin privileged/host/docker.sock."; }

reg 11 "Presencia de Dockerfile"    "Detecta Dockerfiles en el repo."                   "find"  "LOCAL" m_dockerfile_present
reg 11 "Lint de Dockerfile"         "Buenas prácticas: USER, tags, secretos, ADD."      "find"  "LOCAL" m_dockerfile_lint
reg 11 "Imágenes Docker locales"    "Lista imágenes (si hay daemon)."                   "docker" "LOW"  m_docker_images
reg 11 "trivy fs (repo)"            "Escaneo de vulnerabilidades del árbol de archivos." "trivy" "LOCAL" m_trivy_fs
reg 11 "trivy image (PL_IMAGE)"     "Escaneo de una imagen concreta."                   "trivy" "LOW"  m_trivy_image
reg 11 "Comprobar .dockerignore"    "Que excluya .env/node_modules."                    ""      "LOCAL" m_dockerignore
reg 11 "Revisar docker-compose"     "Busca privileged/host/socket montado."             "find"  "LOCAL" m_compose
