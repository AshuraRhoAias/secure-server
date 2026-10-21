#!/usr/bin/env bash
# Categoría 8 — Análisis estático (y dinámico ligero) de código.

_js_files() { find "$REPO_DIR" -path "$REPO_DIR/node_modules" -prune -o -name '*.js' -type f -print 2>/dev/null; }

m_node_check() {
  local rc=0 f
  while IFS= read -r f; do
    node --check "$f" 2>/tmp/pl_nc.$$ || { flag "Sintaxis inválida: ${f#$REPO_DIR/}"; cat /tmp/pl_nc.$$; rc=1; }
  done < <(_js_files)
  rm -f /tmp/pl_nc.$$
  (( rc==0 )) && good "Todos los .js pasan 'node --check'."
  return $rc
}
m_eslint() { ( cd "$REPO_DIR" && eslint src --no-eslintrc --env node,es2022 --parser-options ecmaVersion:2022 2>&1 ) | head -60 || true; note "(eslint sin config del proyecto: sólo errores de parseo)"; }
m_bandit() {
  if find "$REPO_DIR" -path "$REPO_DIR/node_modules" -prune -o -name '*.py' -type f -print 2>/dev/null | grep -q .; then
    bandit -r "$REPO_DIR" -x "$REPO_DIR/node_modules" 2>&1 | tail -40; return ${PIPESTATUS[0]}
  else note "Sin archivos .py en el repo (proyecto Node)."; fi
}
m_shellcheck() {
  local rc=0 f found=0
  while IFS= read -r f; do found=1; shellcheck -S warning "$f" 2>&1 || rc=1; done < <(find "$REPO_DIR" -path "$REPO_DIR/node_modules" -prune -o -name '*.sh' -type f -print 2>/dev/null)
  (( found==0 )) && { note "Sin scripts .sh fuera del propio entorno."; return 0; }
  (( rc==0 )) && good "shellcheck sin advertencias (nivel warning)."
  return $rc
}
m_danger() {
  local rc=0
  say "Buscando patrones peligrosos en src/ …"
  if grep -rnE '\beval\(|child_process|exec\(|execSync|new Function\(' "$REPO_DIR/src" 2>/dev/null | grep -v node_modules; then
    flag "Revisar los usos anteriores (ejecución dinámica / comandos)."; rc=1
  else good "Sin eval/exec/child_process evidentes en src/."; fi
  return $rc
}
m_debug_flags() {
  local rc=0
  if grep -rnE 'console\.log\(|NODE_ENV.*development|debug\s*=\s*true' "$REPO_DIR/src" 2>/dev/null | grep -v node_modules | head -30; then
    note "Revisa restos de depuración/console.log antes de producción."; rc=1
  else good "Sin restos de depuración evidentes."; fi
  return $rc
}
m_yamllint() {
  if find "$REPO_DIR" -path "$REPO_DIR/node_modules" -prune -o \( -name '*.yml' -o -name '*.yaml' \) -type f -print 2>/dev/null | grep -q .; then
    yamllint -d relaxed "$REPO_DIR" 2>&1 | grep -v node_modules | head -40; return ${PIPESTATUS[0]}
  else note "Sin archivos YAML en el repo."; fi
}

reg 8 "Sintaxis JS (node --check)"  "Valida la sintaxis de todos los .js."                ""           "LOCAL" m_node_check
reg 8 "ESLint (errores de parseo)"  "Análisis estático básico de src/."                   "eslint"     "LOCAL" m_eslint
reg 8 "Bandit (Python)"             "SAST para archivos .py (si los hay)."                "bandit"     "LOCAL" m_bandit
reg 8 "ShellCheck (.sh)"            "Analiza scripts shell del repo."                     "shellcheck" "LOCAL" m_shellcheck
reg 8 "Patrones peligrosos"         "Busca eval/exec/child_process en src/."              "grep"       "LOCAL" m_danger
reg 8 "Restos de depuración"        "console.log, NODE_ENV=development, debug=true."       "grep"       "LOCAL" m_debug_flags
reg 8 "YAML lint"                   "Valida archivos YAML del repo."                      "yamllint"   "LOCAL" m_yamllint
