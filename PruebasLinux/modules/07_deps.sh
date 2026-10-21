#!/usr/bin/env bash
# Categoría 7 — Revisión de dependencias, paquetes y librerías.

m_npm_audit()   { [[ -f "$REPO_DIR/package.json" ]] || { note "Sin package.json."; return 0; }; ( cd "$REPO_DIR" && npm audit --omit=dev 2>&1 ) | tail -40; local rc=${PIPESTATUS[0]}; return $rc; }
m_npm_audit_json(){ [[ -f "$REPO_DIR/package.json" ]] || { note "Sin package.json."; return 0; }; ( cd "$REPO_DIR" && npm audit --json 2>/dev/null ) | jq '{vulnerabilities: (.metadata.vulnerabilities // {})}' 2>/dev/null || note "jq/npm no disponibles para resumen."; }
m_npm_outdated(){ [[ -f "$REPO_DIR/package.json" ]] || { note "Sin package.json."; return 0; }; ( cd "$REPO_DIR" && npm outdated 2>&1 ) || note "(npm outdated devuelve rc≠0 cuando hay paquetes desactualizados)"; return 0; }
m_npm_prod()    { [[ -f "$REPO_DIR/package.json" ]] || { note "Sin package.json."; return 0; }; jq -r '.dependencies | to_entries[] | "  \(.key) \(.value)"' "$REPO_DIR/package.json"; }
m_pip_audit()   {
  if ls "$REPO_DIR"/requirements*.txt >/dev/null 2>&1; then
    local f; for f in "$REPO_DIR"/requirements*.txt; do say "== $f"; pip-audit -r "$f" 2>&1 || return 1; done
  else note "Sin requirements*.txt en el repo (proyecto Node)."; fi
}
m_npm_ci()      { [[ -f "$REPO_DIR/package-lock.json" ]] || { flag "Falta package-lock.json (builds no reproducibles)."; return 1; }; good "package-lock.json presente (builds reproducibles)."; note "Verificación estricta: 'npm ci' reinstala según el lock."; }
m_licenses()    { [[ -f "$REPO_DIR/package.json" ]] || return 0; say "Licencia del proyecto: $(jq -r '.license // "sin declarar"' "$REPO_DIR/package.json")"; note "Para auditar licencias de deps: 'npx license-checker' (requiere red)."; }

reg 7 "npm audit (producción)"      "Vulnerabilidades conocidas en dependencias."         "npm"  "LOCAL" m_npm_audit
reg 7 "npm audit (resumen JSON)"    "Conteo por severidad (jq)."                          "npm"  "LOCAL" m_npm_audit_json
reg 7 "npm outdated"                "Dependencias desactualizadas."                       "npm"  "LOCAL" m_npm_outdated
reg 7 "Listar dependencias de prod" "Versiones declaradas en package.json."               "jq"   "INFO"  m_npm_prod
reg 7 "pip-audit (si hay Python)"   "Vulnerabilidades en requirements*.txt."              "pip-audit" "LOCAL" m_pip_audit
reg 7 "Integridad del lockfile"     "Comprueba package-lock.json."                        ""     "LOCAL" m_npm_ci
reg 7 "Licencias"                   "Licencia del proyecto y guía de auditoría."          "jq"   "INFO"  m_licenses
