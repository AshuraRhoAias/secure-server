#!/usr/bin/env bash
# Categoría 12 — Detección de secretos expuestos y configuraciones inseguras.

m_detect_secrets() {
  local n
  n=$( ( cd "$REPO_DIR" && detect-secrets scan --exclude-files 'node_modules|package-lock.json' 2>/dev/null ) \
    | jq -r '.results | if length==0 then "0" else (to_entries[] | "\(.key): \(.value|length) hallazgo(s)") end' 2>/dev/null )
  if [[ -z "$n" ]]; then note "detect-secrets/jq no produjeron salida."; return 1; fi
  if [[ "$n" == "0" ]]; then good "detect-secrets no reporta secretos (en archivos versionables)."; return 0; fi
  while IFS= read -r line; do flag "$line"; done <<<"$n"
  note "Revisa los hallazgos; márcalos como falsos positivos con una baseline si procede (.secrets.baseline)."
  return 1
}
m_gitleaks() { if have_cmd gitleaks; then ( cd "$REPO_DIR" && gitleaks detect --no-banner 2>&1 ) | tail -30; return ${PIPESTATUS[0]}; else note "gitleaks no instalado → $(install_hint gitleaks)"; return 3; fi; }
m_grep_keys() {
  local rc=0
  say "Buscando patrones de claves/tokens en archivos versionados…"
  if git -C "$REPO_DIR" grep -nIE 'AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|ghp_[0-9A-Za-z]{36}|-----BEGIN [A-Z ]*PRIVATE KEY-----|xox[baprs]-' -- . ':(exclude)package-lock.json' 2>/dev/null; then
    flag "Patrones de secreto encontrados — revisar."; rc=1
  else good "Sin patrones de clave/token conocidos en archivos versionados."; fi
  return $rc
}
m_env_committed() {
  if git -C "$REPO_DIR" ls-files --error-unmatch .env >/dev/null 2>&1; then flag ".env está versionado en git (debe ignorarse)."; return 1; else good ".env no está versionado."; fi
}
m_git_history() {
  say "Buscando secretos en el historial (últimos 50 commits)…"
  if git -C "$REPO_DIR" log -p -50 2>/dev/null | grep -nIE 'AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY-----|password\s*=\s*["'\''][^"'\'']{6,}' | head -20; then
    flag "Posibles secretos en el historial — considera rotarlos y limpiar el historial."; return 1
  else good "Sin secretos evidentes en los últimos 50 commits."; fi
}
m_private_keys() {
  local f; f=$(find "$REPO_DIR" -path "$REPO_DIR/node_modules" -prune -o \( -name '*.pem' -o -name '*.key' -o -name 'id_rsa*' \) -type f -print 2>/dev/null)
  if [[ -n "$f" ]]; then flag "Archivos de clave privada en el repo:"; say "$f"; return 1; else good "Sin archivos de clave privada en el repo."; fi
}
m_entropy() {
  python3 - "$REPO_DIR" <<'PY'
import os,sys,math,re
root=sys.argv[1]
def ent(s):
    if not s: return 0
    from collections import Counter
    n=len(s); return -sum((c/n)*math.log2(c/n) for c in Counter(s).values())
skip=('node_modules','.git','logs','reports')
skipfiles=('package-lock.json','yarn.lock','pnpm-lock.yaml')
hits=0
for dp,dn,fn in os.walk(root):
    if any(s in dp for s in skip): continue
    for f in fn:
        if f.endswith(('.lock','.map','.min.js')) or f in skipfiles: continue
        p=os.path.join(dp,f)
        try:
            if os.path.getsize(p)>400000: continue
            for i,line in enumerate(open(p,encoding='utf-8',errors='ignore'),1):
                # Ignora líneas que son claramente hashes de integridad/dependencias.
                if 'integrity' in line or 'sha512-' in line or 'sha256-' in line: continue
                for tok in re.findall(r'[A-Za-z0-9+/=_\-]{24,}', line):
                    if ent(tok)>4.6:
                        print(f"  [!] alta entropia ({ent(tok):.1f}) en {os.path.relpath(p,root)}:{i}")
                        hits+=1; break
        except Exception: pass
        if hits>=25: break
    if hits>=25: break
print("  [OK] Sin cadenas de alta entropía sospechosas." if hits==0 else f"  Revisar {hits} candidato(s) (posibles secretos).")
sys.exit(1 if hits else 0)
PY
}

reg 12 "detect-secrets (escaneo)"   "Motor de detección de secretos de Yelp."           "detect-secrets" "LOCAL" m_detect_secrets
reg 12 "gitleaks (si está)"         "Escaneo de secretos en el repo/historial."         "gitleaks"       "LOCAL" m_gitleaks
reg 12 "Patrones de clave/token"    "git grep de AWS/GCP/GitHub/PEM/Slack."             "git"            "LOCAL" m_grep_keys
reg 12 ".env fuera de git"          "Confirma que .env no esté versionado."             "git"            "LOCAL" m_env_committed
reg 12 "Secretos en el historial"   "Revisa los últimos 50 commits."                    "git"            "LOCAL" m_git_history
reg 12 "Claves privadas en el repo" "Busca .pem/.key/id_rsa."                           "find"           "LOCAL" m_private_keys
reg 12 "Heurística de entropía"     "Cadenas de alta entropía (posibles secretos)."     "python3"        "LOCAL" m_entropy
