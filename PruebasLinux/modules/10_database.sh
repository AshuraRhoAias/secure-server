#!/usr/bin/env bash
# Categoría 10 — Auditoría de bases de datos (estática sobre esquema/código + test de conexión opcional).

_schema() { echo "$REPO_DIR/database/schema.sql"; }

m_schema_sensitive() {
  local s; s="$(_schema)"
  [[ -f "$s" ]] || { note "Sin database/schema.sql."; return 0; }
  say "Columnas que sugieren datos sensibles y si parecen cifradas/hasheadas:"
  grep -inE '(password|passwd|secret|token|ssn|card|email|phone|username)[a-z_]*' "$s" | while read -r line; do
    if grep -qiE 'encrypted|hash' <<<"$line"; then good "$line"; else flag "$line  ← ¿texto plano?"; fi
  done
  grep -iqE '(password|secret|token)[a-z_]*\s' "$s" && grep -iE '(password|secret|token)[a-z_]*\s' "$s" | grep -viqE 'encrypted|hash' && return 1
  return 0
}
m_migrations_enc() {
  local d="$REPO_DIR/database/migrations"
  [[ -d "$d" ]] || { note "Sin carpeta de migraciones."; return 0; }
  grep -rilE 'encrypt|_encrypted|crypto' "$d" && good "Las migraciones referencian cifrado." || { note "Las migraciones no mencionan cifrado explícito."; }
}
m_sql_injection() {
  say "Buscando concatenación/interpolación en consultas SQL…"
  local hits
  hits=$(grep -rnE 'query\(\s*`[^`]*\$\{|query\(\s*["'\''][^"'\'']*\+' "$REPO_DIR/src" 2>/dev/null | grep -v node_modules)
  if [[ -n "$hits" ]]; then
    say "$hits"
    # Interpolar NOMBRES de columnas con lista blanca es aceptable; valores deben ir parametrizados.
    flag "Revisar: toda interpolación debe limitarse a identificadores validados; los valores, con '?'"
    return 1
  else good "No se detecta interpolación directa de valores en consultas."; fi
}
m_db_creds() {
  if grep -rnE 'mysql://[^@]*:[^@]+@|password\s*[:=]\s*["'\''][^"'\'']{3,}' "$REPO_DIR/src" 2>/dev/null | grep -v node_modules | grep -viE 'process\.env|example|placeholder'; then
    flag "Posibles credenciales embebidas en el código."; return 1
  else good "No se detectan credenciales de BD embebidas (se usan variables de entorno)."; fi
}
m_db_connect() {
  if ! have_cmd mysql; then note "Cliente mysql no instalado; test de conexión omitido."; return 3; fi
  local host="${PL_DB_HOST:-127.0.0.1}" port="${PL_DB_PORT:-3306}"
  if timeout 3 bash -c ">/dev/tcp/$host/$port" 2>/dev/null; then good "Puerto MySQL $host:$port accesible."; else note "MySQL $host:$port no accesible (sin BD en el lab)."; return 1; fi
}
m_param_ratio() {
  local total param
  total=$(grep -roE 'db\.query\(' "$REPO_DIR/src" 2>/dev/null | wc -l)
  param=$(grep -rnE 'db\.query\([^)]*\?,' "$REPO_DIR/src" 2>/dev/null | wc -l)
  say "Llamadas db.query(): $total   con marcador '?': aprox $param"
  note "Cuanto mayor sea la proporción parametrizada, menor el riesgo de inyección."
}

reg 10 "Columnas sensibles en esquema" "¿Las columnas sensibles están cifradas/hasheadas?" "grep" "LOCAL" m_schema_sensitive
reg 10 "Cifrado en migraciones"       "Las migraciones referencian cifrado."               "grep" "LOCAL" m_migrations_enc
reg 10 "Riesgo de inyección SQL"      "Concatenación/interpolación en consultas."          "grep" "LOCAL" m_sql_injection
reg 10 "Credenciales de BD embebidas" "Busca credenciales en el código."                   "grep" "LOCAL" m_db_creds
reg 10 "Conexión a MySQL (opcional)"  "Prueba de alcance al puerto de BD."                 ""     "LOW"  m_db_connect
reg 10 "Proporción parametrizada"     "Ratio de consultas con marcadores '?'."             "grep" "INFO" m_param_ratio
