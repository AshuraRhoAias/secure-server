#!/usr/bin/env bash
# Categoría 14 — Evaluación de registros, trazabilidad y monitorización.

m_audit_present() {
  if grep -rqE "audit\.(log|service)|security_logs|winston" "$REPO_DIR/src" 2>/dev/null; then good "Sistema de auditoría/logging presente (audit.service / winston / security_logs)."; else flag "No se detecta sistema de auditoría."; return 1; fi
}
m_logs_encrypted() {
  local f="$REPO_DIR/src/services/audit.service.js"
  [[ -f "$f" ]] || { note "Sin audit.service.js."; return 0; }
  grep -qiE "encrypt|tripleEncryptor|cifr" "$f" && good "Los logs de seguridad se cifran antes de persistir." || flag "El servicio de auditoría no parece cifrar los registros."
}
m_log_perms() {
  local d="$PL_LOG_DIR" l="$REPO_DIR/logs"
  for t in "$d" "$l"; do
    [[ -d "$t" ]] || continue
    say "$t → $(stat -c '%a %U:%G' "$t")"
  done
  note "Los logs no deben ser legibles por usuarios no autorizados."
}
m_log_sensitive() {
  say "Buscando posible registro de datos sensibles (console.log de password/token)…"
  if grep -rnE "console\.log\([^)]*(password|token|secret|jwt)" "$REPO_DIR/src" 2>/dev/null | grep -v node_modules; then
    flag "Posible fuga de datos sensibles en logs."; return 1
  else good "No se detecta console.log de datos sensibles."; fi
}
m_integrity_cfg() {
  if grep -rqiE "INTEGRITY_MONITOR_ENABLED|integrity|fingerprint" "$REPO_DIR/.env.example" "$REPO_DIR/src" 2>/dev/null; then good "Monitorización de integridad configurada."; grep -niE "INTEGRITY_MONITOR_ENABLED|INTEGRITY_CHECK" "$REPO_DIR/.env.example" 2>/dev/null; else note "Sin monitorización de integridad evidente."; fi
}
m_auth_failures() {
  if have_cmd journalctl && journalctl --no-pager -n1 >/dev/null 2>&1; then
    journalctl --no-pager -p warning -n 30 2>/dev/null | grep -iE 'fail|denied|invalid' | tail -20 || note "Sin eventos de fallo recientes en el journal."
  else note "journalctl no disponible en este entorno (contenedor)."; return 0; fi
}

reg 14 "Sistema de auditoría"       "Presencia de logging/auditoría."                   "grep" "LOCAL" m_audit_present
reg 14 "Logs cifrados"              "El servicio de auditoría cifra los registros."      "grep" "LOCAL" m_logs_encrypted
reg 14 "Permisos de logs"           "Permisos de las carpetas de logs."                  "stat" "LOCAL" m_log_perms
reg 14 "Fuga de datos en logs"      "console.log de password/token/secret."              "grep" "LOCAL" m_log_sensitive
reg 14 "Monitorización de integridad" "Config de integridad/fingerprint."                "grep" "LOCAL" m_integrity_cfg
reg 14 "Fallos de auth del sistema" "journalctl: avisos recientes (si disponible)."      ""     "LOCAL" m_auth_failures
