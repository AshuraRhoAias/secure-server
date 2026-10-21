#!/usr/bin/env bash
# Categoría 15 — Generación de informes técnicos y recomendaciones.

m_env_report()  { diagnose_env; }
m_export_md()   { report_have_results && report_markdown || { warn "Ejecuta pruebas antes de exportar."; return 1; }; }
m_export_json() { report_have_results && report_json     || { warn "Ejecuta pruebas antes de exportar."; return 1; }; }
m_export_csv()  { report_have_results && report_csv      || { warn "Ejecuta pruebas antes de exportar."; return 1; }; }
m_run_safe()    { run_safe_all; report_markdown; }
m_scorecard()   {
  if ! report_have_results; then warn "Sin resultados en esta sesión; ejecuta pruebas primero (p.ej. perfil seguro)."; return 1; fi
  local total=${#RES_IDS[@]} ok_n=0 flag_n=0 skip_n=0 i
  for i in "${!RES_IDS[@]}"; do
    case "${RES_STATUS[$i]}" in
      OK) ok_n=$((ok_n+1));;
      "OMITIDA"*) skip_n=$((skip_n+1));;
      *) flag_n=$((flag_n+1));;
    esac
  done
  hr
  say "Resumen de la sesión:"
  say "  Pruebas ejecutadas : $total"
  say "  Sin hallazgos (OK) : $ok_n"
  say "  Con hallazgos/error: $flag_n"
  say "  Omitidas (dep.)    : $skip_n"
  local base=$((total - skip_n))
  if (( base > 0 )); then
    local score=$(( ok_n * 100 / base ))
    say "  Índice de pruebas superadas: ${score}% (sobre las realmente ejecutadas)"
  fi
  note "Este índice mide pruebas superadas en esta sesión; NO es una puntuación de seguridad absoluta."
}

reg 15 "Informe del entorno"        "Diagnóstico de herramientas disponibles/ausentes." "" "INFO" m_env_report
reg 15 "Exportar a Markdown"        "Guarda los resultados de la sesión en .md."        "" "INFO" m_export_md
reg 15 "Exportar a JSON"            "Guarda los resultados de la sesión en .json."      "" "INFO" m_export_json
reg 15 "Exportar a CSV"             "Guarda los resultados de la sesión en .csv."       "" "INFO" m_export_csv
reg 15 "Ejecutar perfil seguro"     "Corre todas las pruebas locales/INFO/LOW."         "" "LOCAL" m_run_safe
reg 15 "Scorecard de la sesión"     "Resumen OK/hallazgos/omitidas e índice."           "" "INFO" m_scorecard
