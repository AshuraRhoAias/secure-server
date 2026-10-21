#!/usr/bin/env bash
# report.sh — Exportación de resultados a Markdown, JSON y CSV.
# Consume los arrays RES_* rellenados por core.sh::run_option.

_json_escape() { printf '%s' "$1" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read())[1:-1])'; }

report_have_results() { [[ "${#RES_IDS[@]}" -gt 0 ]]; }

report_markdown() {
  local out="${1:-$PL_REPORT_DIR/reporte_${PL_RUN_ID}.md}" i
  {
    echo "# Informe de PruebasLinux"
    echo
    echo "- **Fecha (UTC):** $(_ts)"
    echo "- **Host:** $(uname -n)"
    echo "- **Objetivo:** $TARGET"
    echo "- **URL base:** $BASE_URL"
    echo "- **Log asociado:** \`$(basename "$PL_LOG_FILE")\`"
    echo "- **Pruebas ejecutadas:** ${#RES_IDS[@]}"
    echo
    echo "| # | Prueba | Estado | rc | Riesgo | Inicio | Duración | Notas |"
    echo "|---|--------|--------|----|--------|--------|----------|-------|"
    for i in "${!RES_IDS[@]}"; do
      printf '| %s | %s | %s | %s | %s | %s | %s | %s |\n' \
        "${RES_IDS[$i]}" "${RES_NAME[$i]//|/\\|}" "${RES_STATUS[$i]}" \
        "${RES_RC[$i]}" "${RES_RISK[$i]}" "${RES_START[$i]}" "${RES_DUR[$i]}" "${RES_NOTE[$i]//|/\\|}"
    done
    echo
    echo "> Generado por el entorno PruebasLinux. Los estados reflejan el código de salida real de cada herramienta."
    echo "> \`OK\` = ejecución sin error; \`CON HALLAZGOS/ERROR\` = la herramienta terminó con rc≠0 (revisa el log);"
    echo "> \`OMITIDA\` = faltaba una dependencia; \`CANCELADA\` = interrumpida por el usuario."
  } > "$out"
  ok "Informe Markdown escrito en: $out"
}

report_json() {
  local out="${1:-$PL_REPORT_DIR/reporte_${PL_RUN_ID}.json}" i
  {
    echo "{"
    echo "  \"generated_at\": \"$(_ts)\","
    echo "  \"host\": \"$(uname -n)\","
    echo "  \"target\": \"$TARGET\","
    echo "  \"base_url\": \"$BASE_URL\","
    echo "  \"log_file\": \"$(basename "$PL_LOG_FILE")\","
    echo "  \"results\": ["
    for i in "${!RES_IDS[@]}"; do
      local comma=","; [[ "$i" -eq $(( ${#RES_IDS[@]} - 1 )) ]] && comma=""
      printf '    {"id": %s, "name": "%s", "status": "%s", "rc": "%s", "risk": "%s", "start": "%s", "duration": "%s", "note": "%s"}%s\n' \
        "${RES_IDS[$i]}" "$(_json_escape "${RES_NAME[$i]}")" "${RES_STATUS[$i]}" \
        "${RES_RC[$i]}" "${RES_RISK[$i]}" "${RES_START[$i]}" "${RES_DUR[$i]}" \
        "$(_json_escape "${RES_NOTE[$i]}")" "$comma"
    done
    echo "  ]"
    echo "}"
  } > "$out"
  ok "Informe JSON escrito en: $out"
}

report_csv() {
  local out="${1:-$PL_REPORT_DIR/reporte_${PL_RUN_ID}.csv}" i
  {
    echo "id,name,status,rc,risk,start,duration,note"
    for i in "${!RES_IDS[@]}"; do
      printf '%s,"%s","%s",%s,%s,%s,%s,"%s"\n' \
        "${RES_IDS[$i]}" "${RES_NAME[$i]//\"/\"\"}" "${RES_STATUS[$i]}" \
        "${RES_RC[$i]}" "${RES_RISK[$i]}" "${RES_START[$i]}" "${RES_DUR[$i]}" "${RES_NOTE[$i]//\"/\"\"}"
    done
  } > "$out"
  ok "Informe CSV escrito en: $out"
}

report_all() {
  if ! report_have_results; then warn "No hay resultados que exportar todavía."; return 1; fi
  report_markdown; report_json; report_csv
}
