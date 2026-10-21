#!/usr/bin/env bash
# ui.sh — Menú interactivo y navegación.

ui_banner() {
  log "${C_BOLD}${C_BLUE}"
  log "  ╔══════════════════════════════════════════════════════════╗"
  log "  ║   PruebasLinux · Entorno de pruebas de seguridad (lab)     ║"
  log "  ║   Defensivo · no destructivo · sólo sistemas autorizados   ║"
  log "  ╚══════════════════════════════════════════════════════════╝"
  log "${C_RESET}"
  log "Objetivo: ${C_BOLD}$TARGET${C_RESET}   URL base: ${C_BOLD}$BASE_URL${C_RESET}   Opciones: ${C_BOLD}$OPT_COUNT${C_RESET}"
}

# Lista las opciones de una categoría con su número global.
ui_list_category() {
  local cat="$1" i shown=0
  log "${C_BOLD}${C_MAGENTA}[$cat] ${CAT_LABEL[$cat]}${C_RESET}"
  for (( i=1; i<=OPT_COUNT; i++ )); do
    if [[ "${OPT_CAT[$i]}" == "$cat" ]]; then
      local miss; miss="$(missing_reqs "${OPT_REQ[$i]}")"
      local tag=""; [[ -n "$miss" ]] && tag=" ${C_YELLOW}(falta: $miss)${C_RESET}"
      printf '   %3d) %s ${C_DIM}· %s${C_RESET}%s\n' "$i" "${OPT_NAME[$i]}" "${OPT_RISK[$i]}" "$tag" \
        | sed "s/\${C_DIM}/$C_DIM/g; s/\${C_RESET}/$C_RESET/g; s/\${C_YELLOW}/$C_YELLOW/g"
      shown=$((shown+1))
    fi
  done
}

ui_list_all() {
  local c
  for c in $(printf '%s\n' "${!CAT_LABEL[@]}" | sort -n); do
    ui_list_category "$c"; echo
  done
}

ui_main_menu() {
  local choice c
  while true; do
    echo
    ui_banner
    echo
    log "${C_BOLD}Categorías:${C_RESET}"
    for c in $(printf '%s\n' "${!CAT_LABEL[@]}" | sort -n); do
      local n=0 i
      for (( i=1; i<=OPT_COUNT; i++ )); do [[ "${OPT_CAT[$i]}" == "$c" ]] && n=$((n+1)); done
      printf '   %2d) %s ${C_DIM}(%d pruebas)${C_RESET}\n' "$c" "${CAT_LABEL[$c]}" "$n" \
        | sed "s/\${C_DIM}/$C_DIM/g; s/\${C_RESET}/$C_RESET/g"
    done
    echo
    log "${C_BOLD}Acciones:${C_RESET}"
    log "   d) Diagnóstico del entorno (herramientas disponibles/ausentes)"
    log "   a) Listar TODAS las opciones con su número"
    log "   n) Ejecutar una opción por número"
    log "   s) Ejecutar perfil seguro (todas las pruebas locales/INFO/LOW)"
    log "   t) Cambiar objetivo (actual: $TARGET)"
    log "   r) Exportar informes de esta sesión (MD + JSON + CSV)"
    log "   q) Salir"
    echo
    read -r -p "Elige categoría (1-15) o acción: " choice

    case "$choice" in
      q|Q) info "Saliendo. Logs en $PL_LOG_DIR, informes en $PL_REPORT_DIR."; return 0 ;;
      d|D) diagnose_env ;;
      a|A) ui_list_all ;;
      r|R) report_all ;;
      t|T) TARGET="$(prompt_target)"; ok "Objetivo = $TARGET" ;;
      s|S) run_safe_all; report_markdown ;;
      n|N)
        read -r -p "Número de opción (1-$OPT_COUNT): " num
        if is_int "$num"; then run_option "$num"; else err "Entrada no numérica."; fi
        ;;
      *)
        if is_int "$choice" && [[ -n "${CAT_LABEL[$choice]:-}" ]]; then
          ui_category_menu "$choice"
        else
          err "Opción no reconocida: '$choice'"
        fi
        ;;
    esac
  done
}

ui_category_menu() {
  local cat="$1" sub
  while true; do
    echo
    ui_list_category "$cat"
    echo
    log "   c) Ejecutar TODA la categoría    b) Volver    número) ejecutar esa prueba"
    read -r -p "Acción: " sub
    case "$sub" in
      b|B) return 0 ;;
      c|C) run_category "$cat" ;;
      *)
        if is_int "$sub" && [[ "${OPT_CAT[$sub]:-}" == "$cat" ]]; then
          run_option "$sub"
        else
          err "Número fuera de esta categoría."
        fi
        ;;
    esac
  done
}
