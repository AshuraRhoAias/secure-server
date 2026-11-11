#!/usr/bin/env bash
# macOS: doble clic en Finder abre Terminal con el menú del instalador de secure-server.
# (Si macOS lo bloquea por venir de Internet: clic derecho → Abrir, o en Terminal:  bash instalar.sh)
cd "$(dirname "$0")" || exit 1
bash ./instalar.sh
codigo=$?
echo
read -rp "Pulsa Enter para cerrar..." _
exit $codigo
