@echo off
rem Instalador de secure-server (Windows). Doble clic: abre una terminal con el menu
rem (1 Windows, 2 Linux, 3 macOS) e instala los requisitos del sistema elegido.
rem Sin preguntar:  instalar.cmd -Sistema windows -Si
setlocal
title Instalador de secure-server
chcp 65001 >nul
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0instalador\menu.ps1" %*
set "codigo=%errorlevel%"
echo.
pause
exit /b %codigo%
