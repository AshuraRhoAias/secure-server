# Menú del instalador en Windows (lo abre instalar.cmd). Pregunta el sistema y lanza su instalador:
#   1) Windows → instalador\windows.ps1      2) Linux → instalador/linux.sh (aquí, dentro de WSL)      3) macOS → en el Mac
# Sin preguntar:  instalar.cmd -Sistema windows [-Si ...]   (el resto de opciones pasa al instalador elegido)
param([ValidateSet('', 'windows', 'linux', 'macos')][string]$Sistema = '')
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
$resto = $args

function Menu {
    Clear-Host
    Write-Host ''
    Write-Host '  ╔══════════════════════════════════════════════╗' -ForegroundColor Cyan
    Write-Host '  ║        Instalador de secure-server           ║' -ForegroundColor Cyan
    Write-Host '  ╚══════════════════════════════════════════════╝' -ForegroundColor Cyan
    Write-Host ''
    Write-Host '  ¿En qué sistema quieres instalar?'
    Write-Host ''
    Write-Host '    1) Windows   Node.js, MariaDB, ClamAV y npm con winget'
    Write-Host '    2) Linux     Debian/Ubuntu (apt), Fedora/RHEL (dnf), Arch (pacman)'
    Write-Host '    3) macOS     con Homebrew'
    Write-Host '    0) Salir'
    Write-Host ''
    Write-Host '  Sistema detectado: Windows' -ForegroundColor DarkGray
    Write-Host ''
    while ($true) {
        switch ((Read-Host '  Elige una opción [1-3]').Trim()) {
            '1' { return 'windows' }
            '2' { return 'linux' }
            '3' { return 'macos' }
            '0' { return '' }
            default { Write-Host '  Opción no válida: escribe 1, 2, 3 o 0.' -ForegroundColor Yellow }
        }
    }
}

if (-not $Sistema) { $Sistema = Menu }
switch ($Sistema) {
    '' { exit 0 }
    'windows' {
        & "$PSScriptRoot\windows.ps1" @resto
        exit $LASTEXITCODE
    }
    'linux' {
        # Desde Windows solo se puede instalar en el Linux de WSL; en un equipo Linux se usa instalar.sh
        if (Get-Command wsl -ErrorAction SilentlyContinue) {
            $r = Read-Host '  Estás en Windows. ¿Instalar dentro de tu Linux de WSL? [s/N]'
            if ($r -match '^(s|si|sí|y|yes)$') {
                & wsl --cd "$Root" -- bash ./instalador/linux.sh @resto
                exit $LASTEXITCODE
            }
        }
        Write-Host ''
        Write-Host '  Para instalar en un equipo Linux, copia el proyecto allí y ejecuta:' -ForegroundColor Yellow
        Write-Host '      bash instalar.sh        (y elige la opción 2)'
        exit 0
    }
    'macos' {
        Write-Host ''
        Write-Host '  macOS se instala desde el propio Mac. Copia el proyecto allí y:' -ForegroundColor Yellow
        Write-Host '      doble clic en instalar.command   (o en Terminal:  bash instalar.sh  → opción 3)'
        exit 0
    }
}
