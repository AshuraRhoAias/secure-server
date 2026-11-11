# Compatibilidad: el instalador de Windows ahora es instalar.cmd (menú) o instalador\windows.ps1
# Uso:  powershell -ExecutionPolicy Bypass -File .\install.ps1 [-Si] [-InicioClamd auto|manual] ...
& "$PSScriptRoot\instalador\windows.ps1" @args
exit $LASTEXITCODE
