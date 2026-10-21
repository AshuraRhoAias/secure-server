# Instalador para Windows — delega en install.js (Node).
# Uso:  powershell -ExecutionPolicy Bypass -File .\install.ps1
#       .\install.ps1 -Yes
param([switch]$Yes, [switch]$NoTools)
$ErrorActionPreference = "Stop"
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
  Write-Host "X  Node.js no esta instalado. Instalalo (>=18) desde https://nodejs.org" -ForegroundColor Red
  exit 1
}
$argsList = @("$dir\install.js", "--os", "windows")
if ($Yes) { $argsList += "--yes" }
if ($NoTools) { $argsList += "--no-tools" }
& node $argsList
exit $LASTEXITCODE
