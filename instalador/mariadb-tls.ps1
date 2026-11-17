# Configura TLS en MariaDB (Windows) con los certificados de `npm run db:tls`.
# Requiere administrador. Idempotente: puede ejecutarse varias veces.
#
#   powershell -ExecutionPolicy Bypass -File instalador\mariadb-tls.ps1 [-CertDir <dir>] [-MyIni <ruta>] [-Service MariaDB]
#
# No activa require_secure_transport: `npm run dev` y las pruebas se conectan sin TLS.

[CmdletBinding()]
param(
    [string]$CertDir = (Join-Path $env:ProgramData 'secure-server\db-tls'),
    [string]$MyIni   = 'C:\Program Files\MariaDB 13.1\data\my.ini',
    [string]$Service = 'MariaDB'
)

$ErrorActionPreference = 'Stop'

function Fallo($msg) { Write-Host "ERROR: $msg" -ForegroundColor Red; exit 1 }

# --- Administrador ---
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Fallo 'Este script necesita un PowerShell abierto como administrador.'
}

# --- Certificados ---
$ca   = Join-Path $CertDir 'ca.pem'
$cert = Join-Path $CertDir 'server-cert.pem'
$key  = Join-Path $CertDir 'server-key.pem'
$caKey = Join-Path $CertDir 'ca-key.pem'
foreach ($f in @($ca, $cert, $key)) {
    if (-not (Test-Path -LiteralPath $f)) { Fallo "Falta $f. Genera los certificados antes con: npm run db:tls" }
}

# --- my.ini ---
if (-not (Test-Path -LiteralPath $MyIni)) {
    $cand = Get-ChildItem -Path 'C:\Program Files\MariaDB*\data\my.ini' -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($cand) { $MyIni = $cand.FullName } else { Fallo "No se encontró my.ini (probé $MyIni y C:\Program Files\MariaDB*\data\my.ini). Indícalo con -MyIni." }
}
Write-Host "my.ini: $MyIni"

$svc = Get-Service -Name $Service -ErrorAction SilentlyContinue
if (-not $svc) { Fallo "No existe el servicio '$Service'. Indícalo con -Service." }

$backup = "$MyIni.bak-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
Copy-Item -LiteralPath $MyIni -Destination $backup
Write-Host "Copia de seguridad: $backup"

$valores = [ordered]@{
    ssl_ca   = ($ca   -replace '\\', '/')
    ssl_cert = ($cert -replace '\\', '/')
    ssl_key  = ($key  -replace '\\', '/')
}

$lineas = [System.Collections.Generic.List[string]]::new()
foreach ($l in [System.IO.File]::ReadAllLines($MyIni)) { $lineas.Add($l) }

# Localiza [mysqld]
$ini = -1
for ($i = 0; $i -lt $lineas.Count; $i++) { if ($lineas[$i].Trim() -ieq '[mysqld]') { $ini = $i; break } }
if ($ini -lt 0) { $lineas.Add(''); $lineas.Add('[mysqld]'); $ini = $lineas.Count - 1 }
$fin = $lineas.Count
for ($i = $ini + 1; $i -lt $lineas.Count; $i++) { if ($lineas[$i].Trim() -match '^\[.+\]$') { $fin = $i; break } }

# Quita ssl_ca/ssl_cert/ssl_key existentes de la sección (sin duplicar) y recuerda dónde estaba la primera
$pos = $ini + 1
$primera = $true
for ($i = $fin - 1; $i -gt $ini; $i--) {
    if ($lineas[$i] -match '^\s*(ssl[-_]ca|ssl[-_]cert|ssl[-_]key)\s*=') {
        $lineas.RemoveAt($i)
        $pos = $i
        $fin--
    }
}
$nuevas = @($valores.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" })
# Inserta justo tras [mysqld] si no había ninguna; si la había, en el hueco de la primera
$lineas.InsertRange($pos, [string[]]$nuevas)

# Sin BOM
$utf8SinBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($MyIni, (($lineas -join "`r`n") + "`r`n"), $utf8SinBom)
Write-Host 'my.ini actualizado ([mysqld]: ssl_ca, ssl_cert, ssl_key).'

# --- Permisos de las claves privadas ---
$cuentas = @('*S-1-5-18:(F)', '*S-1-5-32-544:(F)')   # SYSTEM, Administradores
if ($Service -and (& sc.exe qc $Service 2>$null | Select-String 'SERVICE_START_NAME\s*:\s*NT SERVICE\\')) {
    $cuentas += "NT SERVICE\${Service}:(R)"
}
foreach ($k in @($key, $caKey)) {
    if (-not (Test-Path -LiteralPath $k)) { continue }
    & icacls.exe $k /inheritance:r | Out-Null
    foreach ($c in $cuentas) { & icacls.exe $k /grant:r $c | Out-Null }
    Write-Host "Permisos restringidos: $k"
}

# --- Reinicio ---
function Reiniciar {
    Restart-Service -Name $Service -Force
    $svc.Refresh()
    $svc.WaitForStatus('Running', [TimeSpan]::FromSeconds(60))
}
$ok = $true
try { Reiniciar } catch { $ok = $false }
if (-not $ok -or (Get-Service -Name $Service).Status -ne 'Running') {
    Write-Host "El servicio '$Service' no arrancó con TLS. Restaurando $backup ..." -ForegroundColor Yellow
    Copy-Item -LiteralPath $backup -Destination $MyIni -Force
    try { Restart-Service -Name $Service -Force } catch { }
    Fallo 'MariaDB no arrancó con la nueva configuración; se restauró my.ini. Revisa el registro de errores (carpeta data\*.err).'
}

Write-Host "`nMariaDB '$Service' está en ejecución con TLS." -ForegroundColor Green
$bin = Join-Path (Split-Path (Split-Path $MyIni -Parent) -Parent) 'bin\mariadb.exe'
Write-Host "`nComprobación:"
Write-Host "  & `"$bin`" -u sec -p --ssl-ca=`"$ca`" --ssl-verify-server-cert -e `"SHOW STATUS LIKE 'Ssl_version'`""
Write-Host "`nEn .env:  DB_SSL=verify   DB_SSL_CA=$($ca -replace '\\', '/')"
