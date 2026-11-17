# Instalador de secure-server para WINDOWS 10/11. Lo lanza el menú (instalar.cmd) o directamente:
#   powershell -ExecutionPolicy Bypass -File instalador\windows.ps1 [-Si] [-InicioClamd auto|manual] [-SinMariaDB] [-SinClamAV] [-SinNpm]
#
# Con winget (paquetes oficiales firmados) instala lo que falte:
#   - Node.js LTS (>= 22)
#   - MariaDB (si no hay ya un servicio MariaDB/MySQL; el instalador gráfico te pide a TI la contraseña de root)
#   - ClamAV: clamd + freshclam como servicios de Windows. clamd escucha SOLO en 127.0.0.1:3310 (lo que espera el servidor
#     por defecto: CLAMAV_HOST/CLAMAV_PORT) y nunca hacia fuera.
#   - Dependencias de npm (install.js) y, si quieres, las de la interfaz web.
# Es idempotente: lo ya instalado se respeta y se puede repetir. Deja un registro en instalador\registros\.
param(
    [switch]$Si,
    [ValidateSet('auto', 'manual', 'preguntar')][string]$InicioClamd = 'preguntar',
    [switch]$SinMariaDB,
    [switch]$SinClamAV,
    [switch]$SinNpm,
    [switch]$Elevado
)
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot

# ---- Permisos de administrador (servicios, Program Files): se pide con la ventana de Windows (UAC) ----
$esAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $esAdmin) {
    Write-Host 'Hacen falta permisos de administrador (servicios y C:\Program Files). Windows te pedirá confirmación...' -ForegroundColor Yellow
    $pasar = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"", '-Elevado')
    foreach ($k in $PSBoundParameters.Keys) {
        $v = $PSBoundParameters[$k]
        if ($v -is [System.Management.Automation.SwitchParameter]) { if ($v.IsPresent) { $pasar += "-$k" } }
        else { $pasar += "-$k"; $pasar += "$v" }
    }
    try { $p = Start-Process powershell -Verb RunAs -ArgumentList $pasar -Wait -PassThru }
    catch { Write-Host 'Instalación cancelada: no se concedieron permisos de administrador.' -ForegroundColor Red; exit 1 }
    Write-Host "El instalador terminó (código $($p.ExitCode)). Registro: $Root\instalador\registros\"
    exit $p.ExitCode
}

New-Item -ItemType Directory -Force "$Root\instalador\registros" | Out-Null
$registro = "$Root\instalador\registros\windows-$(Get-Date -Format yyyyMMdd-HHmmss).log"
Start-Transcript -Path $registro | Out-Null

function Paso($t) { Write-Host ''; Write-Host "==> $t" -ForegroundColor Cyan }
function Ok($t) { Write-Host "  ✔ $t" -ForegroundColor Green }
function Aviso($t) { Write-Host "  ⚠ $t" -ForegroundColor Yellow }
function Preguntar($texto, [bool]$porDefecto) {
    if ($Si) { return $porDefecto }
    $r = Read-Host "$texto [$(if ($porDefecto) { 'S/n' } else { 's/N' })]"
    if (-not $r) { return $porDefecto }
    return ($r -match '^(s|si|sí|y|yes)$')
}
function Refrescar-Path {
    $env:Path = [Environment]::GetEnvironmentVariable('Path', 'Machine') + ';' + [Environment]::GetEnvironmentVariable('Path', 'User')
}
function Instalar-Winget([string]$id, [switch]$Interactivo) {
    $a = @('install', '--id', $id, '--exact', '--source', 'winget', '--accept-package-agreements', '--accept-source-agreements')
    if ($Interactivo) { $a += '--interactive' } else { $a += @('--silent', '--disable-interactivity') }
    & winget @a
    # -1978335189 (0x8A15002B): ya instalado / sin actualización aplicable
    if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne -1978335189) { throw "winget no pudo instalar $id (código $LASTEXITCODE)" }
    Refrescar-Path
}

$codigo = 0
try {
    Write-Host ''
    Write-Host '  ╔══════════════════════════════════════════════╗' -ForegroundColor Cyan
    Write-Host '  ║   secure-server · instalación para Windows   ║' -ForegroundColor Cyan
    Write-Host '  ╚══════════════════════════════════════════════╝' -ForegroundColor Cyan

    Paso 'Requisitos del instalador'
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        throw 'No está winget. Instala "Instalador de aplicación" (App Installer) desde Microsoft Store y repite.'
    }
    Ok "winget $(winget --version)"

    # ---------------------------------------------------------------- Node.js
    Paso 'Node.js (>= 22)'
    $nodeOk = $false
    if (Get-Command node -ErrorAction SilentlyContinue) { $nodeOk = [int]((node -v).TrimStart('v').Split('.')[0]) -ge 22 }
    if ($nodeOk) { Ok "Node $(node -v) ya instalado" }
    else {
        Instalar-Winget 'OpenJS.NodeJS.LTS'
        if (-not (Get-Command node -ErrorAction SilentlyContinue)) { throw 'Node se instaló pero no está en el PATH: abre otra terminal y repite.' }
        Ok "Node $(node -v) instalado"
    }

    # ---------------------------------------------------------------- MariaDB
    if (-not $SinMariaDB) {
        Paso 'MariaDB'
        $servicio = Get-Service -Name 'MariaDB*', 'MySQL*' -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($servicio) { Ok "Servicio $($servicio.Name) ya instalado ($($servicio.Status))" }
        else {
            Aviso 'Se abre el instalador de MariaDB: elige tú la contraseña de root (este script no la ve ni la guarda).'
            Instalar-Winget 'MariaDB.Server' -Interactivo
            Ok 'MariaDB instalado'
        }
        $mysql = Get-ChildItem 'C:\Program Files\MariaDB*\bin\mysql.exe', 'C:\Program Files\MySQL\*\bin\mysql.exe' -ErrorAction SilentlyContinue |
            Sort-Object FullName -Descending | Select-Object -First 1
        if ($mysql -and (Preguntar '¿Crear las bases y el usuario de PRUEBAS (database\setup-local.sql)? Pedirá la contraseña de root' $false)) {
            Get-Content "$Root\database\setup-local.sql" | & $mysql.FullName -uroot -p
            if ($LASTEXITCODE -eq 0) { Ok 'bases de prueba y usuario sec listos' } else { Aviso 'no se pudo ejecutar setup-local.sql (¿contraseña de root?)' }
        }
    }

    # ---------------------------------------------------------------- ClamAV
    if (-not $SinClamAV) {
        Paso 'ClamAV (antivirus de las subidas)'
        $clam = 'C:\Program Files\ClamAV'
        if (Test-Path "$clam\clamd.exe") { Ok "ClamAV ya instalado en $clam" }
        else { Instalar-Winget 'Cisco.ClamAV'; Ok 'ClamAV instalado' }
        if (-not (Test-Path "$clam\clamd.exe")) { throw "No se encuentra clamd.exe en $clam" }

        # Configuración propia (rutas sin espacios para los registros; base de firmas en la carpeta por defecto)
        $datos = 'C:\ProgramData\ClamAV'
        New-Item -ItemType Directory -Force $datos, "$clam\database" | Out-Null
        $marca = '# Generado por secure-server (instalador\windows.ps1). Se puede volver a generar ejecutando el instalador.'
        function Escribir-Conf($archivo, [string[]]$lineas) {
            if ((Test-Path $archivo) -and ((Get-Content $archivo -TotalCount 1) -ne $marca)) {
                $copia = "$archivo.bak-$(Get-Date -Format yyyyMMddHHmmss)"
                Copy-Item $archivo $copia
                Aviso "tu configuración anterior queda en $copia"
            }
            Set-Content -Path $archivo -Value (@($marca) + $lineas) -Encoding ASCII
        }
        Escribir-Conf "$clam\freshclam.conf" @(
            'DatabaseMirror database.clamav.net',
            '# Como servicio comprueba firmas nuevas 12 veces al día',
            'Checks 12',
            "UpdateLogFile $datos\freshclam.log",
            'LogTime yes',
            'LogFileMaxSize 10M'
        )
        Escribir-Conf "$clam\clamd.conf" @(
            '# Solo en local: el servidor se conecta a 127.0.0.1:3310 (CLAMAV_HOST / CLAMAV_PORT)',
            'TCPSocket 3310',
            'TCPAddr 127.0.0.1',
            '# Igual que CLAMAV_MAX_BYTES (25 MB por defecto en el servidor)',
            'StreamMaxLength 25M',
            'MaxThreads 4',
            "LogFile $datos\clamd.log",
            'LogTime yes',
            'LogFileMaxSize 10M'
        )
        Ok 'clamd.conf y freshclam.conf configurados (solo 127.0.0.1:3310)'

        Write-Host '  Descargando firmas (freshclam; la primera vez son ~300 MB y tarda unos minutos)...'
        foreach ($svc in 'FreshClam', 'ClamD') {
            if ((Get-Service $svc -ErrorAction SilentlyContinue).Status -eq 'Running') { Stop-Service $svc }
        }
        & "$clam\freshclam.exe"
        $hayFirmas = Get-ChildItem "$clam\database" -Include 'main.cvd', 'main.cld' -Recurse -ErrorAction SilentlyContinue
        if ($LASTEXITCODE -ne 0 -and -not $hayFirmas) { throw "freshclam no pudo descargar las firmas (código $LASTEXITCODE)." }
        if ($LASTEXITCODE -ne 0) { Aviso "freshclam terminó con código $LASTEXITCODE; se usan las firmas ya descargadas" } else { Ok 'firmas al día' }

        if (-not (Get-Service ClamD -ErrorAction SilentlyContinue)) { & "$clam\clamd.exe" --install-service | Out-Null }
        if (-not (Get-Service FreshClam -ErrorAction SilentlyContinue)) { & "$clam\freshclam.exe" --install-service | Out-Null }
        if (-not (Get-Service ClamD -ErrorAction SilentlyContinue)) { throw 'No se pudo registrar el servicio ClamD.' }

        $inicio = $InicioClamd
        if ($inicio -eq 'preguntar') {
            $inicio = if (Preguntar '¿Arrancar ClamAV automáticamente con Windows? (clamd usa ~1-1,5 GB de RAM con las firmas cargadas)' $true) { 'auto' } else { 'manual' }
        }
        $tipo = if ($inicio -eq 'auto') { 'Automatic' } else { 'Manual' }
        Set-Service ClamD -StartupType $tipo
        if (Get-Service FreshClam -ErrorAction SilentlyContinue) { Set-Service FreshClam -StartupType $tipo; Start-Service FreshClam }
        Start-Service ClamD
        Ok "servicios ClamD y FreshClam en marcha (inicio: $(if ($tipo -eq 'Automatic') { 'automático' } else { 'manual: Start-Service ClamD' }))"

        Write-Host '  Esperando a que clamd cargue las firmas (hasta 3 minutos)...'
        & node "$Root\instalador\verificar-clamav.js" --esperar 180
        if ($LASTEXITCODE -ne 0) { Aviso "clamd no respondió bien: revisa $datos\clamd.log"; $codigo = 1 }
    }

    # ---------------------------------------------------------------- npm
    if (-not $SinNpm) {
        Paso 'Dependencias del proyecto (npm)'
        Push-Location $Root
        try {
            & node instalador/install.js --os windows --no-tools
            if ($LASTEXITCODE -ne 0) { throw 'install.js falló' }
            if (Preguntar '¿Instalar también la interfaz web (web\)?' $true) {
                Push-Location web; & npm.cmd ci --no-audit --no-fund; $rc = $LASTEXITCODE; Pop-Location
                if ($rc -eq 0) { Ok 'dependencias de web\ instaladas' } else { Aviso 'npm ci en web\ falló' }
            }
        } finally { Pop-Location }
    }

    Paso 'Listo'
    Ok 'Instalación para Windows terminada.'
    Write-Host '  Siguiente:  revisa .env  ·  npm start  ·  pruebas: npm run test:all'
    Write-Host '  Antivirus en el servidor: FILE_SCAN=required (clamd en 127.0.0.1:3310)'
} catch {
    Write-Host ''
    Write-Host "  ✖ $($_.Exception.Message)" -ForegroundColor Red
    $codigo = 1
} finally {
    Write-Host "  Registro: $registro"
    Stop-Transcript | Out-Null
}
if ($Elevado -and -not $Si) { Read-Host 'Pulsa Enter para cerrar' | Out-Null }
exit $codigo
