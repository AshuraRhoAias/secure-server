# Instalación de secure-server (Windows, Linux y macOS)

Un **programa base** abre una terminal con un **menú** que pregunta el sistema (**1 Windows · 2 Linux · 3 macOS**) e instala
los requisitos de ese sistema: **Node.js ≥ 22, MariaDB, ClamAV** (antivirus de las subidas) y las **dependencias de npm**.
No hace falta tener nada instalado antes (tampoco Node).

## Cómo empezar

| Sistema | Programa base | Qué abre |
|---|---|---|
| **Windows 10/11** | doble clic en **`instalar.cmd`** | terminal con el menú → `instalador\windows.ps1` (pide permisos de administrador) |
| **Linux** | `bash instalar.sh` | terminal con el menú → `instalador/linux.sh` (pide `sudo` solo para paquetes y servicios) |
| **macOS** | doble clic en **`instalar.command`** (o `bash instalar.sh`) | Terminal con el menú → `instalador/macos.sh` |

Cada instalador se ejecuta **en su propio sistema**: elegir Linux desde Windows ofrece instalar dentro de **WSL**; elegir macOS
desde otro sistema indica cómo hacerlo en el Mac. Sin preguntar: `instalar.cmd -Sistema windows -Si` o
`bash instalar.sh --sistema linux --si`.

## Qué instala cada uno

| | Windows (`winget`) | Linux (`apt` / `dnf` / `pacman`) | macOS (Homebrew) |
|---|---|---|---|
| Node.js ≥ 22 | `OpenJS.NodeJS.LTS` | NodeSource 22 (apt, con su clave) · `nodejs` (dnf/pacman) | `node@22` |
| MariaDB | `MariaDB.Server` (instalador gráfico: **tú** eliges la contraseña de root) | `mariadb-server` + servicio | `mariadb` + `brew services` |
| ClamAV | `Cisco.ClamAV`; servicios **ClamD** y **FreshClam** | `clamav-daemon` / `clamd@scan` / `clamav-daemon` + freshclam (systemd) | `clamav`; agentes de launchd `com.secure-server.clamd` y `.freshclam` |
| npm | `install.js` (+ `web/` si quieres) | igual | igual |

Lo ya instalado se respeta (se puede repetir sin romper nada). Cada ejecución deja un registro en `instalador/registros/`.
Opcionalmente crea las **bases y el usuario de pruebas** con `database/setup-local.sql` (pregunta antes; la contraseña de root
la escribes tú en el cliente de MariaDB, el instalador no la ve).

## ClamAV: configuración por sistema

El servidor habla con `clamd` por el protocolo INSTREAM (`src/files/av-scanner.js`); por defecto en **`127.0.0.1:3310`**
(`CLAMAV_HOST` / `CLAMAV_PORT`) o por socket Unix (`CLAMAV_SOCKET`). Los tres instaladores dejan clamd **escuchando solo en
local**, nunca hacia fuera, y con `StreamMaxLength 25M` (= `CLAMAV_MAX_BYTES`).

| | Configuración | Firmas | Registro |
|---|---|---|---|
| Windows | `C:\Program Files\ClamAV\clamd.conf` y `freshclam.conf` (generados; el anterior se guarda en `.bak-*`) | `C:\Program Files\ClamAV\database` | `C:\ProgramData\ClamAV\clamd.log` |
| Debian/Ubuntu | `/etc/clamav/clamd.conf` + `ListenStream=127.0.0.1:3310` en `clamav-daemon.socket.d/` | `/var/lib/clamav` | `journalctl -u clamav-daemon` |
| Fedora/RHEL | `/etc/clamd.d/scan.conf` (socket `/run/clamd.scan/clamd.sock`) | `/var/lib/clamav` | `journalctl -u clamd@scan` |
| Arch | `/etc/clamav/clamd.conf` (socket `/run/clamav/clamd.ctl`) | `/var/lib/clamav` | `journalctl -u clamav-daemon` |
| macOS | `$(brew --prefix)/etc/clamav/clamd.conf` | `$(brew --prefix)/var/lib/clamav` | `$(brew --prefix)/var/log/clamav/` |

- **Memoria**: clamd ocupa **~1-1,5 GB** con las firmas cargadas. En Windows el instalador pregunta si arranca con el sistema
  (`-InicioClamd auto|manual`); en manual: `Start-Service ClamD`.
- **Comprobar**: `node instalador/verificar-clamav.js` (PING, versión y detección del archivo de prueba EICAR, por el mismo
  camino que el servidor).
- **Activarlo en el servidor**: `FILE_SCAN=required` (rechaza la subida si clamd no responde) u `optional`. Ver
  `docs/SEGURIDAD.md` (antivirus) y `scripts/rescanFiles.js` para volver a revisar lo ya guardado con firmas nuevas.
- Las pruebas `test_av.js` con **clamd real** arrancan su propio clamd con firmas mínimas (no usan el servicio): en Linux/macOS
  por socket Unix, en Windows por TCP en `127.0.0.1` y un puerto libre.

## Opciones de los instaladores

| Windows (`instalador\windows.ps1`) | Linux / macOS (`instalador/*.sh`) | Efecto |
|---|---|---|
| `-Si` | `--si` | no pregunta: usa las respuestas por defecto |
| `-SinMariaDB` · `-SinClamAV` · `-SinNpm` | `--sin-mariadb` · `--sin-clamav` · `--sin-npm` | omite ese bloque |
| `-InicioClamd auto\|manual` | — | arranque del servicio ClamD |

`node install.js [--os windows|linux|macos] [--yes] [--no-tools] [--production]` es solo el paso de npm/.env (lo llaman los
tres instaladores). `install.sh` e `install.ps1` se mantienen por compatibilidad y llevan al instalador nuevo.

## Después de instalar

1. Revisa `.env` (credenciales y semillas reales; nunca subas credenciales al repositorio).
2. Esquema de la base de datos: `mysql -u <usuario> -p <base> < database/schema.sql`.
3. Arranca: `npm start` · pruebas: `npm run test:all`.
4. Pruebas de seguridad (laboratorio): `cd PruebasLinux && ./pruebas.sh` (en Windows, WSL o Git Bash).
