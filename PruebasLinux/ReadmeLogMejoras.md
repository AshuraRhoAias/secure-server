# PruebasLinux — Entorno independiente de pruebas de seguridad y diagnóstico de redes

> **Aviso de uso responsable.** Este entorno es **defensivo** y está pensado para
> auditar **sistemas propios o para los que exista autorización expresa**, en un
> laboratorio aislado. El objetivo por defecto es `127.0.0.1`. Cualquier objetivo
> que no sea local exige confirmación explícita. Las pruebas son **no destructivas**:
> no incluyen explotación, fuerza bruta real, ni denegación de servicio.

---

## 1. Objetivo y alcance

`PruebasLinux` es un entorno **independiente** del proyecto `secure-server`. Vive en
la carpeta `PruebasLinux/` en la raíz del repositorio y **no modifica ni importa** el
código de la aplicación: sólo lo **lee** para análisis estático (esquema SQL, código
fuente, dependencias, configuración). Arrancar o usar este entorno **no afecta** a la
ejecución normal del servidor.

Ofrece un **menú interactivo en terminal** con **117 opciones reales y diferenciadas**
organizadas en **15 categorías**, que invocan herramientas defensivas estándar
(`nmap`, `sslscan`, `nikto`, `whatweb`, `openssl`, `dig`, `bandit`, `detect-secrets`,
`pip-audit`, `shellcheck`, `yamllint`, `npm audit`, etc.) y comprobaciones propias
basadas en utilidades del sistema.

Capacidades principales:

- Diagnóstico previo del entorno (herramientas disponibles, ausentes o incompatibles).
- Ejecución **individual**, **por categoría** o **perfil general seguro**.
- Comprobación de **dependencias antes** de cada módulo, con sugerencia de instalación.
- **Control de errores**, **validación de entradas** y **cancelación limpia** (Ctrl-C).
- **Logging** con fecha/hora, herramienta y resultado.
- **Exportación** de informes en **Markdown**, **JSON** y **CSV**.
- **Modular y ampliable**: añadir una prueba no requiere tocar el código del proyecto
  ni el lanzador; basta con registrar una opción en un módulo (ver §8).

---

## 2. Arquitectura y estructura de directorios

```
PruebasLinux/
├── pruebas.sh              # Lanzador principal (menú + modo no interactivo)
├── lib/
│   ├── core.sh             # Núcleo: rutas, logging, registro de opciones,
│   │                       # dependencias, validación, ejecución y resultados
│   ├── ui.sh               # Menú interactivo y navegación
│   └── report.sh           # Exportación a Markdown / JSON / CSV
├── modules/                # Una categoría por archivo; cada opción se registra con reg()
│   ├── 01_recon.sh         # Cat. 1  — Reconocimiento de red
│   ├── 02_ports.sh         # Cat. 2  — Puertos y protocolos
│   ├── 03_dns_http_tls.sh  # Cat. 3  — DNS, HTTP, HTTPS, TLS
│   ├── 04_vuln.sh          # Cat. 4  — Vulnerabilidades conocidas
│   ├── 05_server_config.sh # Cat. 5  — Configuración de servidores
│   ├── 06_linux_perms.sh   # Cat. 6  — Permisos y seguridad del sistema
│   ├── 07_deps.sh          # Cat. 7  — Dependencias y paquetes
│   ├── 08_sast.sh          # Cat. 8  — Análisis estático/dinámico de código
│   ├── 09_webapi.sh        # Cat. 9  — Aplicaciones web y API
│   ├── 10_database.sh      # Cat. 10 — Bases de datos
│   ├── 11_docker.sh        # Cat. 11 — Contenedores Docker
│   ├── 12_secrets.sh       # Cat. 12 — Secretos y configuraciones inseguras
│   ├── 13_authz.sh         # Cat. 13 — Autenticación, sesiones y autorización
│   ├── 14_logging.sh       # Cat. 14 — Registros, trazabilidad y monitorización
│   └── 15_reporting.sh     # Cat. 15 — Informes y recomendaciones
├── logs/                   # Logs de cada sesión (run_<fecha>.log). No se versionan.
└── reports/                # Informes exportados (MD/JSON/CSV). No se versionan.
```

### Cómo funciona por dentro

- `core.sh` mantiene un **registro** de opciones en arrays paralelos. Cada módulo
  llama a `reg <categoría> "<nombre>" "<descripción>" "<requisitos>" "<riesgo>" <función>`.
  El numerado (1..117) es automático según el orden de carga de los módulos.
- `run_option N` comprueba las dependencias de la opción; si falta alguna, la **omite**
  y muestra cómo instalarla (nunca simula un resultado). Si están, ejecuta la función,
  mide el tiempo, captura el código de salida real y lo registra para el informe.
- La salida de cada herramienta se muestra en pantalla **y** se anexa al log de la sesión.

---

## 3. Niveles de riesgo

Cada opción se etiqueta para que el operador sepa qué hace antes de ejecutarla:

| Nivel    | Significado |
|----------|-------------|
| `INFO`   | Sólo lectura/inventario; sin impacto. |
| `LOCAL`  | Análisis local del repo o del sistema (estático o de sólo lectura). |
| `LOW`    | Actividad de red ligera (p. ej. una conexión, cabeceras HTTP) o sondas locales acotadas. |
| `MEDIUM` | Escaneo activo de red contra el objetivo (nmap, nikto, sslscan). Requiere objetivo autorizado. |

No hay opciones destructivas ni de nivel alto: el entorno evita por diseño la
explotación y las pruebas que puedan causar daño.

---

## 4. Requisitos, instalación y dependencias

**Requisitos base:** Linux, Bash ≥ 4, utilidades estándar (coreutils, `find`, `grep`,
`git`, `curl`, `openssl`, `python3`).

Cada prueba declara sus herramientas. El entorno **no obliga** a tenerlas todas: las
opciones cuya dependencia falte se marcan como *omitidas* con la orden de instalación.

Instalación recomendada del toolset defensivo (Debian/Ubuntu):

```bash
sudo apt-get update
sudo apt-get install -y nmap sslscan nikto whatweb net-tools tcpdump \
    shellcheck sqlite3 dnsutils iputils-ping traceroute mtr-tiny whois
pip3 install pip-audit detect-secrets yamllint wafw00f bandit
# Opcionales (binarios externos):
pip3 install semgrep
# gitleaks: https://github.com/gitleaks/gitleaks/releases
# trivy:    https://aquasecurity.github.io/trivy
# hadolint: https://github.com/hadolint/hadolint/releases
```

> **Estado verificado en este laboratorio (2026-10-21):** se instalaron y verificaron
> 33 herramientas: nmap, sslscan, nikto, whatweb, tcpdump, shellcheck, sqlite3, dig,
> host, ping, traceroute, mtr, ss, netstat, whois, openssl, curl, wget, node, npm, go,
> docker, bandit, pip-audit, detect-secrets, yamllint, wafw00f, jq, python3, git,
> **semgrep, gitleaks y hadolint**. Quedó **ausente** sólo `trivy` (el binario de la
> versión fijada devolvió 404 al descargarse en este entorno); las 2 opciones que lo
> usan (88 y 89) se omiten con la orden de instalación hasta que esté disponible.
> Ejecuta `./pruebas.sh --diagnose` para ver el estado real en tu máquina.

---

## 5. Comandos para iniciar el menú

```bash
cd PruebasLinux

# Menú interactivo
./pruebas.sh

# Diagnóstico del entorno (qué herramientas hay)
./pruebas.sh --diagnose

# Listar las 117 opciones con su número
./pruebas.sh --list

# Ejecutar una o varias pruebas por número
./pruebas.sh --run 65 79 100

# Ejecutar una categoría completa (1-15)
./pruebas.sh --category 8

# Perfil seguro: todas las pruebas locales/INFO/LOW
./pruebas.sh --safe-all

# Exportar informes (MD + JSON + CSV)
./pruebas.sh --report
```

Opciones útiles: `--target HOST`, `--url URL`, `--yes` (asume sí en confirmaciones de
objetivo externo), `--no-color`, `-h`/`--help`.

Variables de entorno que afinan algunas pruebas: `PL_TARGET`, `PL_BASE_URL`,
`PL_PORT`, `PL_PORT_RANGE`, `PL_IMAGE` (imagen Docker para trivy), `PL_DB_HOST`,
`PL_DB_PORT`.

### Navegación del menú

- Elige una **categoría (1-15)** para ver sus pruebas, o una **acción**:
  `d` diagnóstico, `a` listar todo, `n` ejecutar por número, `s` perfil seguro,
  `t` cambiar objetivo, `r` exportar informes, `q` salir.
- Dentro de una categoría: un **número** ejecuta esa prueba, `c` ejecuta toda la
  categoría, `b` vuelve. El menú valida la entrada y nunca cierra la terminal por un
  dato inválido.

---

## 6. Ejemplos de ejecución y resultados esperados

**Diagnóstico:**
```
$ ./pruebas.sh --diagnose
✔  nmap             /usr/bin/nmap
...
ℹ  Herramientas disponibles: 30   ausentes: 4
ℹ  Opciones registradas: 117 en 15 categorías
```

**Análisis estático del código (categoría 8):**
```
$ ./pruebas.sh --category 8
[65] Sintaxis JS (node --check)   (riesgo: LOCAL)
  [OK] Todos los .js pasan 'node --check'.
✔  Prueba [65] finalizada (rc=0) en 2s
...
```

**Permisos del repo (categoría 6):** en este laboratorio detecta, p. ej., que `.env`
tiene permisos `644` (recomendado `600`) y que está versionado en git.

Cada ejecución deja un **log** en `logs/run_<fecha>.log` y, al exportar, un informe en
`reports/reporte_<fecha>.{md,json,csv}`.

---

## 7. Ubicación de logs, informes y temporales

- **Logs de sesión:** `PruebasLinux/logs/run_<AAAAMMDDTHHMMSSZ>.log`
- **Informes:** `PruebasLinux/reports/reporte_<AAAAMMDDTHHMMSSZ>.{md,json,csv}`
- **Temporales:** archivos `/tmp/pl_*` creados y borrados por cada prueba.

Las carpetas `logs/` y `reports/` están en `.gitignore` (sólo se versiona un
`.gitkeep`), para no subir resultados ni datos de ejecución.

---

## 8. Procedimiento para añadir herramientas y módulos

Sin tocar el lanzador ni el código del proyecto:

1. Crea o edita un archivo en `modules/` (p. ej. `modules/16_mio.sh`).
2. Define una función que haga la prueba y devuelva `0` si todo correcto o `≠0` si hay
   hallazgos/errores. Usa `say`/`good`/`flag`/`note` para la salida.
3. Regístrala:
   ```bash
   reg <categoría> "Nombre" "Descripción" "cmd1,cmd2" "RIESGO" mi_funcion
   ```
   (Si usas una categoría nueva, añade su etiqueta a `CAT_LABEL` en `lib/core.sh`.)
4. El lanzador la auto-descubre al arrancar y le asigna su número.

---

## 9. Medidas de seguridad, limitaciones y precauciones

- **Autorización:** las pruebas de red contra objetivos no locales piden confirmación.
  Úsalas sólo sobre sistemas propios o autorizados.
- **No destructivo:** no hay explotación, fuerza bruta real ni DoS. La prueba de rate
  limiting hace un número pequeño y acotado de peticiones de login.
- **Honestidad de resultados:** una herramienta ausente se **omite** (no se finge). Un
  `rc≠0` se refleja como "CON HALLAZGOS/ERROR". Los estados del informe provienen del
  código de salida real.
- **Limitaciones del entorno de contenedor:** algunas pruebas dependen del entorno:
  - La detección de SO/UDP de `nmap` puede requerir privilegios y host alcanzable.
  - `journalctl` puede no estar disponible dentro de un contenedor.
  - Las pruebas web/API (categoría 9) requieren el servidor del proyecto en marcha
    (`npm start`); si no, la prueba lo indica en vez de fallar en silencio.
  - `trivy`, `gitleaks`, `hadolint` y `semgrep` son opcionales; sin ellas, sus
    opciones se omiten con la orden de instalación.

---

## 10. Listado completo de las 117 opciones

Número · nombre · finalidad · requisitos · nivel de riesgo.
<!-- GENERADO desde el registro real del lanzador (./pruebas.sh --list). -->

### Categoría 1 — Reconocimiento de red y descubrimiento de servicios

| # | Nombre | Finalidad | Requisitos | Riesgo |
|---|--------|-----------|-----------|--------|
| 1 | Ping al objetivo | Comprueba si el host responde a ICMP (3 paquetes). | ping | LOW |
| 2 | Descubrimiento de hosts (nmap -sn) | Ping scan sin escaneo de puertos. | nmap | LOW |
| 3 | Escaneo rápido de puertos (nmap -F) | Top-100 puertos TCP más comunes. | nmap | MEDIUM |
| 4 | Escaneo top-1000 (nmap) | Los 1000 puertos TCP más frecuentes. | nmap | MEDIUM |
| 5 | Traceroute | Ruta de red hasta el objetivo (máx 15 saltos). | traceroute | LOW |
| 6 | MTR (traceroute + pérdidas) | Informe de latencia y pérdida por salto. | mtr | LOW |
| 7 | Resolución de nombre | Resolución directa del host/IP del objetivo. | getent | INFO |
| 8 | WHOIS del objetivo | Información de registro del dominio/IP. | whois | LOW |
| 9 | Vecinos de red (ARP) | Tabla ARP/neighbors local. | ip | INFO |
| 10 | Servicios locales a la escucha | Puertos abiertos locales y su proceso (ss/netstat). | ss | INFO |

### Categoría 2 — Análisis de puertos y protocolos

| # | Nombre | Finalidad | Requisitos | Riesgo |
|---|--------|-----------|-----------|--------|
| 11 | Detección de servicios/versión (nmap -sV) | Identifica servicios y versiones en puertos abiertos. | nmap | MEDIUM |
| 12 | Detección de SO (nmap -O) | Huella del sistema operativo (requiere root). | nmap | MEDIUM |
| 13 | Top-20 puertos (nmap) | Escaneo rápido de los 20 puertos más usados. | nmap | MEDIUM |
| 14 | Escaneo UDP top-20 (nmap) | Puertos UDP comunes (requiere root). | nmap | MEDIUM |
| 15 | Rango de puertos personalizado | Escanea PL_PORT_RANGE (por defecto 1-1024). | nmap | MEDIUM |
| 16 | Banner grabbing (nmap) | Captura banners de servicios (top-50). | nmap | MEDIUM |
| 17 | Scripts seguros por defecto (nmap -sC) | NSE 'default' sobre top-100. | nmap | MEDIUM |
| 18 | Comprobar un puerto TCP (bash) | Prueba PL_PORT (def. 3000) con /dev/tcp. | (builtin) | LOW |
| 19 | Puertos TCP locales en escucha | Lista puertos TCP locales y proceso. | ss | INFO |

### Categoría 3 — Auditoría de DNS, HTTP, HTTPS y TLS

| # | Nombre | Finalidad | Requisitos | Riesgo |
|---|--------|-----------|-----------|--------|
| 20 | DNS: registros A | Resolución de direcciones A del objetivo. | dig | INFO |
| 21 | DNS: registros MX | Servidores de correo del dominio. | dig | INFO |
| 22 | DNS: registros TXT | SPF/DKIM/DMARC y otros TXT. | dig | INFO |
| 23 | DNS: registros NS | Servidores de nombres autoritativos. | dig | INFO |
| 24 | DNS: traza de resolución | dig +trace (delegación completa). | dig | LOW |
| 25 | DNSSEC: comprobar RRSIG | Verifica firmas DNSSEC. | dig | INFO |
| 26 | Transferencia de zona (AXFR) | Comprueba que AXFR esté correctamente denegada. | dig | LOW |
| 27 | HTTP: cabeceras de respuesta | Cabeceras HTTP del servidor (curl -I). | curl | LOW |
| 28 | HTTP: cabeceras de seguridad | HSTS, CSP, X-Frame-Options, etc. | curl | LOW |
| 29 | HTTP: métodos permitidos | Métodos anunciados vía OPTIONS. | curl | LOW |
| 30 | TLS: datos del certificado | Subject/Issuer/validez del certificado. | openssl | LOW |
| 31 | TLS: caducidad del certificado | Fecha de expiración del certificado. | openssl | LOW |
| 32 | TLS: auditoría con sslscan | Protocolos y cifrados soportados. | sslscan | MEDIUM |
| 33 | TLS: versiones aceptadas | Comprueba TLS 1.0–1.3 (marca obsoletos). | openssl | LOW |
| 34 | TLS: cifrados débiles (nmap) | ssl-enum-ciphers sobre el puerto 443. | nmap | MEDIUM |
| 35 | HTTP: cadena de redirecciones | Sigue redirecciones y muestra Location. | curl | LOW |

### Categoría 4 — Detección y evaluación de vulnerabilidades conocidas

| # | Nombre | Finalidad | Requisitos | Riesgo |
|---|--------|-----------|-----------|--------|
| 36 | Scripts de vulnerabilidad (nmap vuln+safe) | NSE 'vuln' no intrusivos sobre top-100. | nmap | MEDIUM |
| 37 | Escaneo web con Nikto | Comprobaciones conocidas del servidor web (máx 120s). | nikto | MEDIUM |
| 38 | Enumeración HTTP (http-enum) | Descubre rutas/paneles conocidos. | nmap | MEDIUM |
| 39 | Comprobar Heartbleed | Detecta CVE-2014-0160 en TLS (no explota). | nmap | MEDIUM |
| 40 | Vulnerabilidades HTTP (http-vuln) | Scripts http-vuln* seguros de nmap. | nmap | MEDIUM |

### Categoría 5 — Auditoría de configuraciones de servidores

| # | Nombre | Finalidad | Requisitos | Riesgo |
|---|--------|-----------|-----------|--------|
| 41 | Fingerprint web (whatweb) | Tecnologías del servidor y la app. | whatweb | LOW |
| 42 | Divulgación Server/X-Powered-By | Detecta cabeceras que revelan software. | curl | LOW |
| 43 | Listado de directorios | Busca 'Index of' en rutas comunes. | curl | LOW |
| 44 | Archivos sensibles expuestos | Prueba .env, .git, package.json, etc. vía HTTP. | curl | LOW |
| 45 | Fuga en páginas de error | Comprueba si el 404/500 revela trazas. | curl | LOW |
| 46 | Método TRACE (XST) | Detecta TRACE habilitado. | curl | LOW |
| 47 | Flags de cookies | Secure/HttpOnly/SameSite en Set-Cookie. | curl | LOW |

### Categoría 6 — Análisis de permisos y seguridad del sistema Linux

| # | Nombre | Finalidad | Requisitos | Riesgo |
|---|--------|-----------|-----------|--------|
| 48 | World-writable en el repo | Archivos escribibles por cualquiera dentro del repo. | (builtin) | LOCAL |
| 49 | Binarios SUID del sistema | Lista binarios con bit SUID. | find | LOCAL |
| 50 | Binarios SGID del sistema | Lista binarios con bit SGID. | find | LOCAL |
| 51 | Permisos de .env | Verifica que .env tenga permisos restrictivos. | stat | LOCAL |
| 52 | Archivos con permisos 777 | Busca 777 en el repo. | find | LOCAL |
| 53 | Secretos/dotfiles en git | Comprueba que .env/.ssh no estén versionados. | git | LOCAL |
| 54 | Comprobar umask | umask actual del entorno. | (builtin) | INFO |
| 55 | PATH escribible | Directorios de PATH escribibles por grupo/otros. | (builtin) | LOCAL |
| 56 | Endurecimiento de SSHD | Revisa sshd_config (root login, passwords). | (builtin) | LOCAL |
| 57 | Versión de SO y kernel | Muestra SO/kernel para contraste con CVEs/EOL. | (builtin) | INFO |

### Categoría 7 — Revisión de dependencias, paquetes y librerías

| # | Nombre | Finalidad | Requisitos | Riesgo |
|---|--------|-----------|-----------|--------|
| 58 | npm audit (producción) | Vulnerabilidades conocidas en dependencias. | npm | LOCAL |
| 59 | npm audit (resumen JSON) | Conteo por severidad (jq). | npm | LOCAL |
| 60 | npm outdated | Dependencias desactualizadas. | npm | LOCAL |
| 61 | Listar dependencias de prod | Versiones declaradas en package.json. | jq | INFO |
| 62 | pip-audit (si hay Python) | Vulnerabilidades en requirements*.txt. | pip-audit | LOCAL |
| 63 | Integridad del lockfile | Comprueba package-lock.json. | (builtin) | LOCAL |
| 64 | Licencias | Licencia del proyecto y guía de auditoría. | jq | INFO |

### Categoría 8 — Análisis estático y dinámico de código

| # | Nombre | Finalidad | Requisitos | Riesgo |
|---|--------|-----------|-----------|--------|
| 65 | Sintaxis JS (node --check) | Valida la sintaxis de todos los .js. | (builtin) | LOCAL |
| 66 | ESLint (errores de parseo) | Análisis estático básico de src/. | eslint | LOCAL |
| 67 | Bandit (Python) | SAST para archivos .py (si los hay). | bandit | LOCAL |
| 68 | ShellCheck (.sh) | Analiza scripts shell del repo. | shellcheck | LOCAL |
| 69 | Patrones peligrosos | Busca eval/exec/child_process en src/. | grep | LOCAL |
| 70 | Restos de depuración | console.log, NODE_ENV=development, debug=true. | grep | LOCAL |
| 71 | YAML lint | Valida archivos YAML del repo. | yamllint | LOCAL |

### Categoría 9 — Pruebas de aplicaciones web y API

| # | Nombre | Finalidad | Requisitos | Riesgo |
|---|--------|-----------|-----------|--------|
| 72 | Endpoint /health | Comprueba disponibilidad del servidor. | curl | LOW |
| 73 | Acceso no autenticado | /api/notes sin token debe dar 401/403. | curl | LOW |
| 74 | Rate limiting en login | 12 intentos: espera ver 429. | curl | LOW |
| 75 | Validación de entrada | JSON malformado debe dar 400. | curl | LOW |
| 76 | Política CORS | Origen malicioso no debe reflejarse. | curl | LOW |
| 77 | Cabeceras de seguridad API | Cabeceras extra en respuestas de API. | curl | LOW |
| 78 | Fuga de errores en API | El error de ID inválido no debe filtrar traza. | curl | LOW |

### Categoría 10 — Auditoría de bases de datos

| # | Nombre | Finalidad | Requisitos | Riesgo |
|---|--------|-----------|-----------|--------|
| 79 | Columnas sensibles en esquema | ¿Las columnas sensibles están cifradas/hasheadas? | grep | LOCAL |
| 80 | Cifrado en migraciones | Las migraciones referencian cifrado. | grep | LOCAL |
| 81 | Riesgo de inyección SQL | Concatenación/interpolación en consultas. | grep | LOCAL |
| 82 | Credenciales de BD embebidas | Busca credenciales en el código. | grep | LOCAL |
| 83 | Conexión a MySQL (opcional) | Prueba de alcance al puerto de BD. | (builtin) | LOW |
| 84 | Proporción parametrizada | Ratio de consultas con marcadores '?'. | grep | INFO |

### Categoría 11 — Análisis de contenedores Docker y sus imágenes

| # | Nombre | Finalidad | Requisitos | Riesgo |
|---|--------|-----------|-----------|--------|
| 85 | Presencia de Dockerfile | Detecta Dockerfiles en el repo. | find | LOCAL |
| 86 | Lint de Dockerfile | Buenas prácticas: USER, tags, secretos, ADD. | find | LOCAL |
| 87 | Imágenes Docker locales | Lista imágenes (si hay daemon). | docker | LOW |
| 88 | trivy fs (repo) | Escaneo de vulnerabilidades del árbol de archivos. | trivy | LOCAL |
| 89 | trivy image (PL_IMAGE) | Escaneo de una imagen concreta. | trivy | LOW |
| 90 | Comprobar .dockerignore | Que excluya .env/node_modules. | (builtin) | LOCAL |
| 91 | Revisar docker-compose | Busca privileged/host/socket montado. | find | LOCAL |

### Categoría 12 — Detección de secretos expuestos y configuraciones inseguras

| # | Nombre | Finalidad | Requisitos | Riesgo |
|---|--------|-----------|-----------|--------|
| 92 | detect-secrets (escaneo) | Motor de detección de secretos de Yelp. | detect-secrets | LOCAL |
| 93 | gitleaks (si está) | Escaneo de secretos en el repo/historial. | gitleaks | LOCAL |
| 94 | Patrones de clave/token | git grep de AWS/GCP/GitHub/PEM/Slack. | git | LOCAL |
| 95 | .env fuera de git | Confirma que .env no esté versionado. | git | LOCAL |
| 96 | Secretos en el historial | Revisa los últimos 50 commits. | git | LOCAL |
| 97 | Claves privadas en el repo | Busca .pem/.key/id_rsa. | find | LOCAL |
| 98 | Heurística de entropía | Cadenas de alta entropía (posibles secretos). | python3 | LOCAL |

### Categoría 13 — Pruebas de autenticación, sesiones y autorización

| # | Nombre | Finalidad | Requisitos | Riesgo |
|---|--------|-----------|-----------|--------|
| 99 | Configuración JWT | Expiración y fijación de algoritmo. | grep | LOCAL |
| 100 | Hashing de contraseñas | bcrypt/argon2/scrypt en el código. | grep | LOCAL |
| 101 | Auditoría de sesiones/cookies | Flags de cookies y gestión de sesión. | grep | LOCAL |
| 102 | Protección fuerza bruta | Rate limiting / bloqueo de cuentas. | grep | LOCAL |
| 103 | Autorización por rol | Middleware requireRole/authorize. | grep | LOCAL |
| 104 | Soporte 2FA/TOTP | Detecta speakeasy/qrcode. | grep | INFO |
| 105 | Sonda autorización (admin) | Endpoint admin sin token debe dar 401/403. | curl | LOW |

### Categoría 14 — Evaluación de registros, trazabilidad y monitorización

| # | Nombre | Finalidad | Requisitos | Riesgo |
|---|--------|-----------|-----------|--------|
| 106 | Sistema de auditoría | Presencia de logging/auditoría. | grep | LOCAL |
| 107 | Logs cifrados | El servicio de auditoría cifra los registros. | grep | LOCAL |
| 108 | Permisos de logs | Permisos de las carpetas de logs. | stat | LOCAL |
| 109 | Fuga de datos en logs | console.log de password/token/secret. | grep | LOCAL |
| 110 | Monitorización de integridad | Config de integridad/fingerprint. | grep | LOCAL |
| 111 | Fallos de auth del sistema | journalctl: avisos recientes (si disponible). | (builtin) | LOCAL |

### Categoría 15 — Generación de informes técnicos y recomendaciones

| # | Nombre | Finalidad | Requisitos | Riesgo |
|---|--------|-----------|-----------|--------|
| 112 | Informe del entorno | Diagnóstico de herramientas disponibles/ausentes. | (builtin) | INFO |
| 113 | Exportar a Markdown | Guarda los resultados de la sesión en .md. | (builtin) | INFO |
| 114 | Exportar a JSON | Guarda los resultados de la sesión en .json. | (builtin) | INFO |
| 115 | Exportar a CSV | Guarda los resultados de la sesión en .csv. | (builtin) | INFO |
| 116 | Ejecutar perfil seguro | Corre todas las pruebas locales/INFO/LOW. | (builtin) | LOCAL |
| 117 | Scorecard de la sesión | Resumen OK/hallazgos/omitidas e índice. | (builtin) | INFO |

---

## 11. Problemas detectados, soluciones aplicadas y mejoras futuras

Durante el desarrollo y las pruebas de este entorno:

- **Falso positivo "PATH escribible" como root:** la comprobación inicial usaba el test
  efectivo `-w`, verdadero para root en todo. **Solución:** se cambió a inspeccionar los
  bits de permiso de grupo/otros. *(Aplicado.)*
- **Ruido en la heurística de entropía:** `package-lock.json` y los hashes de integridad
  disparaban muchos falsos positivos. **Solución:** se excluyen lockfiles y líneas con
  `integrity`/`sha512-`. *(Aplicado.)*
- **detect-secrets no reflejaba hallazgos en el código de salida.** **Solución:** ahora
  devuelve `rc=1` cuando hay hallazgos. *(Aplicado.)*

Mejoras futuras propuestas: baseline de `detect-secrets` (`.secrets.baseline`) para
marcar falsos positivos; integración opcional de `semgrep` con reglas para Node/Express;
perfil de escaneo autenticado de la API (con token de prueba); empaquetado del toolset
en una imagen de contenedor reproducible.

Ver la bitácora de auditoría del proyecto completo en
[`../ReadmeLogsMejoras.md`](../ReadmeLogsMejoras.md).
