# ReadmeLogsMejoras.md — Bitácora de auditoría de `secure-server`

> Documento maestro de auditoría, cambios, verificaciones y tareas pendientes del
> proyecto. Se ha elaborado **con evidencia real**: ejecución de los tests del
> repositorio, análisis estático con el entorno [`PruebasLinux/`](../PruebasLinux/ReadmeLogMejoras.md)
> y revisión manual del código. Donde algo **no** ha podido verificarse (por falta de
> base de datos, servidor en marcha o conectividad en el laboratorio), se indica
> explícitamente y **no** se declara como completado.

- **Fecha de la auditoría inicial:** 2026-10-21 (UTC) · **última actualización:** 2026-11-17 (ver §A, §L, §M, §N, §O y §P)
- **Commit base auditado:** `b7b1ea1` (rama por defecto `main`)
- **Rama de trabajo de esta intervención:** `claude/project-thread-qjkfd0`
- **Entorno de ejecución:** contenedor Ubuntu 24.04, Node 22, sin MySQL ni el servidor
  arrancado (laboratorio aislado). Herramientas defensivas instaladas: 33 (ver §A).

---

## A. Resumen ejecutivo

- **Última actualización:** 2026-11-10 (7.ª intervención, «cierre»: CI de todas las fases en verde). Punto de recuperación: tag `pre-cierre-2026-11` (= `b36a9a1`, el `main` tras el PR #8).
- **Trabajo de esta intervención:** ramas apiladas `cierre/0-base` → `cierre/1-seguridad` → `cierre/2-deps` → `cierre/3-web` → `cierre/4-escala`
  → `cierre/5-pruebaslinux` → `cierre/6-docs` (una por fase, para revisarlas por separado). Entradas #21–#29.
- **Entorno de verificación:** Windows 11 + Node 26 en local **sin MariaDB** (decisión del propietario: lo que necesita BD se verifica en
  GitHub Actions con MariaDB 10.11 real). **Todas las fases están verificadas en CI** (jobs `test`, `web` con e2e en Chromium,
  Firefox y WebKit + axe, `compose` con 2 réplicas + nginx + MariaDB + SeaweedFS, `pruebaslinux` y `production-install` en verde el
  10-nov). Al ejecutarse por primera vez, el CI encontró **16 problemas**: 4 errores reales del código o de la interfaz, 3 de entorno y
  9 de las propias pruebas; todos corregidos en la fase donde nacían (#29). Solo queda en rojo CodeQL, por el falso positivo conocido.
- **Actualización 2026-11-11 (§M, #30–#32):** las fases están fusionadas en `main` (PR #26, #33–#35). El propietario tiene ya
  **MariaDB 13.1 y ClamAV 1.5.4 en local**, así que la suite completa corre también en Windows (pruebas adaptadas sin rebajar Linux).
  **Instalador con menú** para Windows, Linux y macOS que instala Node, MariaDB, ClamAV y npm (probado de punta a punta en Windows).
  **Adaptador de base de datos**, paso 1: motor elegido con `DB_CLIENT` y contrato probado contra la base real; PostgreSQL/Supabase en
  camino (no se afirma hasta tener su job del CI).
- **Revisión del código 2026-11-12 (#33, `docs/REVISION-CODIGO-2026-11.md`):** 0 vulnerabilidades, cobertura 77 % líneas / 84 % ramas.
  Cerradas dos trampas de claves (clave pública de reserva y semilla por defecto) y quitado código muerto peligroso. **Riesgo abierto:**
  el `.env` local funcionaba en producción con claves `legacy` (cambian cada día).
- **Rotación 2026-11-12 (#34):** `KEY_EPOCH` ya en el `.env` local; rotación **semanal** que descifra y re-cifra todo con el servidor
  **sin entradas ni salidas**; caídas y pausas reales probadas sin pérdida de datos (y corregido un `recover` que podía perder las semillas).
- **Mantenimiento 2026-11-15 (#35, §N):** por decisión del propietario solo queda la rama `main` (29 ramas remotas borradas; lo único sin
  fusionar se conserva en la etiqueta `archivo/project-thread-qjkfd0`); 9 actualizaciones de Dependabot aplicadas y 3 aparcadas;
  `npm audit fix` sin `--force` (quedan 5 moderadas, solo de desarrollo); grafo de graphify regenerado. **Verificado solo en local**
  (Windows, MariaDB 13.1): el CI real de GitHub, el job `compose` con las imágenes nuevas y `web/` **no** se han comprobado. Problema
  nuevo: `test_fuzz.js` no termina en este equipo, así que `test:all` y `coverage` se cuelgan en local.
- **Orden de la raíz 2026-11-17 (#36, §O):** a petición del propietario, la raíz pasa de 49 a 20 archivos versionados (pruebas en `test/`,
  documentación en `docs/`, `SECURITY.md` en `.github/`, instalador en `instalador/`, `debug-env.js` en `scripts/`), sin cambios de
  comportamiento. Verificado **solo en local** (lint 0 avisos, `test:api` 16/16, suite sin `test_fuzz.js` 592/593 igual que `main`); el CI
  de GitHub está caído por un problema de cuenta de Actions y `compose` no se probó con la ruta `test/`. Pendiente de decisión del
  propietario: `install.sh`, `install.ps1` y `security.config.js`. Las rutas de las entradas anteriores son las de su fecha.
- **Cuelgue del fuzz resuelto 2026-11-17 (#37, §P):** `test_fuzz.js` no fallaba por el servidor: su fuzz HTTP abría el stream SSE
  `GET /api/system/stream` como admin y el cliente de pruebas esperaba un cuerpo que no termina nunca. El helper `api()` ahora corta las
  respuestas `text/event-stream`. Resultado **solo en local**: `test:all` 614/615 (1 omitida por SIGHUP) en 699 s; `web/` typecheck,
  57/57 y build. Revisados también los commits de TLS de MariaDB y del usuario `secure_app` (PR #42), sin defectos.
- **CI de nuevo en verde 2026-11-17 (#38, §P):** los jobs no arrancaban por la facturación de la cuenta (repositorio privado); con el
  repositorio público vuelven a correr. El job `web` fallaba al instalar los navegadores porque `ubuntu-latest` ya es Ubuntu 26 y
  Playwright 1.56 no lo soporta: queda fijado a `ubuntu-24.04`. Resultado en GitHub (`a248917`): `test` (MariaDB 10.11, cobertura y fuzz),
  `web` (e2e en Chromium, Firefox y WebKit + axe), `compose`, `pruebaslinux` y `production-install` **en verde**. `Security`, pendiente del PR.

**Estado general.** API REST (Express 5 + MariaDB/MySQL) para datos sensibles con interfaz web de operación (Next.js) para
administradores. Cifrado AES-256-GCM por campo y por archivo, estado de seguridad en la base de datos, sesiones cortas con refresh
rotatorio, MFA (TOTP, passkeys), SSO (OIDC, SAML), roles finos con aprobación de dos administradores, KMS, antivirus, alertas, métricas,
trazas, cluster y varias réplicas. Media de los componentes evaluados (§C): **≈ 8,0/10** (antes 6,7 el 21-oct y ≈ 7,6 el 9-nov por la mañana).

**Componentes analizados.** Entrada y middlewares, autenticación/autorización, criptografía y rotación, archivos (local y S3), SSO,
observabilidad, cluster y despliegue (Docker), interfaz web (BFF), base de datos y migraciones, dependencias, CI, PruebasLinux y documentación.

**Problemas críticos encontrados en esta intervención.**
1. **Credenciales reales de una base de datos MySQL remota en `test.js`**, en el historial del repositorio público desde `4b196d1`
   (25-ago-2025). Archivo eliminado (#22); **hay que cambiar esa contraseña en el proveedor** (solo puede hacerlo el propietario).
2. `main` en **rojo** desde que se publicó GHSA-mrwp-f3q8-3g9p (`follow-redirects`, vía `axios`): el código no había cambiado (#21).
3. `DISABLE_IP_BLOCKING=true` quitaba bloqueos **y límites de login también en producción** (#22).

**Mejoras implementadas** (#21–#27): `main` en verde; bypass de pruebas de carga imposible en producción; MFA de un solo factor por
petición (alerta de CodeQL analizada); restos engañosos de 2025 retirados; 14 dependencias al día (incluidas TypeScript 7, ESLint 10,
fast-check 4); interfaz web completa (passkey, SSO sin tokens en el navegador, datos en vivo, cluster, accesibilidad, tres navegadores);
archivos en S3; varias réplicas con Docker; réplica de lectura y particionado de eventos; `@prometheus-io/client`; 9 opciones nuevas en
PruebasLinux con Semgrep propio; documentación al día con la tabla de endpoints generada y comprobada.

**Riesgos pendientes** (detalle en §D): rotar la contraseña filtrada; `.env` versionado (decisión del propietario: datos de prueba);
descartar la alerta de CodeQL; pentest externo; multi-organización; S3 y proveedores de identidad reales sin probar.

---

## B. Bitácora numerada de mejoras

### #1 — Creación del entorno independiente de pruebas `PruebasLinux`

- **Estado:** completado.
- **Archivos y módulos:** `PruebasLinux/pruebas.sh`, `PruebasLinux/lib/{core,ui,report}.sh`,
  `PruebasLinux/modules/01..15_*.sh`, `PruebasLinux/ReadmeLogMejoras.md`.
- **Problema detectado:** no existía un banco de pruebas de seguridad reproducible e
  independiente del código.
- **Acciones realizadas:** lanzador modular con registro automático de opciones,
  comprobación de dependencias, validación de entradas, cancelación limpia, logging con
  fecha/hora y exportación de informes. 117 opciones diferenciadas.
- **Pruebas ejecutadas:**
  - `bash -n` y `shellcheck -S error` sobre los 19 scripts → sin errores.
  - `./pruebas.sh --list` → 117 opciones en 15 categorías.
  - `./pruebas.sh --diagnose` → 33 herramientas presentes, 1 ausente (`trivy`).
  - Menú interactivo probado con entradas válidas e inválidas → navega y valida sin
    cerrarse.
  - Exportación MD/JSON/CSV → los 3 formatos se generan; JSON válido (`jq`).
- **Puntuación:** 8/10 (completo y funcional; `trivy` y un escaneo autenticado de API
  quedan como mejora).
- **Problemas restantes:** `trivy` no se pudo instalar (404 del binario fijado); 2
  opciones (88, 89) se omiten hasta tenerlo.
- **Siguiente mejora:** baseline de `detect-secrets` y reglas `semgrep` para Node. *(Prioridad media.)*

### #2 — Verificación de la suite de pruebas del proyecto

- **Estado:** completado (parcial por falta de BD).
- **Archivos:** `test_system.js`, `test_api.js`, `test_icmp.js`, `test_rotation.js`.
- **Acciones:** `npm ci` y ejecución de todas las suites.
- **Pruebas ejecutadas y resultados verificables:**
  - `npm test` (`test_system.js`) → **5/5** correctos.
  - `npm run test:api` → **12/12**.
  - `npm run test:icmp` → **24/24**.
  - `npm run test:rotation` → **46 pruebas, 14 ejecutadas y en verde, 32 OMITIDAS**
    por no haber MySQL (lo indica el propio test). Se ejecutó 6 veces para descartar
    intermitencias: 0 fallos.
- **Puntuación:** 7/10 (suite sólida; la cobertura de integración con BD no es
  verificable aquí).
- **Problemas restantes:** las 32 pruebas de rotación/BD no se pueden validar sin MySQL.
- **Siguiente mejora:** levantar MySQL efímero en CI para ejercitar esas rutas. *(Prioridad media.)*

### #3 — Análisis estático de código y configuración

- **Estado:** completado.
- **Acciones:** categorías 8, 10, 12, 13, 14 de `PruebasLinux` sobre el repo.
- **Resultados verificables:**
  - `node --check` sobre todos los `.js` → **sin errores de sintaxis**.
  - `shellcheck` → advertencias en scripts `.sh` del proyecto (`scripts/*.sh`).
  - Patrones peligrosos → `child_process.spawn` en `scripts/icmpMonitor.js` (uso
    legítimo y controlado del monitor ICMP; no es inyección).
  - Inyección SQL → la única interpolación (`notes.controller.js:109`) concatena
    **nombres de columna fijos** y parametriza los valores con `?`: **revisado, sin
    inyección real**.
  - BD: columnas sensibles `*_encrypted`/`*_hash` → cifradas/hasheadas; migraciones
    referencian cifrado.
  - Auth: bcrypt presente; rate limiting/bloqueo configurado; middleware de rol
    presente; 2FA (speakeasy/qrcode) detectado.
  - Logging: auditoría presente y **cifrada** antes de persistir; sin `console.log` de
    datos sensibles; monitorización de integridad configurada.
- **Puntuación:** 7/10.
- **Problemas restantes:** fijar `algorithms` en `jwt.verify`; revisar advertencias de
  shellcheck.
- **Siguiente mejora:** endurecer JWT y limpiar scripts shell. *(Prioridad media.)*

### #4 — Revisión de dependencias

- **Estado:** completado (hallazgo abierto).
- **Acciones:** `npm audit --omit=dev`.
- **Resultado verificable:** **21 vulnerabilidades (1 crítica, 12 altas, 8 moderadas).**
- **Puntuación:** 4/10.
- **Problemas restantes:** la corrección total requiere `npm audit fix --force` con
  *breaking changes* (p. ej. `nodemailer` mayor, `geoip-lite`), lo que **afecta al
  código**; no se aplica en esta intervención aditiva.
- **Siguiente mejora:** plan de actualización escalonado con pruebas. *(Prioridad alta.)*

### #5 — Higiene de secretos y repositorio

- **Estado:** completado (hallazgos abiertos).
- **Acciones:** categorías 6 y 12 de `PruebasLinux` + inspección de `git ls-files`.
- **Resultados verificables:** `.env` versionado (valores = `.env.example`); 56
  `src/notifications/*.json` y 1 `reports/*.json` versionados; permisos de `.env` `644`
  (recomendado `600`); sin claves privadas ni tokens reales detectados en archivos
  versionados; `detect-secrets` marca entradas en `.env`, `README.md` y algunos tests
  (coinciden con semillas de ejemplo/documentación).
- **Puntuación:** 5/10.
- **Problemas restantes:** dejar de versionar `.env` y los artefactos; rotar cualquier
  secreto que alguna vez haya sido real; limpiar historial si procede.
- **Siguiente mejora:** `git rm --cached` de esos ficheros + rotación. *(Prioridad alta;* afecta al repo, se propone, no se aplica.)*

### #6 — Corrección de vulnerabilidades de dependencias

- **Estado:** completado (de 21 a 3; las 3 restantes, riesgo aceptado documentado).
- **Archivos:** `package.json`, `package-lock.json`, `src/security/anomaly-detection.service.js`.
- **Problema detectado:** `npm audit --omit=dev` reportaba 21 vulnerabilidades (1 crítica).
- **Acciones realizadas:**
  - `npm audit fix` (no disruptivo): resuelve la mayoría (incl. `proxy-addr` crítica, `axios`, `mysql2`, `path-to-regexp`, `lodash`, `qs`, `morgan`, `brace-expansion`).
  - `nodemailer` 7 → **10.1.7**: corrige la inyección de comandos SMTP (`envelope.size`).
  - Migración del parseo de user-agent de `useragent` (sin arreglo, arrastra `tmp`) a
    **`ua-parser-js`** (ya presente y parcheado) en `anomaly-detection.service.js`;
    eliminada la dependencia `useragent`.
- **Pruebas ejecutadas:** `test:api` 12/12, `test:icmp` 24/24, `test:system` 5/5,
  `test:rotation` 14 en verde (+32 omitidas sin MySQL); smoke de carga de
  `anomaly-detection` y `nodemailer`. Sin regresiones.
- **Puntuación:** dependencias **4 → 7/10**.
- **Problemas restantes:** 3 vulnerabilidades transitivas vía `geoip-lite → ip-address@5.9.4`
  (XSS en métodos HTML de `ip-address`, DoS de `sprintf-js`). El único "arreglo" de npm
  degrada `geoip-lite` a 1.2.2 (pierde la BD mantenida) y el `ip-address` parcheado es un
  *major* (10.x) incompatible con `geoip-lite`. **No alcanzables:** la app sólo usa
  `geoip.lookup()`; nunca renderiza HTML de `ip-address` ni pasa entrada de usuario a
  `sprintf`. Riesgo aceptado y a vigilar upstream.
- **Siguiente mejora:** actualizar cuando `geoip-lite` publique una versión con
  `ip-address` parcheado. *(Prioridad media.)*

### #7 — Instalador multiplataforma (Linux y Windows)

- **Estado:** completado.
- **Archivos:** `install.js`, `install.sh`, `install.ps1`, `INSTALL.md`.
- **Problema detectado:** no había un instalador que preparase el entorno de forma guiada
  en ambos sistemas.
- **Acciones realizadas:** instalador en Node (sin dependencias nuevas) que **pregunta
  Linux/Windows**, instala dependencias (`npm ci`/`install`), prepara `.env` (con `600`
  en Linux), ajusta permisos, ofrece instalar el toolset de `PruebasLinux` y verifica,
  todo con **barra de progreso**. Lanzadores `install.sh` (Linux) y `install.ps1`
  (Windows) que delegan en él.
- **Pruebas ejecutadas:** `node --check` + `shellcheck`; ejecución real `--os linux`
  (npm ci, .env, chmod 600, verificación → OK) y `--os windows` (sin chmod, guía
  Windows); rechazo de `--os` inválido con código 2.
- **Puntuación:** 8/10 (en Windows la instalación del toolset de seguridad se guía, no se
  automatiza; el menú de `PruebasLinux` requiere WSL/Git Bash en Windows).
- **Problemas restantes:** automatizar el toolset en Windows (winget/choco) queda como
  mejora.
- **Siguiente mejora:** script `winget`/`choco` para el toolset en Windows. *(Prioridad baja.)*

Las entregas siguientes siguen en las secciones **K** (#8–#20), **L** (#21–#29) y **M** (#30–#32), con este mismo formato.

---

## C. Sistema de puntuación por componente (0–10)

Criterios: **F** funcionalidad · **S** seguridad · **Q** calidad y mantenibilidad · **E** gestión de errores · **R** rendimiento ·
**T** cobertura de pruebas · **D** documentación. «Evaluado» = con pruebas ejecutadas (local o CI); «Parcial» = parte sin ejecutar (se dice
qué); «No evaluado» = sin evidencia. **Ninguna puntuación es 10**: sin pentest externo ni producción real, no hay evidencia suficiente.

| Componente | Estado | F | S | Q | E | R | T | D | Media | Justificación breve |
|---|---|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|---|
| Criptografía y rotación | Evaluado (CI, oct) | 9 | 8 | 8 | 9 | 6 | 9 | 9 | **8,3** | v4 + HKDF, rotación probada con `kill -9`; RAM ≈7× la BD al rotar |
| Autenticación (sesiones, MFA, SSO) | Evaluado (CI) | 9 | 9 | 8 | 8 | 8 | 9 | 9 | **8,6** | Refresh rotatorio, TOTP/WebAuthn/OIDC/SAML; solo contra simuladores |
| Autorización | Evaluado (CI) | 9 | 9 | 8 | 8 | 8 | 8 | 8 | **8,3** | Permisos por rol desde la BD, dos administradores; sin multi-organización |
| API y validación | Evaluado (local + CI) | 9 | 8 | 8 | 9 | 8 | 9 | 9 | **8,6** | OpenAPI = código (prueba) y README = OpenAPI (prueba); fuzzing de todas las rutas |
| Base de datos | Evaluado (CI; réplica de lectura solo con la principal) | 8 | 8 | 8 | 8 | 7 | 8 | 8 | **7,9** | Parámetros siempre; réplica y particiones opcionales; adaptador con contrato probado (#32), aún solo MySQL/MariaDB |
| Archivos (local y S3) | Evaluado (CI: simulador y SeaweedFS) | 9 | 9 | 8 | 9 | 8 | 8 | 8 | **8,4** | Integridad por bloque; S3 con una petición por rango; antivirus con ClamAV real también en Windows (#31); audio/vídeo sin sanear |
| Gestión de errores | Evaluado | 8 | 8 | 8 | 8 | — | 8 | 7 | **7,8** | Sin trazas al cliente (fuzzing); fallos de S3/BD sin filas a medias |
| Dependencias | Parcial (CI de fases 0–2; #35 solo en local) | 9 | 8 | 8 | — | — | 8 | 8 | **8,2** | `npm audit`: `web/` 0; raíz 5 moderadas solo de desarrollo (minimatch/glob; corrección con versión mayor, pendiente de decisión); 9 actualizaciones y 3 aparcadas (#35) |
| Secretos y configuración | Evaluado | 7 | 5 | 7 | 7 | — | 7 | 8 | **6,8** | Credencial real en el historial (rotación pendiente), `.env` versionado y, en local, claves `legacy` sin `KEY_EPOCH` (#33) |
| Observabilidad y operación | Evaluado (CI, también a través de nginx) | 9 | 8 | 8 | 8 | 7 | 8 | 9 | **8,1** | Alertas, métricas, trazas, SSE con revalidación |
| Rendimiento y escalabilidad | Evaluado (CI: 2 réplicas en una máquina) | 8 | 7 | 8 | 8 | 7 | 7 | 9 | **7,7** | Medido en 1 máquina; réplicas solo en contenedores de una máquina |
| Pruebas automatizadas | Evaluado (CI en verde, #38) | 9 | 8 | 8 | 8 | — | 9 | 8 | **8,3** | 615 API + 57 web + e2e; CI `a248917`: `test` (MariaDB 10.11, cobertura y fuzz), `web` (e2e en 3 navegadores + axe), `compose`, `pruebaslinux` en verde; en local `test:all` 614/615 (#37) |
| Interfaz web | Evaluado (CI: e2e en 3 navegadores + axe) | 9 | 9 | 8 | 8 | 8 | 8 | 9 | **8,4** | BFF, passkey, SSO sin tokens, SSE, axe, 3 navegadores |
| Infraestructura / Docker | Evaluado (CI `compose` en verde con las imágenes de #35 y la ruta `test/`, #38) | 8 | 8 | 8 | 7 | 7 | 8 | 8 | **7,7** | Imagen sin root ni dev; TLS a la BD desactivado en el compose de prueba |
| PruebasLinux | Evaluado (local y CI) | 8 | 8 | 8 | 8 | — | 7 | 9 | **8,0** | 126 opciones; trivy/hadolint sin instalar en CI |
| Documentación | Evaluado | 9 | — | 8 | — | — | 8 | 9 | **8,5** | README 4979→560 líneas, histórico separado, tabla de endpoints con prueba |

**Media de los 16 componentes ≈ 8,1/10** (antes 6,7 el 21-oct). El CI de las fases 3–6 está en verde desde el 10-nov: «Parcial» pasa a
«Evaluado». Las notas se mantienen porque los fallos que encontró el CI (#29) se corrigieron con pruebas que los cubren. Solo sube la T de
Docker, que ya tiene pruebas ejecutadas.

**Actualización 2026-11-15 (#35, mantenimiento):** no sube ninguna nota. Bajan dos por falta de evidencia: Dependencias (S 9→8: 5
moderadas de desarrollo abiertas; pasa a «Parcial») y Pruebas automatizadas (T 8→7: `test_fuzz.js` no termina en local; «Parcial»).
Infraestructura / Docker pasa a «Parcial» porque nginx, SeaweedFS y aws-cli cambiaron de versión y el job `compose` no se ha ejecutado.
La media sigue en **≈ 8,1/10**. Lo ejecutado en #35 es solo local; el CI real de GitHub no se ha podido comprobar.

**Actualización 2026-11-17 (#36, orden de la raíz):** no cambia ninguna nota ni la media (**≈ 8,1/10**). La entrega solo mueve archivos y
actualiza referencias, sin cambios de comportamiento: mejora la mantenibilidad y la claridad de la documentación (Q y D), pero no se
sube nada porque la evidencia es solo local (lint 0 avisos, `test:api` 16/16, suite sin `test_fuzz.js` 592/593 igual que `main`) y el CI
de GitHub sigue sin poder comprobarse. Los componentes «Parcial» de #35 (Pruebas automatizadas, Infraestructura / Docker) siguen así;
Docker/compose no se probó con la nueva ruta `test/`.

**Actualización 2026-11-17 (#37, cuelgue de `test_fuzz.js`):** Pruebas automatizadas sube de T 7 a 8 (8,0 → **8,2**) porque `test:all`
vuelve a terminar en local (614/615, 1 omitida por SIGHUP en Windows) y `web/` pasa typecheck, 57/57 y build. Sigue en «Parcial»: la
evidencia es solo local (Windows, MariaDB 13.1) y el CI de GitHub no se ha comprobado. La media no cambia (**≈ 8,1/10**).

**Actualización 2026-11-17 (#38, CI de nuevo en verde):** con el repositorio público vuelven a ejecutarse los jobs y todo el CI pasa en
`a248917`. Pruebas automatizadas pasa a «Evaluado» y T 8 → 9 (**8,3**); Infraestructura / Docker pasa a «Evaluado» (`compose` en verde
con la ruta `test/`), sin cambiar notas. La media sigue en **≈ 8,1/10**. `Security` (CodeQL, gitleaks, SBOM, DAST) no se ha ejecutado aún:
solo corre en PR o en push a `main`.

---

## D. Registro de problemas y tareas pendientes (por prioridad)

| Prioridad | Hallazgo | Evidencia | Impacto | Solución | Estado |
|---|---|---|---|---|---|
| **Crítica** | Contraseña real de una BD MySQL remota en el repositorio público | `test.js` (host `sistemagym.xo.je`), en el historial desde `4b196d1` | Cualquiera puede leerla del historial de GitHub | Archivo eliminado (#22). **Cambiar la contraseña en el proveedor**; opcional: reescribir el historial | Abierto (rotación: propietario) |
| Alta | CI de las fases 3–6 sin ejecutar | `git push` bloqueado: el Git Credential Manager tenía 3 cuentas de GitHub y preguntaba cuál usar | Lo que necesita MariaDB/navegadores/Docker no estaba verificado | Cuenta fijada en la configuración local del repositorio; ramas subidas en orden; 16 fallos corregidos (#29) | Cerrado (CI verde 10-nov) |
| Alta | Sin pentest externo ni auditoría | `docs/PENTEST-AUTOEVALUACION.md` §4 | Las pruebas propias no sustituyen a un tercero | Encargar pentest con `docs/openapi.json` y el entorno reproducible | Abierto (organización) |
| Alta (aceptada) | `.env` versionado | `git ls-files .env` | Si un día lleva secretos reales, quedan en el historial | Decisión del propietario: hoy son datos de prueba; antes de producción, `npm run kms -- migrate-env` y sacarlo | Aceptado |
| Media | Alerta de CodeQL `js/user-controlled-bypass` en `mfa.service.js` (sigue en rojo en los PR #24 y #25) | Check «Code scanning results» del PR #8 | Falso positivo analizado: el valor elige qué factor se verifica, no si se verifica | Endurecido (un solo factor, tipo texto) (#22); **descartarla en GitHub** como falso positivo | Mitigado |
| Media | Proveedores reales sin probar (Entra ID/Okta, AWS KMS/Vault, AWS S3/R2) | Pruebas contra simuladores | Diferencias de un proveedor real | Prueba en preproducción con cada proveedor usado | Abierto |
| Media | Rotación de claves en memoria | 83 MB → 593 MB de RAM, 75 s cerrado | Inviable con BD de GB | Snapshot y re-cifrado por lotes en streaming | Propuesto |
| Media | Multi-organización, HIBP, límite de sesiones simultáneas, versionado de API | `docs/CONTROLES.md` §2 | Controles ASVS no cubiertos | Diseño y desarrollo por separado | Propuesto |
| Media | Producción puede arrancar con claves `legacy` (cambian cada día) | `src/crypto/key-provider.js:14-17` (#33) | Un `.env` sin `KEY_EPOCH` pierde lo cifrado cada día | `.env` local corregido (#34); propuesto: no arrancar en producción con `legacy` | Abierto (decisión del propietario) |
| Media | El servidor local no conecta a la MariaDB local con el `.env` actual | TLS verificado con certificado autofirmado + usuario de BD inexistente (#34) | No se puede probar `npm start` de punta a punta en local | Credenciales de prueba válidas o `NODE_ENV=development` en local | Abierto |
| Media | SQL acoplado a MySQL/MariaDB (`DATE_SUB … INTERVAL`, `ON DUPLICATE KEY`, `GET_LOCK`, esquema con `ENUM`/`AUTO_INCREMENT`) | `docs/BASES-DE-DATOS.md` §2 | Sin PostgreSQL/Supabase | Adaptador por pasos: paso 1 hecho (#32) | En curso |
| Media | Instaladores de Linux y macOS sin ejecutar | Solo hay Windows en este entorno (#31) | Un fallo de distribución no se vería hasta usarlo | Ejecutarlos en equipos reales o en un job del CI | Abierto |
| Media | `test_fuzz.js` no terminaba en local; `test:all` y `coverage` se colgaban. Causa: el fuzz HTTP abría `GET /api/system/stream` (SSE, sin fin) como admin y el helper `api()` esperaba el cuerpo entero | Ejecución local (#35); causa confirmada en #37 (128 usuarios creados = 64 rutas de `user` + 64 de `admin`, la última es el stream) | Sin `test:all` ni cobertura completos en local | `api()` corta el cuerpo de las respuestas `text/event-stream` (#37) | **Cerrado (#37, solo local)** |
| Media | 5 moderadas de `npm audit` en la raíz (solo desarrollo): minimatch <11.0.1 vía `nodemon` y `c8`→`test-exclude`→`glob` 13 (GHSA-3g3m-2fjr-6pw4) | `npm audit` tras #35; GitHub avisó de 2 moderadas en `main` (no se pudo ver la página; probablemente los dos advisories de minimatch/glob) | Solo herramientas de desarrollo, no producción | Exige versión mayor (minimatch 11 / glob >14.0.1) o volver a `c8` 9.1.0; posible `overrides` | Abierto (decisión del propietario) |
| Baja | 3 actualizaciones aparcadas: `mariadb` 10.11→13.0 en `deploy/`, imagen `node` 22→26-bookworm-slim, `actions/upload-artifact` 4→7 | Dependabot (#35) | El CI usa MariaDB 10.11 a propósito | Decidir cada una | Abierto (decisión del propietario) |
| Baja | Commit `5ee29e5` sin fusionar (token de cliente diario, `capacity.js`, optimización de `level3.js`) | Etiqueta `archivo/project-thread-qjkfd0` (#35) | Trabajo conservado pero fuera de `main` | Decidir si se rescata o se descarta | Abierto (decisión del propietario) |
| Alta | CI de GitHub caído por la cuenta: los jobs no llegaban a arrancar («recent account payments have failed or your spending limit needs to be increased»; el repositorio era privado) | Anotaciones de los check-runs (#38) | Nada del CI verificado desde #35 | El propietario hizo público el repositorio; además el job `web` se fijó a `ubuntu-24.04` (Playwright 1.56 no instala dependencias en Ubuntu 26) | **Cerrado (#38): CI en verde en `a248917`** |
| Media | `Security` (CodeQL, gitleaks, SBOM, DAST) sin ejecutar desde que volvió el CI | Solo corre en PR o en push a `main` (#38) | Análisis de seguridad sin evidencia reciente | Abrir el PR de `ci/revision` y revisar su resultado | Abierto |
| Baja | Playwright fijado en 1.56.1 obliga a usar `ubuntu-24.04` en el job `web` | #38 | Al retirar 24.04 de los runners, el job fallaría | Subir Playwright a una versión que soporte Ubuntu 26 y volver a `ubuntu-latest` | Abierto |
| Baja | `install.sh`, `install.ps1` (atajos que solo redirigen) y `security.config.js` (sin importadores; objeto estático de 2025) siguen en la raíz | Raíz tras #36 | Ruido y código muerto | Borrarlos o mantenerlos | Abierto (decisión del propietario) |
| Baja | `dependency-review` en rojo en los PR | «Dependency review is not supported on this repository» | Ruido (no bloquea: `continue-on-error`) | Activar «Dependency graph» en Settings | Abierto (propietario) |
| Baja | trivy y hadolint no se instalan en CI | Opciones 88, 89 y 125 omitidas | Menos cobertura de imagen/Dockerfile | Fijar binarios con suma de verificación | Propuesto |
| Baja | Saneado solo de imágenes y PDF | `docs/SEGURIDAD.md` §22 | Metadatos en audio/vídeo/texto | Recodificar o despojar metadatos | Propuesto |
| Baja | Mensaje del commit `b1863b6` dice «test:api 16/16» | Ejecución: 15/15 | Inexactitud en el historial | Corregido aquí (#22) | Cerrado |

Resueltos de la lista del 21-oct (§D anterior): dependencias (0 vulnerabilidades), JWT con algoritmo fijo, auto-puntuación retirada
(completado en #22: `fix-system.js` y los marcadores «score 100»), `src/notifications/`, CI con MariaDB.

---

## E. Historial de cambios

### Entregas 1–2 (21-oct, PR #6)

| Acción | Archivo(s) | Motivo | Validación |
|--------|-----------|--------|------------|
| Creado | `PruebasLinux/` (lanzador, 3 librerías, 15 módulos, documentación) | Entorno independiente de pruebas | `bash -n`, `shellcheck`, `--list/--diagnose`, menú |
| Creado | `ReadmeLogsMejoras.md` | Bitácora de auditoría | — |
| Modificado | `package.json`, `package-lock.json`, `src/security/anomaly-detection.service.js` | 21 → 3 vulnerabilidades (`nodemailer`, `ua-parser-js`) | `npm audit`; suites en verde |
| Creado | `install.js`, `install.sh`, `install.ps1`, `INSTALL.md` | Instalador multiplataforma | `--os linux/windows` |

### Entregas 3–6 (21–27-oct, PR #7 y #8)

Ver secciones G–J y los commits `64920de`…`5943aa8` (`git log e7b6597^..b36a9a1`). Resumen por entrada en §K (#8–#20).

### Intervención 7 (9-nov, ramas `cierre/*`)

| Fase / commit | Creado | Modificado | Eliminado | Por qué | Validación |
|---|---|---|---|---|---|
| 0 · `a5b9b05`, `f32972a` | — | `package-lock.json`, `src/crypto/kms-providers.js`, `test_kms.js` | — | `main` en rojo; proveedor KMS `file` inutilizable en Windows | CI verde; `test_kms` 16/16 en Windows |
| 1 · `b1863b6` | `scripts/healthCheck.js` | `protection.middleware.js`, `index.js`, `mfa.service.js`, `.gitleaksignore`, `.env.example`, `docs/SEGURIDAD.md`, `package.json`, `test_api.js`, `test_mfa.js` | `test.js`, `fix-system.js`, 8 marcadores «score 100», `reports/…json`, `integrity/history.json` | Bypass en producción, CodeQL, gitleaks, restos engañosos, credencial filtrada, health-check falso | CI verde; `test:api` 15/15; lint 0 |
| 2 · `d0daebb`…`bed6619` | — | 3 workflows, `package*.json`, `web/package*.json`, `test_fuzz.js` | — | 14 actualizaciones de Dependabot | CI verde; build con TypeScript 7; fuzz 16/16 |
| 3 · `62dbe6b` | migración 017, `handoff.service.js`, `live-stream.js`, `cluster-status.js`, 6 rutas y 4 módulos de `web/`, `e2e/live-auth.test.cjs`, `sso-passkey-stream.test.ts` | controladores SSO/SAML/system, rutas, `index.js`, `cluster.js`, `schema.sql`, `openapi.json`, páginas web, `ci.yml`, 4 suites de pruebas | — | Interfaz web completa (#24) | Local: web 57/57 (mutaciones), build, `test:api`, lint; CI verde tras #29 |
| 4 · `2ad6e0b` | `s3-store.js`, `events-partitions.js`, `Dockerfile`, `.dockerignore`, `deploy/*`, `test_s3.js`, `test_files_s3.js`, `test_partitions.js`, `test_compose.js`, `mock-s3.js`, `scripts/eventsPartitions.js` | `storage.js`, `file-cipher.js`, `files-backup.js`, `database.js`, `metrics.js`, `cluster.js`, 2 servicios, `ci.yml`, `dependabot.yml`, `install.js`, `INSTALL.md` | dependencia `prom-client` | Escalabilidad (#25) | Local: `test_s3` 5/5, fuzz, `test_files` sin BD, agregación de métricas, compose validado; CI verde tras #29 |
| 5 · `10d4921` | `PruebasLinux/modules/16_ampliacion.sh`, `rules/semgrep-node.yml` | `ci.yml` | — | PruebasLinux (#26) | `bash -n`, `--list` 126, opciones 119/120/121/124 OK; CI verde tras #29 |
| 6 · (este commit) | `docs/historico/GUIA-ORIGINAL.md`, `scripts/openapiTable.js` | `README.md`, `ReadmeLogsMejoras.md`, `docs/SEGURIDAD.md`, `web/README.md`, `PruebasLinux/ReadmeLogMejoras.md`, `.env.example`, `test_api.js`, `package.json` | 4300 líneas históricas del README (movidas) | Documentación fiel (#27) | `test:api` 16/16 (incluye README = OpenAPI) |
| 3–6 · correcciones del CI (10-nov) | `.github/scripts/annotate-log.sh` | `ci.yml`, `Dockerfile`, `deploy/docker-compose.yml`, `compose.env.example`, `secure-communications.service.js`, `events-partitions.js`, `web/src/{lib/client.ts,components/{Live,Shell}.tsx,app/globals.css}` y 7 páginas, `mock-idp.js`, `test_ops`, `test_sessions`, `test_partitions`, `test_compose`, `live-auth.test.cjs`, docs | servicio MinIO | 16 fallos que encontró el primer CI (#29) | CI verde en las fases 3–6 |

---

### Intervención 8 (10–11-nov, ramas `cierre/8-bd` e `instalador`)

| Entrada / commit | Creado | Modificado | Eliminado | Por qué | Validación |
|---|---|---|---|---|---|
| #30 · `1c7666a`, `b558261`, `67051e9` | `database/setup-local.sql`, `docs/BASES-DE-DATOS.md` | `test_files.js`, `test_files_backup.js`, `test_rotation.js`, `test_scale.js`, `CLAUDE.md` | — | MariaDB 13.1 local; 8 fallos solo de Windows | Archivos afectados 168/170 + cluster 3/3 |
| #31 · `a559875`, `2cf2bd1` | `instalar.{cmd,sh,command}`, `instalador/*` | `install.js`, `install.sh`, `install.ps1`, `INSTALL.md`, `test_av.js`, `.gitattributes`, `.gitignore` | — | Instalador con menú y ClamAV por sistema | Instalación real en Windows; `test_av` 23/23 |
| #32 · `d9a7fe9`, `c6f5ec9` | `src/config/db-drivers/{index,mysql}.js`, `test_db.js` | `database.js`, `live-stream.js`, `anomaly-detection.service.js`, `rate-limiter.service.js`, `package.json`, `.env.example`, docs | — | Adaptador (paso 1) y `SUM(CASE …)` | `test_db` 11/11; suite local 601/602 (1 omitida); lint 0 |
| #33 · `881a59d` | `docs/REVISION-CODIGO-2026-11.md` | `secure-env.js`, `key-provider.js`, `auth.controller.js`, `database.js`, `test_rotation.js`, `test_api.js`, docs | 4 métodos de mantenimiento muertos, `secureQuery`/`logDatabaseAccess` | Revisión: claves sin valores conocidos y código muerto fuera | Pruebas nuevas; cobertura 77 %; ver #33 |
| #34 · (este commit) | `src/maintenance/cutoff.js`, `test_helpers/rotation-child.js` | `rotation.service.js`, `guard.js`, `scheduleKeyRotation.js`, `keyRotator.js`, `securityHousekeeping.js`, `alerts.service.js`, `secure-communications.service.js`, `live-stream.js`, `index.js`, `test_rotation.js`, `README.md`, `.env.example`, docs | — | Rotación semanal sin entradas ni salidas; caídas y pausas sin pérdida | 9 pruebas nuevas; ver #34 |

### Intervención 9 (15-nov, mantenimiento, rama `fix/audit-bitacora-2026-11-15`)

| Entrada / commit | Creado | Modificado | Eliminado | Por qué | Validación |
|---|---|---|---|---|---|
| #35 · `c6255e2` | etiqueta `archivo/project-thread-qjkfd0` | `CLAUDE.md` | 29 ramas remotas | Solo `main` + rama corta por tarea | `main` contiene todo salvo `5ee29e5` (archivado) |
| #35 · `9805d95` | — | `package*.json`, `deploy/docker-compose.yml`, `ci.yml` (nginx, SeaweedFS, aws-cli, dependency-review) | — | 9 actualizaciones de Dependabot | Local: lint 0, `test:api` 16/16, suite sin fuzz 592/593; CI sin comprobar |
| #35 · `4ddb01d` | — | `package-lock.json` (eslint 10.15.0, `@eslint/config-array` 0.23.6) | — | `npm audit fix` sin `--force` (GHSA-g3hv-75wg-m249) | Lint 0 y `test:api` 16/16 tras el cambio |
| #35 · `42da76d` | — | `graphify-out/`, `.gitignore` | — | Grafo regenerado; copias por fecha ignoradas | 3337 nodos, 6101 aristas, 203 comunidades |
| #35 · (este commit) | — | `ReadmeLogsMejoras.md` | — | Bitácora de la entrega | — |

### Intervención 10 (17-nov, orden de la raíz, rama `orden/raiz-limpia`)

Las rutas de la columna «Modificado» son las de después de cada commit; las entradas anteriores citan las de su fecha.

| Entrada / commit | Creado | Modificado | Eliminado | Por qué | Validación |
|---|---|---|---|---|---|
| #36 · `45ea6ee` | `test/`, `test/helpers/` (movidos) | `package.json`, `.c8rc.json`, `.dockerignore`, `eslint.config.js`, `ci.yml`, `deploy/docker-compose.yml`, `database/setup-local.sql`, `README.md`, `CLAUDE.md`, `docs/*`, `scripts/openapiTable.js`, comentarios de `src/` | 26 `test_*.js` y `test_helpers/` de la raíz (movidos) | Menos archivos sueltos en la raíz | Local: lint 0, `test:api` 16/16, suite sin fuzz 592/593 (= `main`) |
| #36 · `44357c4` | `scripts/debug-env.js`, `docs/INSTALL.md`, `.github/SECURITY.md`, `docs/ReadmeLogsMejoras.md` (movidos) | enlace a `PruebasLinux` | los mismos 4 archivos de la raíz (movidos) | Idem | Local: lint 0, `test:api` 16/16, `npm run debug-env` |
| #36 · `59349b7` | `instalador/install.js` (movido) | `instalador/comun.sh`, `instalador/windows.ps1`, `docs/INSTALL.md` | `install.js` de la raíz (movido) | Idem | Local: `node instalador/install.js --help` |
| #36 · `d0c283f` | — | `CLAUDE.md` | — | Flujo de git: se sube solo la rama corta; `main` avanza al validarla el propietario | — |
| #36 · (este commit) | — | `docs/ReadmeLogsMejoras.md` | — | Bitácora de la entrega | — |

### Intervención 11 (17-nov, cuelgue del fuzz y revisión, rama `fix/fuzz-sse`)

| Entrada / commit | Creado | Modificado | Eliminado | Por qué | Validación |
|---|---|---|---|---|---|
| #37 · `a64e066` | — | `test/helpers/app.js` (`api()` corta respuestas SSE), `docs/ReadmeLogsMejoras.md`, `graphify-out/` | — | `test_fuzz.js` se colgaba al abrir `GET /api/system/stream` como admin | Local: `test_fuzz.js` 18/18 (105 s), `test:all` 614/615, lint 0, `test:api` 20/20, `web/` typecheck + 57/57 + build |

### Intervención 12 (17-nov, CI de GitHub, rama `ci/revision`)

| Entrada / commit | Creado | Modificado | Eliminado | Por qué | Validación |
|---|---|---|---|---|---|
| #38 · `14a4cbf` | — | `.github/workflows/ci.yml` (comentario de `production-install` en su job) | — | Comentario mal colocado | CI: todo en verde salvo `web` (instalación de Playwright en Ubuntu 26) |
| #38 · `a248917` | — | `.github/workflows/ci.yml` (`web` en `ubuntu-24.04`; anotación si falla la instalación de navegadores) | — | `ubuntu-latest` es Ubuntu 26 y Playwright 1.56 no instala allí | CI: `test`, `web`, `compose`, `pruebaslinux`, `production-install` en verde |
| #38 · (este commit) | — | `docs/ReadmeLogsMejoras.md`, `graphify-out/` | — | Bitácora de la entrega | — |

---

## F. Plan de mejora continua

### Completado (con evidencia)
- ✅ `main` en verde y punto de recuperación (#21). ✅ Seguridad: bypass, MFA, gitleaks, restos y credencial retirada del árbol (#22).
- ✅ Dependencias al día (#23). ✅ Interfaz web completa (#24). ✅ Escalabilidad: S3, Docker, réplica, particiones (#25).
- ✅ PruebasLinux ampliado (#26). ✅ Documentación fiel y con prueba de sincronía (#27). ✅ CI de todas las fases en verde (#28, #29).
- ✅ Fases fusionadas en `main` (PR #26, #33–#35). ✅ Suite completa en local con MariaDB 13.1 (#30). ✅ Instalador con menú y ClamAV,
  probado en Windows (#31). ✅ Adaptador de base de datos, paso 1 (#32). ✅ Revisión del código y trampas de claves cerradas (#33). ✅ Rotación semanal sin entradas ni salidas, caídas y pausas reales probadas (#34).
- ✅ Solo `main` en el remoto, con el commit sin fusionar archivado en una etiqueta (#35). ✅ 9 actualizaciones de Dependabot y
  `npm audit fix` aplicados, verificados **solo en local** (#35). ✅ Grafo de graphify regenerado (#35).
- ✅ Raíz ordenada: de 49 a 20 archivos versionados (pruebas en `test/`, documentación en `docs/`, instalador en `instalador/`), sin
  cambios de comportamiento; verificada **solo en local** (#36).
- ✅ Cuelgue de `test_fuzz.js` resuelto: `test:all` termina en local con 614/615 (#37, **solo local**).
- ✅ CI de GitHub de nuevo en verde (`test`, `web`, `compose`, `pruebaslinux`, `production-install`) tras hacer público el repositorio y
  fijar `web` a `ubuntu-24.04` (#38).

### Propuesto (dependencias · prioridad · criterio de aceptación)
0. **No arrancar en producción con claves `legacy`** (si el propietario lo aprueba; el `.env` local ya tiene `KEY_EPOCH`) · media · el
   servidor se niega a arrancar sin `KEY_EPOCH` con `NODE_ENV=production`.
1. **Cambiar la contraseña filtrada** de la BD remota · crítica · el usuario de `test.js` ya no da acceso.
2. **PostgreSQL/Supabase** (pasos 2–4 de `docs/BASES-DE-DATOS.md`) · media · `test:all` en verde con `DB_CLIENT=postgres` en un job
   del CI, además del de MariaDB. MongoDB después (capa de repositorios).
3. **Descartar la alerta de CodeQL** como falso positivo y **activar Dependency graph** · baja · sin alertas abiertas ni jobs rojos de ruido.
4. **Pruebas con proveedores reales** (IdP, KMS, S3) en preproducción · media · un login SSO real, una clave KMS real, un bucket real.
5. **Pentest externo** · alta (organizativa) · informe y retest de hallazgos.
6. **Rotación de claves en streaming** · media · rotar una BD de 1 GB con RAM acotada.
7. **trivy y hadolint en CI** con binarios verificados · baja · opciones 88, 89 y 125 ejecutadas.
8. **ASVS pendientes**: HIBP, límite de sesiones, versionado de API, multi-organización · media.
9. `.env` fuera del repositorio cuando deje de ser de pruebas · alta antes de producción.
10. **Instaladores de Linux y macOS ejecutados** en equipos reales o en el CI · media · `linux.sh --si` termina con EICAR detectado.
11. ~~**Comprobar el CI tras #35**~~ · hecho en #38: todo el CI en verde en `a248917`. Queda ejecutar `Security` (al abrir el PR) y subir
    Playwright para volver a `ubuntu-latest` · media.
12. ~~**Investigar el cuelgue de `test_fuzz.js`**~~ · hecho en #37 (solo local): `test:all` y `coverage` terminan con 614/615 (1 omitida por SIGHUP); `check-coverage` pasa.
13. **Decidir las 5 moderadas de desarrollo** (`overrides` de minimatch/glob o `c8` 9.1.0), **las 3 actualizaciones aparcadas** y **el
    commit archivado** · baja · decisión del propietario anotada.
14. **Desbloquear el CI de Actions** (cuenta/facturación) y comprobar `compose` y `ci.yml` con las rutas nuevas de `test/` (#36) · alta ·
    todos los jobs en verde o fallos anotados.
15. **Decidir `install.sh`, `install.ps1` y `security.config.js`** (borrar o mantener; #36) · baja · decisión del propietario anotada.

---

## G. Intervención 2026-10-21 (3.ª entrega): seguridad persistente, archivos y anti-inyección

Rama `repo/sharp-noether-tbr0bz`. Todo verificado con `npm run test:all` contra **MariaDB 10.11
real** (no dobles): 12 API · 24 ICMP · 47 rotación · 116 seguridad · 100 archivos.

**Resuelto de la sección D** (y de lo propuesto en F): JWT con `algorithms` fijado, scripts de
auto-puntuación retirados, `src/notifications/` fuera del control de versiones, `npm audit --omit=dev`
**0 vulnerabilidades** (`geoip-lite` 2.0.3), CI con MariaDB real (`.github/workflows/ci.yml`).
**No tocado a propósito:** `.env` (decisión del propietario).

| Problema (con evidencia) | Corrección |
|---|---|
| "Triple cifrado" con la **misma clave** en las 3 capas (verificado) | AES-256-GCM `v4` con HKDF; lectura del formato antiguo; la rotación lo migra |
| Niveles de cifrado volcaban IV, etiqueta, hash de clave y texto cifrado al log | Sin logs criptográficos (prueba que captura consola) |
| **Bloqueo de cuenta inoperante** (clave `usuario_IP` vs consulta por `usuario`; 20 fallos → no bloqueaba) | Bloqueo en `login_attempts`; prueba end-to-end |
| Estado de seguridad en `Map`/`Set` por proceso | Tablas `rate_limit_counters`, `blocked_ips`, `login_attempts`, `security_events`; prueba con **dos procesos** |
| Sin `trust proxy` | `TRUST_PROXY`; IPv6 por /64 |
| TLS a BD `rejectUnauthorized:false` + caída silenciosa a sin TLS | `DB_SSL=verify` por defecto en producción |
| Riesgo de login con fallos de toda la plataforma; login más rápido si el usuario no existe | Por usuario; bcrypt siempre |
| `autoProtect` montado dos veces en `/api/auth` (doble conteo) | Solo global |
| Detector con regex que bloqueaban 24 h por texto legítimo (`on\w+=`, `exec(`) | Reglas por severidad, normalización anti-evasión, rechazo por ubicación, strikes |
| Registro volcaba usuario/email de la petición al log en el error | Eliminado |
| Sin API de archivos | `/api/files` (ver `docs/SEGURIDAD.md` §5) |
| `quick-fix.js` reescribía `anomaly-detection`/`secure-auth`/`auth.controller` con código antiguo | Eliminado |
| Sin índice único en `users.username_hash` (registro concurrente duplicaba) | Migración 006 + 409 en carrera (prueba con 3 registros simultáneos) |

**Pendiente:** ver la sección H (lo que quedaba aquí se resolvió en la entrega siguiente).

---

## H. Intervención 2026-10-21 (4.ª entrega): lo que seguía pendiente

Rama `repo/sharp-noether-tbr0bz`. Detalle y límites honestos en `docs/SEGURIDAD.md` §10–§22.

| Pendiente | Qué se hizo | Límite que se mantiene |
|---|---|---|
| MFA | TOTP (RFC 6238) + 10 códigos de recuperación, anti-reutilización atómica, reto de 5 min que no vale como sesión, `MFA_REQUIRED_FOR_ADMINS` | Sin WebAuthn |
| SSO | OpenID Connect (code + PKCE), state/nonce en BD, defensa mix-up, solo algoritmos asimétricos, sin enlazado por email | Sin SAML; probado contra un IdP simulado |
| KMS/HSM | Secretos del `.env` envueltos (`file`, Vault Transit, AWS KMS); arranque falla cerrado; rotación compatible | Protege el `.env`/backups, no la memoria del proceso en marcha |
| Antivirus | ClamAV `INSTREAM` durante el cifrado, `off/optional/required`, `npm run rescan-files` | Basado en firmas |
| Copias de `FILES_DIR` | Incremental, verificación por hash, retención, restauración, cruce BD↔disco | La prueba de restauración periódica es tuya |
| Pentest/certificaciones | Paquete de preparación: ESLint security, CodeQL, gitleaks, SBOM, ZAP, OpenAPI, sqlmap, matriz ASVS/SOC 2/ISO | **No sustituye** a un pentest externo ni a una auditoría |
| Bloqueo de cuenta abusable | Bloqueo por (usuario, origen) + global con orígenes de confianza + desbloqueo admin | Ataque distribuido + dueño desde origen nuevo: ≤15 min o desbloqueo admin |

Hallazgos reales durante el trabajo: la copia sobrescribía una copia buena con un original truncado (corregido); la descarga de un
archivo ausente/truncado cortaba la conexión (ahora se autentica el primer bloque antes de enviar cabeceras); caracteres
bidireccionales literales en `file-types.js` detectados por el lint (corregido).

---

## I. Intervención 2026-10-27 (5.ª entrega): lo que faltaba tras la puntuación 7,5/10

Misma rama y PR. Detalle y límites en `docs/SEGURIDAD.md` §15–§22.

| Petición | Qué se hizo | Límite que se mantiene |
|---|---|---|
| Sesiones más cortas **sin** iniciar sesión a cada cambio + cerrar todas | JWT de 15 min + refresh token opaco con rotación y detección de reutilización (revoca la sesión), inactividad 7 d / tope 30 d, `logout-all`, lista y cierre de sesiones | El cliente debe guardar bien el refresh token y serializar las renovaciones |
| Los 5 puntos de seguridad | **KMS por archivo** (`KMS_DATA_KEYS`, `kms1:` ligado al archivo, CLI migrate/unmigrate/rewrap); **WebAuthn**, **SAML 2.0** y **roles finos** (`user/auditor/operator/admin`); **aprobación de dos administradores** (reset MFA, borrado); **imágenes recodificadas** y **PDF sin contenido activo**; detector de inyección solo bloquea en rutas críticas | Probado contra simuladores, no contra IdP/KMS reales; solo imágenes y PDF se sanean |
| Operación y observabilidad **solo admin** | Alertas automáticas + webhook firmado + panel JSON; métricas Prometheus y trazas OTLP con `X-Request-Id`; exportar/borrar datos personales; plan de respuesta a incidentes y custodia de claves | Sin interfaz web propia; las copias existentes conservan los datos borrados hasta caducar |
| Cobertura y fuzzing | `npm run coverage` (c8) con umbral en CI; `test_fuzz.js` (fast-check, 18 propiedades, incluye **todas las rutas del OpenAPI** con 3 roles) y `fuzz.yml` nocturno | Property-based, no un fuzzer guiado por cobertura; la cobertura no mide corrección |
| CI | Acciones fijadas por SHA, permisos mínimos, cancelación de ejecuciones obsoletas, *timeouts*, `dependency-review`, puerta de ZAP (riesgo alto), trabajo `production-install` | Los workflows no se han podido ejecutar fuera de GitHub |
| Quitar nodemon en producción | Solo `devDependencies`; `npm run dev` se niega con `NODE_ENV=production`; `install.js --production` usa `--omit=dev`; `check:prod-deps` en CI | — |

**Hallazgos reales del fuzzing** (corregidos, con prueba fija): un id de sesión enorme (`/api/auth/sessions/99999999999999999999`) daba 500 porque el validador aceptaba
enteros no seguros; un cuerpo multipart sin cierre **tumbaba el proceso entero** (busboy emite `error` directamente en el stream del archivo sin listener).
Otros hallazgos de esta entrega: node-saml aceptaba `Recipient`/`Destination`/`Status`
distintos (comprobaciones propias añadidas), y la erradicación de un usuario dejaba un evento de aprobación con su `user_id`.

---

## J. Intervención 2026-10-27 (6.ª entrega): interfaz web y escalabilidad

Misma rama y PR. Detalle en `docs/SEGURIDAD.md` §23 y §24.

| Petición | Qué se hizo | Límite que se mantiene |
|---|---|---|
| Interfaz web React/Next.js para operación y observabilidad | `web/`: Next.js 16 + React 19. BFF con cookie `httpOnly` cifrada (los tokens no llegan al JavaScript), lista cerrada de rutas, CSRF, CSP con nonce; panel, alertas, aprobaciones, eventos (CSV), IP, usuarios/sesiones, datos personales, métricas y sistema. 43 pruebas unitarias + 15 de extremo a extremo con el API real y Chromium; job `web` en el CI | Solo admin; sin passkeys ni SSO en la interfaz; sondeo, no tiempo real |
| Mejorar la escalabilidad | `src/cluster.js` (workers, relanzado, reinicio en caliente, cierre ordenado, métricas agregadas); líder único para las tareas periódicas; `/health/ready`; limitador de una sentencia; caché de 1 s de IP bloqueadas; medido con `benchmarks/scale-bench.js`: **×1,9 con 2 workers y ×2,2–2,3 con 4** en 4 vCPU compartidos, +12 % en proceso único | Medido en UNA máquina de 4 vCPU; `FILES_DIR` sigue siendo disco local (volumen compartido con varias máquinas); el cuello pasa a MariaDB |

**Correcciones a lo dicho antes**: la documentación afirmaba «~3 consultas por petición protegida»; medido con el registro de MariaDB eran 4 (ahora 2–3). Hallazgos reales: un
`GET_LOCK` en una conexión retenida habría tumbado el proceso al caerse la conexión (sin listener de `error`); en el cluster, prom-client solo responde a la agregación si el worker construye un
`AggregatorRegistry` (daba 500); el reparto round-robin perdía conexiones al reiniciar en caliente (ahora socket compartido); y cerrar las conexiones ociosas al instante daba resets.

---

## K. Entregas 3–6 en el formato de la bitácora (#8–#20)

Las entregas 3–6 (secciones G–J) se registraron como tablas resumen. Aquí van con el formato de la sección B, revisadas el 2026-11-09
(revisión estática del código y resultados del CI del 27-oct; las pruebas citadas existen y pasaron en ese CI).

**Estado al 2026-11-09 de las entradas #1–#7:** #1 PruebasLinux 8/10 (ampliado en #26) · #2 suite de pruebas 7→9/10 (CI con MariaDB,
~430 casos) · #3 análisis estático 7→8/10 (JWT con algoritmo, CodeQL y lint en CI) · #4/#6 dependencias 7→9/10 tras #21/#23 · #5 secretos
5→6/10 (credencial filtrada encontrada, #22) · #7 instalador 8/10 (`--production`; exige Node ≥ 22 desde #25).

### #8 — Seguridad persistente en MySQL (2026-10-21)
- **Estado:** completado.
- **Archivos y módulos revisados:** `src/middleware/protection.middleware.js`, `src/security/{rate-limiter,anomaly-detection,secure-auth}.service.js`, migraciones 004–007.
- **Problema detectado:** límites, bloqueos e intentos en `Map`/`Set` por proceso; bloqueo de cuenta inoperante (clave `usuario_IP` vs consulta por usuario); sin `trust proxy`.
- **Acciones realizadas:** todo el estado en tablas; bloqueo por (usuario, origen) y global; `TRUST_PROXY`; TLS a la BD verificado en producción.
- **Pruebas ejecutadas:** `test_security.js` (57) y `test_scale.js` (11), con dos procesos reales.
- **Puntuación:** 9/10 — el estado se comparte entre procesos y réplicas (además probado en #25 con contenedores).
- **Problemas restantes:** la caché de bloqueo (1 s) retrasa un bloqueo hecho por OTRA instancia hasta ese tiempo (documentado).
- **Siguiente mejora:** ninguna urgente. *(Prioridad baja.)*

### #9 — Cifrado v4 y rotación de claves
- **Estado:** completado.
- **Archivos y módulos revisados:** `src/crypto/*`, `src/maintenance/*`, `src/backup/*`, `scripts/rotateKeys.js`.
- **Problema detectado:** «triple cifrado» con la misma clave en las tres capas y claves que cambiaban cada día.
- **Acciones realizadas:** AES-256-GCM `v4` con HKDF; lectura del formato antiguo; rotación con backup previo, re-cifrado transaccional y recuperación.
- **Pruebas ejecutadas:** `test_rotation.js` (48) contra MariaDB y MySQL; `kill -9` en 44 instantes; 8 escritores concurrentes.
- **Puntuación:** 8/10 — robusta y probada; limitada en tamaño.
- **Problemas restantes:** la clave maestra se deriva de semillas del entorno; la rotación necesita ≈7× la BD en RAM.
- **Siguiente mejora:** rotación en streaming por lotes. *(Prioridad media.)*

### #10 — Anti-inyección
- **Estado:** completado.
- **Archivos y módulos revisados:** `src/security/injection-detector.js`, `src/config/sql.js`.
- **Problema detectado:** reglas que bloqueaban 24 h por texto legítimo.
- **Acciones realizadas:** reglas por severidad, normalización contra evasión, bloqueo solo en rutas críticas; prueba que falla si alguien interpola SQL.
- **Pruebas ejecutadas:** `test_security.js`, `test_fuzz.js` (sin ReDoS, ataques ofuscados), sqlmap (`docs/PENTEST-AUTOEVALUACION.md`).
- **Puntuación:** 8/10 — la defensa real son los parámetros; el detector es una capa adicional evadible.
- **Problemas restantes:** reglas conocidas. **Siguiente mejora:** ninguna. *(Prioridad baja.)*

### #11 — Archivos: subida, antivirus, saneado, copias y claves en el KMS
- **Estado:** completado (modo S3 añadido en #25).
- **Archivos y módulos revisados:** `src/files/*`, `src/api/controllers/files.controller.js`, `src/crypto/file-keys.js`.
- **Problema detectado:** no existía API de archivos.
- **Acciones realizadas:** tipo por contenido, ClamAV en streaming, imágenes recodificadas, PDF sin contenido activo, cifrado por archivo y bloque, copias de `FILES_DIR`, claves envueltas por el KMS.
- **Pruebas ejecutadas:** `test_files` (41), `test_sanitize` (16), `test_av` (16), `test_files_backup` (10), `test_kms_files` (12).
- **Puntuación:** 8/10. **Problemas restantes:** audio, vídeo y texto sin sanear. **Siguiente mejora:** despojar metadatos. *(Baja.)*

### #12 — Autenticación: sesiones, MFA, WebAuthn, OIDC, SAML
- **Estado:** completado (ampliado en #22 y #24).
- **Archivos y módulos revisados:** `src/security/{secure-auth,mfa,webauthn}.service.js`, `src/sso/*`.
- **Problema detectado:** JWT de 5 días sin refresh; sin segundo factor robusto ni SSO.
- **Acciones realizadas:** JWT 15 min + refresh opaco con rotación y reutilización detectada; TOTP, passkeys, códigos de recuperación; OIDC (PKCE) y SAML.
- **Pruebas ejecutadas:** `test_sessions` (15), `test_mfa` (15+1), `test_webauthn` (24), `test_sso` (19+4), `test_saml` (22+1).
- **Puntuación:** 8/10 — probado contra simuladores que firman de verdad, no contra proveedores reales.
- **Problemas restantes:** HIBP, límite de sesiones simultáneas. **Siguiente mejora:** preproducción con un IdP real. *(Media.)*

### #13 — Autorización: roles finos y dos administradores
- **Estado:** completado. **Archivos:** `src/security/permissions.js`, `admin-approvals.service.js`, `role.middleware.js`.
- **Problema detectado:** solo `user`/`admin`; acciones destructivas de una sola persona.
- **Acciones realizadas:** `user/auditor/operator/admin` con permisos explícitos; aprobación de un segundo admin, atómica y con caducidad.
- **Pruebas ejecutadas:** `test_rbac` (13), e2e de aprobaciones; en #24, dos administradores aprobando a la vez (e2e, CI verde 10-nov).
- **Puntuación:** 9/10. **Problemas restantes:** multi-organización. **Siguiente mejora:** diseño de tenencia. *(Media.)*

### #14 — KMS para secretos y claves de archivo
- **Estado:** completado (Windows corregido en #21). **Archivos:** `src/crypto/kms*.js`, `scripts/kms.js`.
- **Problema detectado:** semillas en claro en el `.env`.
- **Acciones realizadas:** proveedores `file`, Vault Transit y AWS KMS; arranque que falla cerrado; claves de archivo `kms1:`.
- **Pruebas ejecutadas:** `test_kms` (16, también en Windows tras #21), `test_kms_files` (12).
- **Puntuación:** 7/10 — solo contra simulaciones; la clave maestra sigue en memoria del proceso.
- **Siguiente mejora:** probar con un KMS real; HSM por operación si el riesgo lo exige. *(Media.)*

### #15 — Operación y observabilidad
- **Estado:** completado (en vivo en #24; librería de métricas en #25). **Archivos:** `src/security/{alerts,dashboard,privacy}.service.js`, `src/observability/*`.
- **Problema detectado:** sin alertas, panel ni métricas.
- **Acciones realizadas:** alertas por umbral con webhook firmado, panel JSON, Prometheus, OTLP, exportación y borrado de datos personales, planes de incidentes y custodia.
- **Pruebas ejecutadas:** `test_ops` (21 + 4 del stream y el cluster, estas en CI verde desde el 10-nov).
- **Puntuación:** 8/10. **Problemas restantes:** envío a SIEM. **Siguiente mejora:** exportador a SIEM. *(Baja.)*

### #16 — CI, cobertura y fuzzing
- **Estado:** completado (ampliado en #23, #25 y #26). **Archivos:** `.github/workflows/*`, `.c8rc.json`, `test_fuzz.js`.
- **Problema detectado:** CI sin BD real, sin cobertura ni fuzzing.
- **Acciones realizadas:** MariaDB y ClamAV reales, umbral de cobertura, fast-check (18 propiedades), acciones fijadas por SHA, ZAP, SBOM, gitleaks, CodeQL.
- **Pruebas ejecutadas:** el propio CI (verde en las fases 0–2 de #21–#23).
- **Puntuación:** 8/10. **Problemas restantes:** Dependency graph sin activar; trivy/hadolint. **Siguiente mejora:** ver §F. *(Baja.)*

### #17 — Escalabilidad en una máquina (cluster)
- **Estado:** completado (varias réplicas en #25). **Archivos:** `src/cluster.js`, `src/tasks/leader.js`.
- **Problema detectado:** un solo proceso; N instancias ejecutaban N planificadores.
- **Acciones realizadas:** cluster con reinicio en caliente, un solo líder, `/health/ready`, limitador de una sentencia.
- **Pruebas ejecutadas:** `test_scale` (11); `bench:scale`: ×2,2–2,3 con 4 workers en 4 vCPU.
- **Puntuación:** 8/10. **Siguiente mejora:** hecho en #25 (réplicas, S3, réplica de lectura, particiones).

### #18 — Interfaz web de operación (6.ª entrega)
- **Estado:** completado (ampliado en #24). **Archivos:** `web/`.
- **Problema detectado:** sin interfaz; tokens en el navegador si se hacía a mano.
- **Acciones realizadas:** BFF con cookie `httpOnly` cifrada, lista cerrada, CSRF, CSP con nonce, 9 páginas.
- **Pruebas ejecutadas:** 43 unitarias y 15 e2e (Chromium) en CI.
- **Puntuación:** 8/10 entonces. **Siguiente mejora:** hecho en #24.

### #19 — Pruebas de carga (PR #6)
- **Estado:** completado. **Archivos:** `benchmarks/`.
- **Problema detectado:** rendimiento no evaluado.
- **Acciones realizadas:** 1 millón de peticiones (0 errores), API de estrés con topes de CPU/RAM, informe honesto (GPU no medida).
- **Pruebas ejecutadas:** las del informe `benchmarks/INFORME_RENDIMIENTO.md`.
- **Puntuación:** 7/10. **Problemas restantes:** el interruptor `DISABLE_IP_BLOCKING` funcionaba en producción (corregido en #22).

### #20 — Documentación (estado a 2026-11-09 por la mañana)
- **Estado:** completado en #27. **Archivos:** `README.md`, `docs/*`, esta bitácora.
- **Problema detectado:** README con 28 rutas sin documentar, «JWT 5 días», «migraciones 004-010», «cifrado multicapa» y 4300 líneas de código histórico; esta bitácora sin el formato de B para las entregas 3–6.
- **Acciones realizadas / pruebas / puntuación:** ver #27.

---

## L. Intervención 2026-11-09: plan de cierre (#21–#29)

Plan aprobado por el propietario con estas decisiones: `.env` se queda (datos de prueba); MariaDB no está instalada en el equipo (lo que
necesita BD se verifica en CI); archivos en S3 con un driver propio; interfaz web con alcance completo; un PR por fase.

### #21 — Fase 0: punto de recuperación y `main` en verde
- **Estado:** completado (CI verde en `a5b9b05`).
- **Archivos y módulos revisados:** `package-lock.json`, `.github/workflows/ci.yml`, `src/crypto/kms-providers.js`, `test_kms.js`.
- **Problema detectado:** `CI / test` en rojo en `main` con el mismo árbol que pasó el 27-oct: el último paso (`npm audit --omit=dev --audit-level=high`) falló por GHSA-mrwp-f3q8-3g9p en `follow-redirects` 1.16.1 (vía `axios`), publicado después. En local (Windows), 11 fallos de `test_kms`: los bits de modo no reflejan las ACL de NTFS y el proveedor `file` rechazaba cualquier KEK.
- **Acciones realizadas:** tag `pre-cierre-2026-11`; `npm audit fix` (solo el lockfile); comprobación de permisos de la KEK solo en POSIX (en Windows se documenta `icacls`).
- **Pruebas ejecutadas:** CI `test`, `web`, `production-install` en verde; local `test_kms` 16/16, `test:api` 13/13, `test:icmp` 24/24, lint 0.
- **Puntuación:** 9/10 — causa raíz encontrada (no era el código) y corregida con un cambio mínimo.
- **Problemas restantes:** ninguno. **Siguiente mejora:** —.

### #22 — Fase 1: seguridad pendiente y limpieza
- **Estado:** completado (CI verde en `b1863b6`; la alerta de CodeQL hay que descartarla en GitHub).
- **Archivos y módulos revisados:** `protection.middleware.js`, `index.js`, `mfa.service.js`, `.gitleaksignore`, raíz del repositorio.
- **Problema detectado:** `DISABLE_IP_BLOCKING=true` desactivaba bloqueos y límites de login también en producción; CodeQL `js/user-controlled-bypass` en `mfa.service.js:101`; gitleaks en los PR por un secreto de pruebas de `600be88`; `fix-system.js` y 8 marcadores de «score 100» seguían ahí; **`test.js` con credenciales reales de una BD remota**; `health-check` que imprimía «Sistema funcionando» sin comprobar nada.
- **Acciones realizadas:** el servidor no arranca y el middleware ignora el bypass con `NODE_ENV=production`; `mfa.verify` exige exactamente un factor de tipo texto (antes, con los dos, elegía el de recuperación en silencio); fingerprints de gitleaks; restos y `test.js` eliminados; `scripts/healthCheck.js` consulta `/health/ready`.
- **Pruebas ejecutadas:** `test:api` 15/15 (2 nuevas: bypass y MFA, con el limitador caído responde 503); `test_mfa` +1 en CI; health-check con y sin servidor; lint 0.
- **Puntuación:** 8/10 — los fallos reales quedan cerrados; la contraseña filtrada sigue válida hasta que el propietario la cambie.
- **Problemas restantes:** rotar la credencial; descartar la alerta de CodeQL. **Siguiente mejora:** ver §F 1 y 3. *(Crítica / baja.)*

### #23 — Fase 2: dependencias
- **Estado:** completado (CI verde en `bed6619`).
- **Archivos y módulos revisados:** workflows, `package*.json`, `web/package*.json`, `test_fuzz.js`.
- **Problema detectado:** 13 ramas de Dependabot sin revisar, algunas mayores.
- **Acciones realizadas:** acciones (checkout 7, setup-node 7, CodeQL 4, gitleaks 3, ZAP 0.10); express 5.3, winston 3.19, aws-sdk; eslint 10 + eslint-plugin-security 4 (13 reglas activas comprobadas), fast-check 4 (`fullUnicodeString` → `string({unit})`); next 16.4.5, TypeScript 7, vitest 5.1, @types/node.
- **Pruebas ejecutadas:** lint 0 y reglas detectando `require`/`RegExp`/`eval` no literales; fuzz 16/16; web typecheck + 43 + build; CI verde.
- **Puntuación:** 9/10. **Problemas restantes:** las ramas de Dependabot se cerrarán solas al fusionar. **Siguiente mejora:** —.

### #24 — Fase 3: interfaz web completa
- **Estado:** completado — CI verde (10-nov) tras las correcciones de #29.
- **Archivos y módulos revisados:** `web/`, `src/sso/*`, `src/api/controllers/{sso,saml,system}.controller.js`, `src/cluster.js`, `src/index.js`.
- **Problema detectado:** sin passkey ni SSO en la interfaz; datos por sondeo; `Sistema` describía solo el proceso que atendía. Además, el SSO del API entregaba los tokens en el fragmento de la URL (visibles para el JavaScript), incompatible con el BFF.
- **Acciones realizadas:** entrega SSO por código de un solo uso ligado al navegador (migración 017, `POST /api/sso/exchange`, robo → evento crítico); `GET /api/system/stream` (SSE con cursor, revalidación cada 30 s, límites, cierre ordenado); estado de todos los workers; en la web: passkey (segundo factor), SSO OIDC/SAML, en vivo (panel, alertas, aprobaciones, «N eventos nuevos», avisos), tabla del cluster y mejoras de accesibilidad.
- **Pruebas ejecutadas:** web 57/57 (14 nuevas, con dos mutaciones que las hacen fallar); typecheck y build; `test:api` 15/15 con la OpenAPI al día; IPC del cluster con workers simulados. Escritas para el CI: `test_sso` +4, `test_saml` +1, `test_ops` +4, `test_scale` +1 aserción, e2e `live-auth.test.cjs` (en vivo, passkey, SSO, concurrencia, axe, Firefox y WebKit).
- **Puntuación:** 8/10 confirmada — el CI encontró dos fallos reales de la interfaz (contraste y carrera al cerrar sesión), ya corregidos y cubiertos por las e2e.
- **Problemas restantes:** SSO solo contra un proveedor simulado; passkey solo como segundo factor. **Siguiente mejora:** §F 4. *(Media.)*

### #25 — Fase 4: escalabilidad
- **Estado:** completado — CI verde (10-nov) tras las correcciones de #29.
- **Archivos y módulos revisados:** `src/files/*`, `src/config/database.js`, `src/security/{dashboard,security-events}.service.js`, `src/observability/metrics.js`, `src/cluster.js`.
- **Problema detectado:** `FILES_DIR` local obligaba a un volumen compartido; sin prueba con varias réplicas; MariaDB como cuello; `security_events` purgada con DELETE; `prom-client` sustituido; Node 18/20 fuera de soporte.
- **Acciones realizadas:** `FILES_STORAGE=s3` (una petición con Range por descarga; integridad igual); Dockerfile de producción y `deploy/docker-compose.yml` (2 réplicas + nginx + MariaDB + SeaweedFS; MinIO se descartó porque sus imágenes dejaron de publicarse en Docker Hub) con job `compose`; `DB_READ_HOST` (solo análisis, con vuelta a la principal); particionado mensual opcional; `@prometheus-io/client` (agregación entre procesos comprobada igual que con prom-client); Node ≥ 22.
- **Pruebas ejecutadas:** `test_s3` 5/5 en local (cifrado en el bucket, rangos con una petición, byte alterado/truncado/ausente, servidor que ignora Range, fallo de subida, configuración); fuzz 16/16 y `test_files` sin BD tras reescribir `decryptRange`; prueba anti-interpolación SQL; compose validado con `docker compose config`. Escritas para el CI: `test_files_s3`, `test_partitions`, `test_compose`.
- **Puntuación:** 8/10 confirmada — el CI encontró dos errores reales (el API no arrancaba en el contenedor y el `ALTER TABLE` de las particiones tenía un error de sintaxis), ya corregidos.
- **Problemas restantes:** el compose usa TLS desactivado hacia la BD y `S3_SSE=none` (red interna; los archivos ya van cifrados), documentado. **Siguiente mejora:** §F 2 y 6. *(Alta / media.)*

### #26 — Fase 5: PruebasLinux
- **Estado:** completado — CI verde (10-nov; semgrep 1.181.1, ver #29).
- **Archivos y módulos revisados:** `PruebasLinux/lib/core.sh`, `modules/*`, `.github/workflows/ci.yml`.
- **Problema detectado:** sin semgrep; nada de lo nuevo (refresh, SSO, BFF, Docker) tenía comprobación; PruebasLinux no corría en CI.
- **Acciones realizadas:** opciones 118–126 en un módulo que se carga el último (1–117 sin renumerar); reglas Semgrep propias; job `pruebaslinux` (informe + puerta).
- **Pruebas ejecutadas:** `bash -n`; `--list` = 126; 119/120/121/124 en verde contra el código real; YAML validado. La regla de `child_process` se corrigió antes de usarla: habría marcado cualquier `RegExp.exec`.
- **Puntuación:** 8/10. **Problemas restantes:** trivy y hadolint en CI. **Siguiente mejora:** §F 7. *(Baja.)*

### #27 — Fase 6: documentación
- **Estado:** completado.
- **Archivos y módulos revisados:** `README.md`, `ReadmeLogsMejoras.md`, `docs/SEGURIDAD.md`, `web/README.md`, `PruebasLinux/ReadmeLogMejoras.md`, `.env.example`.
- **Problema detectado:** ver #20.
- **Acciones realizadas:** README de 4979 a 560 líneas (guía de 2025 en `docs/historico/GUIA-ORIGINAL.md`); tabla de endpoints generada desde la OpenAPI con `npm run docs:endpoints` y **una prueba que falla si se desincroniza**; afirmaciones desfasadas corregidas; variables nuevas en `.env.example`; §13, §22, §23 y §24 de SEGURIDAD; esta bitácora con A–F al día y #8–#28 en formato.
- **Pruebas ejecutadas:** `test:api` 16/16 (incluye README = OpenAPI = código).
- **Puntuación:** 9/10 — la documentación de la API ya no puede quedarse atrás sin que falle una prueba; el resto depende de revisión.
- **Problemas restantes:** ninguno (cifras de las fases 3–6 actualizadas con el CI en #29). **Siguiente mejora:** —.

### #28 — Fase 7: validación final
- **Estado:** completado (10-nov).
- **Archivos y módulos revisados:** todo lo anterior.
- **Problema detectado:** `git push` de `cierre/3-web` se quedaba esperando: el Git Credential Manager tiene 3 cuentas de GitHub guardadas y pedía elegir una en cada subida (sin interactividad: «Cannot prompt because user interactivity has been disabled»).
- **Acciones realizadas:** verificación local de todo lo que no necesita MariaDB ni navegadores (ver #21–#27); cuenta del repositorio fijada en su configuración local (`credential.https://github.com.username`); ramas subidas **en orden** y cada corrección propagada por merge (sin reescribir la historia publicada); cadena `main → 0 → … → 6` comprobada.
- **Pruebas ejecutadas:** locales: lint 0, `test:api` 16/16, `test_s3` 5/5, fuzz 16/16, `test_kms` 16/16, web 57/57 + typecheck + build, PruebasLinux 126 opciones; **CI verde de todas las fases** (`test`, `web`, `compose`, `pruebaslinux`, `production-install`).
- **Puntuación:** 9/10 — todo verificado donde puede verificarse (CI con MariaDB, navegadores y Docker reales); falta lo que solo puede hacer el propietario (§F 1 y 3).
- **Problemas restantes:** rotar la contraseña filtrada; descartar la alerta de CodeQL; fusionar por fases. **Siguiente mejora:** §F 1–3. *(Crítica / alta.)*

### #29 — Correcciones que pidió el primer CI de las fases 3–6
- **Estado:** completado (10-nov; CI verde en `cierre/3-web`, `cierre/4-escala`, `cierre/5-pruebaslinux` y `cierre/6-docs`).
- **Archivos y módulos revisados:** registros de cada job. Los completos de GitHub exigen iniciar sesión, así que los pasos que fallan
  publican sus líneas clave como **anotaciones**, que se leen con la API pública (`.github/scripts/annotate-log.sh`).
- **Problema detectado** (16, por tipo):
  - **Errores reales del código o la interfaz (4):** (1) el API **no arrancaba en el contenedor**: creaba `src/notifications` al cargar
    y ahí el código es de solo lectura; (2) el `ALTER TABLE` del particionado tenía una **coma antes de `PARTITION BY`** (error de
    sintaxis en MariaDB: nunca habría funcionado); (3) **accesibilidad**: etiquetas «ok» con contraste 4,46:1 (< 4,5) y tablas o bloques
    desplazables sin foco de teclado; (4) **carrera al cerrar sesión**: un 401 de una petición en curso mandaba a `/login?expired=1`.
  - **Entorno (3):** las imágenes de **MinIO dejaron de publicarse** en Docker Hub; SeaweedFS rechaza el cifrado del lado del servidor
    sin configurar (`S3_SSE`); **semgrep 1.95** ya no arranca en el runner (`pkg_resources`).
  - **Las propias pruebas (9):** `production-install` cargaba `prom-client`; `test_ops` usaba administradores cuyas sesiones cerraba
    una prueba anterior (`revoke-all`); e2e de passkey (el alta responde 201 y el método de sesión es `hwk`, RFC 8176); e2e de SSO
    (Playwright no intercepta peticiones que llegan por redirección); `test_sessions` intermitente (el token renovado también duraba
    1,2 s); `test_partitions` esperaba borrar `p_hist` con datos aún dentro de la retención; `test_compose` perdía trozos del SSE
    (lectura en carrera con un temporizador) y buscaba al líder por HTTP (el proceso con el cerrojo puede no recibir peticiones).
- **Acciones realizadas:** `NOTIFICATIONS_DIR` (en Docker `/app/data/notifications`) y fallo no fatal; coma eliminada; color «ok»
  `#146c3a` (5,75:1) y `tabIndex={0}` en tablas y bloques; `beginLeave()` antes de cerrar sesión; **SeaweedFS 4.51** + aws-cli 2.38.6
  en el compose (`S3_ACCESS_KEY`/`S3_SECRET_KEY`, `S3_SSE=none` documentado); semgrep 1.181.1; el proveedor OIDC simulado atiende
  `/authorize`; el líder se comprueba con `IS_USED_LOCK` en la BD; el resto, pruebas corregidas sin rebajar lo que comprueban.
- **Pruebas ejecutadas:** CI completo en verde en las cuatro ramas (API con MariaDB 10.11; e2e en Chromium, Firefox y WebKit + axe;
  imagen construida y 2 réplicas tras nginx con SeaweedFS; PruebasLinux con semgrep); web 57/57 y typecheck en local.
- **Puntuación:** 9/10 — cada fallo se corrigió en la fase donde nacía y se propagó en orden. De los 16, 4 eran errores reales que solo
  un entorno real podía mostrar.
- **Problemas restantes:** CodeQL (falso positivo, descartar en GitHub); SSO, KMS y S3 solo contra simuladores o SeaweedFS.
  **Siguiente mejora:** §F 3 y 4. *(Baja / media.)*

## M. Intervención 2026-11-10/12: MariaDB local, instalador con ClamAV, adaptador de base de datos y revisión (#30–#34)

Rama `cierre/8-bd` (#30) y rama `instalador` (#31, #32). Cada commit se sube a su rama **y** a `main` por avance rápido.

### #30 — MariaDB 13.1 local y pruebas compatibles con Windows
- **Estado:** completado (10-nov).
- **Archivos y módulos revisados:** `database/setup-local.sql` (nuevo), `test_files.js`, `test_files_backup.js`, `test_rotation.js`,
  `test_scale.js`, `CLAUDE.md`.
- **Problema detectado:** el propietario instaló **MariaDB 13.1.1** en Windows; la suite completa dio **578 bien y 8 fallos**, todos
  por suponer Linux: permisos `0600` (NTFS no tiene bits de modo: siempre `0666`), una ruta «imposible» (`/dev/null/…`) que en Windows
  sí se crea, el reparto del cluster (con `SCHED_NONE` Windows entrega todas las conexiones a un worker) y `SIGHUP`/`SIGTERM`
  (no existen o terminan el proceso a la fuerza).
- **Acciones realizadas:** bases y usuario de pruebas iguales que en el CI con `setup-local.sql` (lo ejecuta el propietario con su
  cuenta de administrador; el proyecto no usa la contraseña de root); permisos comprobados solo en POSIX; «disco no escribible» con
  un archivo usado como carpeta (falla en los dos sistemas); `CLUSTER_SCHEDULING=rr` en Windows; `SIGHUP` y cierre ordenado se
  siguen probando en Linux/CI. Nada se rebaja en Linux.
- **Pruebas ejecutadas:** local (Windows + MariaDB 13.1): los 4 archivos afectados 168/170 (2 omitidas con motivo) y el cluster 3/3 + 1
  omitida; suite completa al cierre de #32 (ver ahí).
- **Puntuación:** 8/10 — la suite completa ya corre en local; el CI sigue en MariaDB 10.11 (verde en uno no prueba el otro).
- **Problemas restantes:** ninguno propio. **Siguiente mejora:** #31 (ClamAV para las 5 pruebas que lo necesitan).

### #31 — Instalador con menú para Windows, Linux y macOS (Node, MariaDB, ClamAV y npm)
- **Estado:** completado en Windows (11-nov); Linux y macOS escritos pero **sin ejecutar** (no hay esos equipos en este entorno).
- **Archivos y módulos revisados:** `instalar.cmd`, `instalar.sh`, `instalar.command`, `instalador/{menu.ps1,windows.ps1,linux.sh,
  macos.sh,comun.sh,verificar-clamav.js}`, `install.js`, `install.sh`, `install.ps1`, `INSTALL.md`, `test_av.js`, `.gitattributes`.
- **Problema detectado:** el instalador de #7 suponía Node ya instalado, no cubría macOS ni instalaba MariaDB ni ClamAV; 5 pruebas
  del antivirus se omitían en local; las pruebas con clamd real solo sabían usar un socket Unix (Windows no lo tiene).
- **Acciones realizadas:** **programa base** que abre una terminal con el menú 1 Windows / 2 Linux / 3 macOS (`instalar.cmd`,
  `instalar.command` con doble clic, `instalar.sh`) y un instalador por sistema (winget con elevación UAC · apt/dnf/pacman con sudo
  solo para paquetes · Homebrew sin sudo), idempotentes y con registro en `instalador/registros/`. **ClamAV configurado por sistema**:
  clamd solo en `127.0.0.1:3310` (+ socket Unix en Linux/macOS), `StreamMaxLength 25M` (= `CLAMAV_MAX_BYTES`); servicios ClamD y
  FreshClam (Windows, arranque a elegir por la memoria), systemd con `ListenStream` en Debian/Ubuntu, agentes de launchd en macOS.
  `verificar-clamav.js` comprueba PING, versión y EICAR por INSTREAM, el mismo camino que el servidor. `test_av.js` arranca su clamd
  real también en Windows (TCP en `127.0.0.1` y puerto libre) y espera a que salga antes de borrar su carpeta (EPERM en Windows).
  `.gitattributes`: `*.sh`/`*.command` con LF y `*.cmd` con CRLF.
- **Pruebas ejecutadas:** sintaxis (`bash -n`, analizador de PowerShell, `node --check`), lint 0; **instalación real en Windows**:
  ClamAV 1.5.4 + firmas, servicios en marcha, verificación con EICAR detectado, npm y `web/`; tras reiniciar, `Start-Service ClamD` y
  verificación de nuevo correcta; `test_av.js` **23/23 sin omitidas** (dos ejecuciones).
- **Puntuación:** 8/10 — Windows probado de punta a punta; Linux y macOS sin ejecutar (sin `shellcheck` en este equipo).
- **Problemas restantes:** ejecutar `instalador/linux.sh` (Debian/Ubuntu y Fedora) y `instalador/macos.sh` en equipos reales.
  **Siguiente mejora:** un job del CI que ejecute `linux.sh --si --sin-mariadb` en Ubuntu. *(Media.)*

### #32 — Adaptador de base de datos (paso 1: driver MySQL) y primer SQL portable
- **Estado:** paso 1 completado (11-nov); pasos 2–4 en curso (`docs/BASES-DE-DATOS.md`, «Estado»).
- **Archivos y módulos revisados:** `src/config/database.js`, `src/config/sql.js`, `src/tasks/leader.js`,
  `src/maintenance/rotation.service.js` (usan una conexión retenida), las ≈ 230 consultas (inventario de `docs/BASES-DE-DATOS.md` §2).
- **Problema detectado:** el acceso estaba centralizado, pero `database.js` importaba `mysql2` directamente y el SQL es dialecto
  MySQL; tres consultas usaban `SUM(condición)`, que **falla** en PostgreSQL. La documentación apuntaba a `src/security/sql.js`, que
  no existe (es `src/config/sql.js`).
- **Acciones realizadas:** `src/config/db-drivers/` elige el motor con `DB_CLIENT` (mysql/mariadb por defecto; postgres/supabase da
  un error claro hasta tener su CI) y documenta el **contrato** que debe cumplir todo driver (el subconjunto de `mysql2` que usa el
  proyecto, también para la conexión retenida del líder: `destroy`, `on('error')`); `db-drivers/mysql.js` es el único archivo de `src/`
  y `scripts/` que importa el cliente. `SUM(CASE WHEN … THEN 1 ELSE 0 END)` en `live-stream.js`, `anomaly-detection.service.js` y
  `rate-limiter.service.js` (mismo resultado en MySQL). `DB_CLIENT` en `.env.example`; rutas corregidas en la documentación.
- **Pruebas ejecutadas:** `test_db.js` (nuevo, en `test:all` y por tanto en el CI): elección del motor, motores desconocidos
  rechazados, «un único punto de entrada», sin `SUM(condición)`, y el contrato contra MariaDB real (`[filas]`, `insertId`,
  `affectedRows` del canje de un solo uso, COMMIT/ROLLBACK, conexión retenida con `destroy`): **11/11**. **Suite completa en
  local** (Windows, MariaDB 13.1, ClamAV 1.5.4, 26 min): **602 pruebas, 601 bien, 0 fallos, 1 omitida** (`SIGHUP`, que Windows no
  tiene). Una primera ejecución dio 2 fallos falsos en `test_fuzz.js` porque se lanzó `test_db.js` a la vez y `prepareDatabase()`
  recrea la base: las pruebas con BD se ejecutan en serie. **CI no comprobado** desde aquí (la API pública de GitHub no respondió).
- **Puntuación:** 8/10 — sin cambio de comportamiento y con red de seguridad; PostgreSQL aún no existe, así que no se afirma.
- **Problemas restantes:** pasos 2–4 (helpers de intervalos/upsert/cerrojos, esquema de PostgreSQL con prueba de paridad, driver `pg`
  y job del CI). **Siguiente mejora:** paso 2. *(Media.)*

### #33 — Revisión del código: claves sin valores conocidos, código muerto fuera y propuestas priorizadas
- **Estado:** completado (12-nov); propuestas pendientes de decisión del propietario. Informe: `docs/REVISION-CODIGO-2026-11.md`.
- **Archivos y módulos revisados:** `src/` (92 archivos), `scripts/` (14), `web/src/` (52, patrones de seguridad), `.env` (solo las líneas
  `NODE_ENV` y `KEY_EPOCH`), dependencias (`npm audit`, `npm outdated`) y cobertura por archivo.
- **Problema detectado:** (1) el `.env` local tiene `NODE_ENV=production` sin `KEY_EPOCH`: claves `legacy`, que **cambian cada día**
  (lo cifrado hoy no se descifra mañana) y el servidor arranca así; (2) `getSecret()` devolvía una clave fija y pública si faltaba un
  secreto; (3) en modo `legacy` sin `BASE_SEED` las claves salían de `default_seed_change_this`, alcanzable desde `rotateKeys` y
  `emergencyRecovery`; (4) ≈ 320 líneas de código muerto (limpieza que borraba usuarios y registraba hashes y cifrados, re-cifrado
  masivo fuera de la herramienta de rotación, `secureQuery` que contaba mal). Más 10 propuestas de rendimiento, mantenibilidad y pruebas.
- **Acciones realizadas:** `getSecret()` lanza si falta el secreto; `BASE_SEED` obligatoria también en `legacy` (la fórmula antigua sin
  `JWT_SEED` se mantiene para los datos existentes); código muerto eliminado de `auth.controller.js` y `database.js`. La corrección (3)
  destapó que `test_api.js` cargaba las claves sin semilla: ahora define la suya. **No aplicado** (necesita decisión): negar el arranque
  en producción con claves `legacy` (pararía el servidor local actual) y las propuestas de §2 del informe.
- **Pruebas ejecutadas:** pruebas nuevas «sin semilla no hay claves» y la fórmula antigua sin `JWT_SEED` (`test_rotation.js`);
  `test_api` 16/16, `test_icmp` 24/24, `test_s3` 5/5, `test_system` 100 %; cobertura 77,2 % líneas / 84,1 % ramas / 90,6 % funciones;
  lint 0; `npm audit` 0 en raíz y `web/`; **suite completa en serie: 603 pruebas, 602 bien, 0 fallos, 1 omitida** (`SIGHUP`).
- **Puntuación:** 8/10 — las trampas de claves cerradas con prueba; el riesgo mayor (claves diarias en el `.env` local) depende del
  propietario.
- **Problemas restantes:** definir `KEY_EPOCH` (y migrar datos `legacy` si los hay); propuestas 5–14 del informe; CI sin comprobar
  desde aquí. **Siguiente mejora:** decidir §3.1 del informe. *(Alta.)*

### #34 — Claves estables en local, rotación semanal sin entradas ni salidas, y caídas/pausas sin pérdida de datos
- **Estado:** completado (12-nov). Detalle de hallazgos 15–21 en `docs/REVISION-CODIGO-2026-11.md` §2 bis.
- **Archivos y módulos revisados:** `src/maintenance/{rotation.service,guard,maintenance,cutoff}.js`, `src/tasks/{scheduleKeyRotation,securityHousekeeping}.js`,
  `src/crypto/keyRotator.js`, `src/security/alerts.service.js`, `src/services/secure-communications.service.js`, `src/index.js`,
  `src/observability/live-stream.js`, `.env` local (solo `KEY_EPOCH`, `AUTO_ROTATION_ENABLED` y si el host de la BD es local).
- **Problema detectado:** la rotación era **mensual** y estaba desactivada en el `.env` local (además en modo `legacy`); durante el
  mantenimiento seguían la limpieza, las alertas, los webhooks, los correos y los streams abiertos, y `/health` daba 503;
  `recover` sin respuesta de la BD deshacía y borraba `.env.pending` (la única copia de las semillas nuevas) aunque la BD hubiera
  confirmado; la rotación no comprobaba que seguía teniendo el cerrojo de la BD antes de confirmar; una alerta enviada en
  mantenimiento se registraba cifrada con una clave que podía ser ya la antigua; no había pruebas de caídas **reales** en la suite.
- **Acciones realizadas:** `.env` local con `KEY_EPOCH` y `AUTO_ROTATION_ENABLED=true` (no se sube: `skip-worktree`; la BD local no
  tenía datos de la aplicación). Rotación **semanal** por defecto (`KEY_ROTATION_CRON`, `KEY_ROTATION_TZ`), que se niega con cron
  inválido o claves `legacy`; 8 backups por defecto. Mantenimiento **sin entradas ni salidas** (`src/maintenance/cutoff.js`: streams
  cerrados al momento y conexiones abiertas cortadas a los 4 s; sin webhooks, alertas, limpieza ni correos; `/health` sigue vivo),
  con una excepción: el aviso de rotación fallida, de texto fijo, también al arrancar si la rotación quedó interrumpida.
  `recover` no decide sin la BD; comprobación del cerrojo antes del `COMMIT`; puntos de control `onPhase` para las pruebas.
- **Pruebas ejecutadas:** nuevas en `test_rotation.js` con proceso hijo real (`test_helpers/rotation-child.js`): muerte con la
  transacción abierta, justo tras el `COMMIT` de la BD y a mitad de colocar archivos; rotación parada a la que la BD corta las
  conexiones; pérdida del cerrojo; `recover` sin BD; bloqueo de entradas y salidas con servidor HTTP y webhook reales; planificador
  semanal. 9/9 en local. **Suite completa en serie: 611 pruebas, 610 bien, 0 fallos, 1 omitida** (`SIGHUP`); lint 0.
- **Puntuación:** 8,5/10 — los puntos de pérdida de datos están cubiertos por pruebas reales; falta ver la rotación con el reloj
  real del domingo y en varias máquinas.
- **Problemas restantes:** el servidor local no conecta con este `.env` (TLS verificado + usuario inexistente en la MariaDB local);
  decidir si producción debe negarse a arrancar con claves `legacy`; las alertas retenidas en mantenimiento no se reenvían.
  **Siguiente mejora:** credenciales locales válidas y una rotación real de punta a punta con `npm start`. *(Media.)*

## N. Intervención 2026-11-15: mantenimiento (#35)

Rama `fix/audit-bitacora-2026-11-15` (rama corta por tarea, desde `main`).

### #35 — Ramas solo `main`, Dependabot, `npm audit` y grafo (verificación solo local)
- **Estado:** completado en lo que se pudo ejecutar en local (15-nov); **CI real de GitHub sin comprobar** (el repositorio responde 404
  sin sesión).
- **Archivos y módulos revisados:** ramas remotas y PR de Dependabot #27–#41; `package.json` y `package-lock.json` (raíz y `web/`),
  Dockerfile, `deploy/docker-compose.yml` y workflows de `.github/`; `npm audit` (raíz y `web/`); `graphify-out/`, `.gitignore`;
  `CLAUDE.md`; suites del API (`test_*.js`, incluida `test_fuzz.js`) y cobertura.
- **Problema detectado:** (1) 30 ramas remotas con flujo confuso; todo estaba fusionado en `main` salvo el commit `5ee29e5` de
  `claude/project-thread-qjkfd0` (token de cliente diario, `capacity.js`, optimización de `level3.js`); (2) 12 PR de Dependabot y una
  rama corta de dependencias pendientes; (3) `npm audit` en la raíz con 7 moderadas, todas de desarrollo (`web/`: 0); (4) grafo
  desactualizado; (5) `test_fuzz.js` no termina en este equipo (16/17 pasan, la 17.ª cae por timeout de 120 s y el proceso queda
  colgado, también con `--test-force-exit`), por lo que `npm run test:all` y `npm run coverage` se cuelgan en local; se reproduce en
  `main` con las dependencias anteriores.
- **Acciones realizadas:** por decisión del propietario solo queda `main`: **29 ramas remotas borradas** (`pruebas`, `postproduccion`,
  `cierre/0-base`…`cierre/8-bd`, `instalador`, `revision-codigo`, `claude/codigo-apis-readme-wrr430`, `claude/project-thread-qjkfd0`,
  `repo/sharp-noether-tbr0bz`, 12 de Dependabot y `deps/dependabot-2026-11`); `5ee29e5` conservado en la etiqueta
  `archivo/project-thread-qjkfd0`; nuevo flujo en `CLAUDE.md` (`c6255e2`): rama corta por tarea desde `main`, push de la rama y avance
  rápido de `main` tras cada commit, rama borrada al terminar. Los PR #27–#41 quedaron cerrados al borrar sus ramas. **Dependabot**
  (`9805d95`): c8 12.0.0, concurrently 10.0.7, fs-extra 11.4.1, globals 17.14.0, node-cron 4.6.0, nginx 1.31-alpine,
  chrislusf/seaweedfs 4.52, amazon/aws-cli 2.39.6 y actions/dependency-review-action 5.0.0 (SHA fijado). **Aparcadas** por decisión del
  propietario: mariadb 10.11→13.0 en `deploy/` (el CI usa 10.11 a propósito), imagen node 22→26-bookworm-slim y
  actions/upload-artifact 4→7. **Seguridad** (`4ddb01d`): `npm audit fix` sin `--force` subió eslint 10.14.0→10.15.0 y
  `@eslint/config-array` 0.23.5→0.23.6 (minimatch 11.0.8 anidado; GHSA-g3hv-75wg-m249). Quedan **5 moderadas de desarrollo**
  (minimatch <11.0.1 vía `nodemon` y `c8`→`test-exclude`→`glob` 13; GHSA-3g3m-2fjr-6pw4) porque la corrección exige versión mayor o
  retroceder `c8` a 9.1.0; pendiente de decisión (posible `overrides`). GitHub avisó de 2 moderadas en `main`; no se pudo ver la
  página y probablemente son esos advisories. **Grafo** (`42da76d`): 3337 nodos, 6101 aristas, 203 comunidades (45 con nombre en
  español); 6 documentos re-extraídos; avisos de salud (25 aristas colgantes, 10 bucles, ≈ 600 aristas colapsadas, sobre todo
  `contains` del YAML del CI); los 19 `.sql` no aportan (falta `tree_sitter_sql`); `.gitignore` ignora las copias por fecha
  `graphify-out/20??-??-??/`.
- **Pruebas ejecutadas (solo local: Windows, Node 26, MariaDB 13.1.1; el CI usa 10.11):** `lint:security` 0 errores y 0 avisos;
  `test:api` 16/16; suite completa **sin `test_fuzz.js`**: 593 pruebas, 592 pasadas, 0 fallidas, 1 omitida; cobertura con c8 12 (sin
  `test_fuzz.js`): sentencias y líneas 78,74 %, funciones 89,6 %, ramas 83,42 %, sobre los umbrales 72/72/88/80. En esa pasada
  `test_av.js` dio 23 fallos «fetch failed: bad port» por un puerto aleatorio inválido; ejecutado solo, 23/23. `test:api` 16/16 y lint
  0 avisos también tras `4ddb01d`. **No verificado:** CI real de GitHub, job `compose` con las imágenes nuevas, scripts con
  concurrently 10, `web/` (typecheck, build, e2e) y dependency-review v5. `test_fuzz.js` **no** se pudo completar.
- **Puntuación:** 7/10 — entrega de mantenimiento: el repositorio queda más simple y con dependencias al día, pero la evidencia es solo
  local, queda un cuelgue de pruebas sin explicar y 5 moderadas abiertas. No cambia el estado de ningún componente salvo a la baja (§C).
- **Problemas restantes:** CI de `main` sin comprobar tras #35; `test_fuzz.js` colgado (causa no investigada; sospecha: handle abierto
  tras «fuzz HTTP: subida de archivos con multipart malformado»); 5 moderadas de desarrollo; contraseña de la BD remota del historial de
  `test.js` (la rota el propietario); decidir el commit archivado y las 3 actualizaciones aparcadas.
  **Siguiente mejora:** comprobar el CI de `main` y `web/`, y encontrar el handle abierto de `test_fuzz.js`. *(Alta.)*

## O. Intervención 2026-11-17: orden de la raíz (#36)

Rama `orden/raiz-limpia` (rama corta por tarea, desde `main`).

### #36 — Raíz ordenada en carpetas (sin cambios de comportamiento; verificación solo local)
- **Estado:** completado en lo que se pudo ejecutar en local (17-nov); **CI real de GitHub sin comprobar** (los jobs fallan en 1–2 s por
  un problema de cuenta o facturación de Actions, no de código: también cae el workflow `Security`, que no cambió).
- **Archivos y módulos revisados:** raíz del repositorio (49 archivos versionados); los 26 `test_*.js` y `test_helpers/`;
  `package.json` (scripts), `.c8rc.json`, `.dockerignore`, `eslint.config.js`, `.github/workflows/ci.yml`, `deploy/docker-compose.yml`,
  `database/setup-local.sql`, `README.md`, `CLAUDE.md`, `docs/*` (incluida la descripción de `docs/openapi.json`),
  `scripts/openapiTable.js`, comentarios de `src/`, `debug-env.js`, `INSTALL.md`, `SECURITY.md`, `install.js`, `instalador/comun.sh` e
  `instalador/windows.ps1`.
- **Problema detectado:** el propietario pidió menos archivos sueltos en la raíz: había 49 versionados (26 pruebas, ayudantes,
  instalador, documentación y política mezclados con la configuración).
- **Acciones realizadas:** la raíz pasa de **49 a 20 archivos versionados**, en tres niveles sin cambios de comportamiento.
  (1) `45ea6ee`: los 26 `test_*.js` → `test/` y `test_helpers/` → `test/helpers/` (rutas internas `../../src`, `../../database`);
  referencias actualizadas en `package.json` (scripts), `.c8rc.json`, `.dockerignore`, `eslint.config.js`, `ci.yml`,
  `deploy/docker-compose.yml`, `database/setup-local.sql`, `README.md`, `CLAUDE.md`, `docs/*` (incl. la descripción de
  `docs/openapi.json`), `scripts/openapiTable.js` y comentarios de `src/` (solo comentarios). (2) `44357c4`: `debug-env.js` →
  `scripts/debug-env.js` (busca el `.env` en la carpeta superior); `INSTALL.md` → `docs/INSTALL.md`; `SECURITY.md` →
  `.github/SECURITY.md` (GitHub la sigue reconociendo); `ReadmeLogsMejoras.md` → `docs/ReadmeLogsMejoras.md` (enlace a
  `PruebasLinux` ajustado; las entradas históricas **no** se reescriben, así que citan las rutas de entonces). (3) `59349b7`:
  `install.js` → `instalador/install.js` (`ROOT` = carpeta superior); `instalador/comun.sh` e `instalador/windows.ps1` llaman a
  `node instalador/install.js`; `docs/INSTALL.md` actualizado. Además `d0c283f` (`CLAUDE.md`): nuevo flujo de git, se sube solo la rama
  corta y `main` avanza (avance rápido) y la rama se borra cuando el propietario la valida. **Quedan en la raíz a propósito:**
  `package.json`, `package-lock.json`, `.env`, `.env.example`, `.gitattributes`, `.gitignore`, `.gitleaksignore`, `.dockerignore`,
  `Dockerfile`, `eslint.config.js`, `.c8rc.json`, `README.md`, `CLAUDE.md` e `instalar.cmd/.command/.sh` (lanzadores de doble clic).
  **Pendientes de decisión del propietario:** `install.sh` e `install.ps1` (atajos de compatibilidad que solo redirigen a
  `instalar.sh` / `instalador\windows.ps1`) y `security.config.js` (no lo importa ningún archivo; objeto estático de 2025, código
  muerto): borrar o mantener.
- **Pruebas ejecutadas (solo local: Windows, Node 26, MariaDB 13.1.1; el CI usa 10.11):** tras el nivel 1, `lint:security` 0
  errores y 0 avisos; `test:api` 16/16; suite completa **sin `test_fuzz.js`**: 593 pruebas, 592 pasadas, 0 fallidas, 1 omitida,
  idéntico a la línea base de `main`. Tras los niveles 2 y 3: lint 0 avisos, `test:api` 16/16 (incluye README = OpenAPI),
  `npm run debug-env` encuentra el `.env` de la raíz y `node instalador/install.js --help` funciona. `test/test_fuzz.js` (solo, `timeout 300`): 16 pruebas pasan y el proceso queda colgado hasta el límite, igual que en `main` antes del cambio (problema previo, ver #35).
  **No verificado:** CI de GitHub, Docker/compose con la nueva ruta `test/`, instaladores en Linux y macOS (nunca ejecutados);
  `web/` no se tocó.
- **Puntuación:** 7/10 — orden útil y sin regresiones medidas, pero con evidencia solo local y sin CI. No cambia ninguna nota de §C.
- **Problemas restantes:** CI bloqueado por la cuenta de Actions (y rutas nuevas de `test/` sin probar en el job `compose`);
  `test_fuzz.js` colgado en local; 5 moderadas de `npm audit` (desarrollo); 3 actualizaciones aparcadas; commit archivado;
  decidir `install.sh`, `install.ps1` y `security.config.js`.
  **Siguiente mejora:** desbloquear el CI de Actions y comprobar `compose` con las rutas nuevas; luego el cuelgue de `test_fuzz.js`.
  *(Alta.)*

---

## P. Intervención 2026-11-17: cuelgue de `test_fuzz.js`, revisión del código y CI de GitHub (#37–#38)

Rama `fix/fuzz-sse` (rama corta por tarea, desde `main` con el PR #42 ya fusionado).

### #37 — `test_fuzz.js` ya no se cuelga: `test:all` completo en local (verificación solo local)
- **Estado:** completado en local (17-nov); **CI de GitHub sin comprobar** (la API pública de Actions no fue accesible desde este equipo
  y el problema de cuenta de #36 sigue sin confirmarse como resuelto).
- **Archivos y módulos revisados:** `test/test_fuzz.js` (fuzz HTTP de rutas y de subidas), `test/helpers/app.js` (`api()`, `startApp()`),
  `src/files/upload.js` (`receiveUpload`, `SniffGate`), `src/api/controllers/files.controller.js` (`upload`),
  `src/observability/live-stream.js` (SSE), `test/test_ops.js` (usos del stream); commits del PR #42: `scripts/dbTlsCerts.js`,
  `src/config/database.js` (`DB_SSL`), `package.json` (`db:tls`, `nodemonConfig`), `database/setup-app-local.sql`,
  `instalador/mariadb-tls.ps1`.
- **Problema detectado:** `test_fuzz.js` pasaba 16 pruebas y se quedaba colgado para siempre, así que `test:all` y `coverage` no
  terminaban (#35, #36). La sospecha anterior (multipart malformado) era falsa: 300 subidas malformadas contra `receiveUpload` aislado
  responden todas. La causa real: el fuzz HTTP recorre todas las rutas de `docs/openapi.json` con tres roles, incluida
  `GET /api/system/stream` (SSE, que solo se cierra al caducar el token). Con rol admin el stream se abre y `api()` hacía
  `await res.arrayBuffer()`, que no vuelve nunca. Evidencia: al colgarse se habían creado exactamente 128 usuarios = 64 rutas del rol
  `user` + 64 del rol `admin`, y el stream es la ruta 64 de 64.
- **Acciones realizadas:** `api()` en `test/helpers/app.js` detecta `Content-Type: text/event-stream`, cancela el cuerpo (cierra la
  conexión, así el servidor libera al cliente y `server.close()` no espera) y devuelve estado y cabeceras con texto vacío. El
  servidor no cambia. Los demás usos del stream no se ven afectados: `test_ops.js` lee eventos con `fetch` directo (`openStream`) y sus
  llamadas con `api()` esperan 401/403/429 en JSON. Revisión de los commits del PR #42: `openssl` con `execFileSync` y argumentos en array,
  claves privadas fuera del repositorio (comprobado antes de buscar `openssl`) y con permisos `0600`, `DB_SSL=verify` por defecto en
  producción, `off` solo en `nodemon`; `secure_app` sin privilegios globales. Sin defectos.
- **Pruebas ejecutadas (solo local: Windows, Node 26, MariaDB 13.1.1; el CI usa 10.11):** `lint:security` 0 errores y 0 avisos;
  `test:api` 20/20; `test/test_fuzz.js` solo **18/18 en 105 s** y el proceso termina; `npm run test:all` **615 pruebas, 614 pasadas,
  0 fallidas, 1 omitida** (SIGHUP no existe en Windows) en 699 s; `web/`: `typecheck` sin errores, `npm test` 57/57, `npm run build`
  correcto (solo el aviso de Next sobre la raíz del workspace por los dos `package-lock.json`).
  `npm run coverage`: misma suite 614/615 en 763 s; líneas 79,1 %, ramas 84,0 %, funciones 91,3 %; `c8 check-coverage` **pasa**.
  **No verificado:** CI de GitHub, e2e de `web/` (Playwright), `compose`, ClamAV real (el servicio `ClamD` estaba parado; las pruebas de
  antivirus usan su simulador).
- **Puntuación:** 8/10 — se cierra el único fallo conocido que impedía ejecutar la suite completa, con la causa demostrada y un cambio
  mínimo solo en pruebas; no llega a más por falta de CI. Pruebas automatizadas 8,0 → 8,2 (§C).
- **Problemas restantes:** CI sin comprobar; 5 moderadas de `npm audit` (desarrollo); instaladores de Linux y macOS sin ejecutar;
  decidir `install.sh`, `install.ps1` y `security.config.js`; aviso de Next sobre `turbopack.root` (inocuo); la rama `fix/db-tls` tiene
  un commit solo del grafo (`550227a`) sin pasar a `main`.
  **Siguiente mejora:** comprobar el CI de `main` (jobs `test`, `web`, `compose`) y ejecutar los e2e de `web/` en local. *(Alta.)*

### #38 — CI de GitHub de nuevo en verde (verificado en GitHub)
- **Estado:** completado. Todos los jobs de `CI` pasan en `a248917` (rama `ci/revision`); `Security` aún sin ejecutar (solo en PR o en
  push a `main`).
- **Archivos y módulos revisados:** `.github/workflows/ci.yml`, `fuzz.yml`, `security.yml` (YAML válido, acciones fijadas por SHA,
  permisos mínimos, `timeout-minutes` en todos los jobs), `.github/scripts/annotate-log.sh`, `.github/dependabot.yml`; anotaciones de los
  check-runs de las ejecuciones fallidas desde #35.
- **Problema detectado:** (1) desde el 16-nov ningún job arrancaba (0 pasos, sin runner, 2 s). La anotación de GitHub lo explica: «The job
  was not started because recent account payments have failed or your spending limit needs to be increased»; el repositorio era privado,
  así que Actions consumía minutos de pago. (2) Con el CI de vuelta, el job `web` fallaba en «Navegadores de Playwright»: `ubuntu-latest`
  pasó a Ubuntu 26 el 19-oct y Playwright 1.56.1 (fijado) no sabe instalar allí las dependencias. Ese paso no publicaba anotación, así que el
  motivo no se podía leer sin sesión. (3) En `ci.yml`, el comentario de `production-install` estaba encima de `pruebaslinux`.
- **Acciones realizadas:** el propietario hizo público el repositorio (los runners estándar son gratuitos en repositorios públicos). Job
  `web` fijado a `ubuntu-24.04`, con un comentario que explica cuándo volver a `ubuntu-latest`. La instalación de navegadores guarda su
  registro y, si falla, publica las últimas 40 líneas como anotación. Comentario de `production-install` movido a su job.
- **Pruebas ejecutadas:** **en GitHub**, ejecución de `a248917`: `test` (MariaDB 10.11, `npm run coverage` con `test_fuzz.js` y umbral de
  cobertura, `npm audit` de producción), `web` (typecheck, 57 unitarias, build, e2e en Chromium, Firefox y WebKit + axe), `compose`
  (2 réplicas + nginx + MariaDB + SeaweedFS), `pruebaslinux` (invariantes + Semgrep), `production-install`: **todos en verde**;
  `dependency-review` omitido (solo en PR). La ejecución anterior (`14a4cbf`) ya tenía todo en verde salvo `web`. En local: YAML de los
  tres workflows validado, `check:prod-deps` limpio, `npm audit --omit=dev --audit-level=high` sin hallazgos en la raíz ni en `web/`,
  invariantes 119–121 y 124 de PruebasLinux en OK, `npm run dev` se niega con `NODE_ENV=production`.
  **No verificado:** el workflow `Security` (CodeQL, gitleaks, SBOM, DAST) y el `Fuzzing` nocturno, que no han corrido desde que volvió el CI.
- **Puntuación:** 9/10 — el CI completo vuelve a estar en verde con evidencia en GitHub y los fallos de instalación quedan legibles; falta
  ver `Security`.
- **Problemas restantes:** ejecutar `Security` (al abrir el PR); Playwright 1.56 obliga a seguir en `ubuntu-24.04`; 1 moderada de
  Dependabot en `main` (según el aviso de `git push`; en local, las 5 moderadas de desarrollo ya conocidas); decidir `install.sh`,
  `install.ps1` y `security.config.js`.
  **Siguiente mejora:** abrir el PR de `ci/revision` para que corra `Security` y revisar su resultado; luego subir Playwright. *(Alta.)*
