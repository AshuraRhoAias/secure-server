# ReadmeLogsMejoras.md — Bitácora de auditoría de `secure-server`

> Documento maestro de auditoría, cambios, verificaciones y tareas pendientes del
> proyecto. Se ha elaborado **con evidencia real**: ejecución de los tests del
> repositorio, análisis estático con el entorno [`PruebasLinux/`](PruebasLinux/ReadmeLogMejoras.md)
> y revisión manual del código. Donde algo **no** ha podido verificarse (por falta de
> base de datos, servidor en marcha o conectividad en el laboratorio), se indica
> explícitamente y **no** se declara como completado.

- **Fecha de la auditoría:** 2026-10-21 (UTC)
- **Commit base auditado:** `b7b1ea1` (rama por defecto `main`)
- **Rama de trabajo de esta intervención:** `claude/project-thread-qjkfd0`
- **Entorno de ejecución:** contenedor Ubuntu 24.04, Node 22, sin MySQL ni el servidor
  arrancado (laboratorio aislado). Herramientas defensivas instaladas: 33 (ver §A).

---

## A. Resumen ejecutivo

**Estado general.** `secure-server` es una API REST en Node.js (Express 5 + MySQL) con
una arquitectura de seguridad notablemente completa para su tamaño: cifrado en tres
capas de los datos persistidos, autenticación JWT ligada a sesión con análisis de
riesgo, autorización por rol leída de la BD en cada petición, rate limiting, detección
de anomalías, rotación de claves con backups cifrados y auditoría cifrada. La **suite
de pruebas que no depende de BD pasa al 100 %** (ver §B#2).

**Componentes analizados.** Capa de entrada (`src/index.js`), middlewares de
protección/auth/rol/errores, servicios de seguridad (auth, anomalías, comunicaciones,
ICMP), criptografía (triple cifrado, rotación), APIs (auth, notes, system), esquema y
migraciones de BD, scripts de operación, dependencias y configuración.

**Problemas críticos / relevantes encontrados.**

1. **Dependencias vulnerables (ALTA):** `npm audit --omit=dev` reporta **21
   vulnerabilidades** (1 crítica, 12 altas, 8 moderadas), p. ej. en `proxy-addr`
   (crítica), `axios`, `mysql2`, `path-to-regexp`, `lodash`.
2. **`.env` versionado en git (ALTA de higiene):** el archivo `.env` está en control de
   versiones pese a estar en `.gitignore`. En este repo sus valores son **idénticos a
   los de `.env.example`** (semillas de ejemplo, no secretos vivos), pero el patrón es
   peligroso: si alguna vez contuviera secretos reales, quedarían expuestos en el
   historial.
3. **JWT sin fijar `algorithms` en la verificación (MEDIA):** `jwt.verify(token,
   secret)` (`src/security/secure-auth.service.js:211`) no restringe el algoritmo
   aceptado. Conviene pasar `{ algorithms: ['HS256'] }` para evitar confusión de
   algoritmo.
4. **Artefactos de "auto-puntuación" engañosos (MEDIA de honestidad):** scripts como
   `maximize-score.js`, `final-boost-to-100.js`, `fix-system.js` y los marcadores
   `.audit_version`, `.integrity_status`, `.security_optimized` afirman una puntuación
   de "100/100" **auto-declarada**, no medida por un auditor independiente. Inducen a
   error sobre el estado real de seguridad.
5. **Ruido/exposición en el repo (BAJA):** 56 ficheros `src/notifications/*.json` y un
   `reports/security_audit_*.json` están versionados (el `.gitignore` pretende
   ignorarlos pero fueron añadidos antes). Contienen contenido camuflado en base64 y
   métricas; aportan ruido y potencial divulgación de información.

**Mejoras implementadas en esta intervención.**

- Entorno independiente **`PruebasLinux/`** con **117 pruebas** defensivas reales en 15
  categorías, menú interactivo, modo no interactivo, logging e informes MD/JSON/CSV.
- Instalación y verificación de 33 herramientas defensivas en el laboratorio.
- **No se ha modificado el código de la aplicación**, conforme a lo solicitado: la
  intervención es aditiva y no interfiere con la ejecución del proyecto (ver §F y la
  verificación de no interferencia).

**Riesgos pendientes.** Las vulnerabilidades de dependencias y la higiene de secretos
siguen abiertas: su corrección implica actualizar paquetes (algunas con *breaking
changes*) y reescribir el historial de git / rotar secretos, decisiones que afectan al
código y a la operación y que se dejan propuestas, no aplicadas (ver §F).

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

---

## C. Sistema de puntuación por componente (0–10)

Criterios: funcionalidad, seguridad, calidad/mantenibilidad, gestión de errores,
rendimiento, cobertura de pruebas y documentación. **No se asignan 10 sin evidencia
suficiente.** Se distingue el grado de evaluación.

| Componente | Evaluación | Punt. | Justificación |
|------------|------------|:----:|---------------|
| Criptografía / cifrado | Evaluado (estático + tests) | 8 | Triple capa + rotación; tests de cifrado/rotación en verde. Riesgo inherente de criptografía a medida. |
| Autenticación | Evaluado (estático) | 7 | JWT+sesión+riesgo, 2FA. `algorithms` sin fijar; expiración de 5 días algo larga. |
| Autorización | Evaluado (estático) | 8 | Rol leído de BD en cada petición; `requireRole` presente. |
| API / validación de entrada | Parcial (sin servidor) | 7 | `validate.js`, 400 en malformados, rate limit. No ejecutado en vivo. |
| Base de datos | Parcial (sin MySQL) | 7 | Columnas cifradas, consultas parametrizadas. Integración no verificada aquí. |
| Gestión de errores | Evaluado (estático) | 7 | Manejador global; 4xx respetados, resto 500 sin detalle. |
| Dependencias | Evaluado | 4 | 21 vulnerabilidades (1 crítica). |
| Secretos / configuración | Evaluado | 5 | `.env` versionado (valores de ejemplo), permisos `644`. |
| Logging / auditoría | Evaluado (estático) | 8 | Auditoría cifrada, integridad, sin fugas en logs. |
| Calidad / mantenibilidad | Evaluado | 6 | Artefactos de auto-puntuación engañosos; ruido (56 JSON); scripts `.sh` con avisos. |
| Pruebas automatizadas | Parcial (sin BD) | 7 | Suites sólidas; 32 pruebas de BD omitidas por entorno. |
| Documentación | Evaluado | 8 | `README.md` extenso y fiel al código. |
| Rendimiento | **No evaluado** | — | Sin pruebas de carga ni servidor en marcha. |
| Infraestructura / Docker | **No evaluado** | — | El proyecto no incluye Dockerfile ni compose. |

**Media de los componentes evaluados (excluye los "No evaluado"):** ≈ **6,7/10**.
Esta cifra es una valoración de auditoría con evidencia, no una puntuación perfecta
auto-declarada.

---

## D. Registro de problemas y tareas pendientes (por prioridad)

### 🔴 Crítica / Alta

- **[ALTA] Dependencias vulnerables.** *Evidencia:* `npm audit --omit=dev` → 21 vulns
  (1 crítica). *Impacto:* exposición a CVEs conocidos en tiempo de ejecución. *Solución:*
  actualizar por fases y validar con las suites. *Estado:* abierto (propuesto).
- **[ALTA] `.env` y artefactos versionados.** *Evidencia:* `git ls-files` lista `.env`,
  56 `src/notifications/*.json`, `reports/*.json`. *Impacto:* higiene de secretos y
  divulgación. *Solución:* `git rm --cached`, rotación de secretos reales si los hubo.
  *Estado:* abierto (propuesto; afecta al repo).

### 🟠 Media

- **[MEDIA] JWT `algorithms` sin fijar.** *Evidencia:* `secure-auth.service.js:211`.
  *Impacto:* confusión de algoritmo. *Solución:* `jwt.verify(t, k, {algorithms:['HS256']})`.
  *Estado:* abierto (propuesto; afecta al código).
- **[MEDIA] Auto-puntuación engañosa.** *Evidencia:* `maximize-score.js`,
  `final-boost-to-100.js`, `.audit_version` (score 100 auto-declarado). *Impacto:*
  induce a confianza no fundamentada. *Solución:* retirar o marcar claramente como
  demostrativos; usar `PruebasLinux` como medición real. *Estado:* abierto (propuesto).

### 🟡 Baja

- **[BAJA] Advertencias de ShellCheck** en `scripts/*.sh`. *Solución:* corregir avisos.
- **[BAJA] Permisos de `.env` 644.** *Solución:* `chmod 600 .env` (hay script
  `npm run fix-permissions`).
- **[BAJA] Ruido de 56 ficheros de notificación** en `src/notifications/`. *Solución:*
  mover a un directorio ignorado o purgar.

---

## E. Historial de cambios de esta intervención

Todos los cambios son **aditivos** y viven bajo `PruebasLinux/` + este documento. **No
se ha creado, modificado ni eliminado ningún archivo del código de la aplicación**
(`src/`, `scripts/`, `database/`, `package.json`, etc.).

| Acción | Archivo(s) | Motivo | Validación |
|--------|-----------|--------|------------|
| Creado | `PruebasLinux/pruebas.sh` | Lanzador principal | `bash -n`, `shellcheck`, `--list/--diagnose`, menú |
| Creado | `PruebasLinux/lib/core.sh`, `lib/ui.sh`, `lib/report.sh` | Núcleo, menú e informes | idem |
| Creado | `PruebasLinux/modules/01..15_*.sh` | 117 pruebas en 15 categorías | ejecución por categoría |
| Creado | `PruebasLinux/ReadmeLogMejoras.md` | Documentación del entorno | revisión; tabla generada del registro real |
| Creado | `PruebasLinux/.gitignore`, `logs/.gitkeep`, `reports/.gitkeep` | No versionar salida | — |
| Creado | `ReadmeLogsMejoras.md` (este archivo) | Bitácora de auditoría | — |

**Punto de recuperación.** El estado previo es el commit `b7b1ea1` en `main`; esta
intervención se realiza en la rama `claude/project-thread-qjkfd0`, de modo que revertir
es tan simple como no fusionar la rama (o eliminar la carpeta `PruebasLinux/` y este
archivo). No hay cambios en la aplicación que deshacer.

---

## F. Plan de mejora continua

Separado entre **completado** en esta intervención y **propuesto** (requiere decisiones
que tocan el código/operación y exceden el encargo aditivo).

### Completado
- ✅ Entorno `PruebasLinux` funcional con 117 pruebas, logging e informes.
- ✅ Verificación de las suites de test existentes (sin regresiones).
- ✅ Auditoría estática con evidencia y esta bitácora.

### Propuesto (con dependencias, prioridad y criterio de aceptación)

1. **Actualizar dependencias vulnerables.** *Prioridad:* alta. *Dependencia:* suite de
   tests verde tras actualizar. *Aceptación:* `npm audit --omit=dev` sin vulnerabilidades
   críticas/altas y `npm test` en verde.
2. **Sacar `.env` y artefactos del control de versiones + rotar secretos.** *Prioridad:*
   alta. *Dependencia:* confirmar que no se rompe el arranque. *Aceptación:* `git ls-files`
   no lista `.env` ni `src/notifications/*.json`; secretos rotados si fueron reales.
3. **Fijar `algorithms` en `jwt.verify`.** *Prioridad:* media. *Aceptación:* `verify`
   restringe a `HS256`; `test:api` sigue en verde.
4. **Retirar/etiquetar los scripts de auto-puntuación.** *Prioridad:* media.
   *Aceptación:* no quedan ficheros que afirmen una puntuación no medida.
5. **CI con MySQL efímero + `PruebasLinux --safe-all`.** *Prioridad:* media.
   *Aceptación:* las 46 pruebas de rotación se ejecutan y el perfil seguro corre en cada
   PR.
6. **Añadir `trivy` y reglas `semgrep`.** *Prioridad:* baja. *Aceptación:* opciones 88–89
   dejan de omitirse; `semgrep` con ruleset Node.

> Las mejoras 1–4 modifican el código o el repositorio del proyecto y, por respetar el
> encargo de **no interferir con el código existente**, se dejan **documentadas y
> propuestas**, no aplicadas. Requieren el visto bueno de Antonio para ejecutarse en una
> intervención aparte.
