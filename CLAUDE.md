# secure-server — instrucciones para Claude

API REST (Node ≥ 22, Express 5, MariaDB/MySQL) para datos sensibles, con interfaz web de operación (Next.js 16 + React 19,
BFF) solo para administradores, y un entorno independiente de pruebas de seguridad en Linux (`PruebasLinux/`).
**Idioma del proyecto: español** (código comentado, documentación, commits y respuestas al usuario).

## Comandos

| Qué | Comando |
|---|---|
| Arrancar API / cluster | `npm start` · `npm run start:cluster` (`npm run dev` se niega en producción) |
| Lint (puerta del CI, 0 avisos) | `npm run lint:security` |
| Pruebas del API sin BD | `npm run test:api` (incluye OpenAPI = rutas y README = OpenAPI) · `npm run test:fuzz` · `node --test test/test_kms.js test/test_s3.js` |
| Todas las del API | `npm run test:all` / `npm run coverage` (**necesitan MariaDB**: sin ella las de BD se omiten, no fallan) |
| Web | `cd web && npm run typecheck && npm test && npm run build` · e2e: `npm run test:e2e` (MariaDB + Playwright) |
| Tabla de endpoints del README | `npm run docs:endpoints -- --write` (tras tocar `docs/openapi.json`) |
| Varias réplicas (Docker) | `deploy/docker-compose.yml` + `npm run test:compose` (ver `docs/SEGURIDAD.md` §23) |
| PruebasLinux | `bash PruebasLinux/pruebas.sh --list` (126 opciones; solo contra sistemas propios o autorizados) |

## Estructura

- `src/index.js` (arranque y validación de configuración) · `src/cluster.js` (workers + IPC)
- `src/api/{routes,controllers}` · `src/middleware` (protección, auth, validación) · `src/security` (auth, MFA, WebAuthn,
  permisos, eventos, alertas, `sql.js`) · `src/sso` (OIDC, SAML, entrega por código) · `src/crypto` (AES-256-GCM v4, KMS)
- `src/files` (cifrado por bloques, local o S3, antivirus, saneado) · `src/maintenance` (rotación, particiones) ·
  `src/observability` (métricas, trazas, stream SSE, estado del cluster) · `src/tasks/leader.js` (líder por `GET_LOCK`)
- `database/schema.sql` + `database/migrations/NNN_*.sql` (toda columna nueva va en las dos)
- `web/` (BFF: `src/lib/{bff,session,sso,stream,client}.ts`; e2e en `web/e2e/`) · `test/` (todas las `test_*.js`) · `test/helpers/`
- Documentación: `README.md`, `docs/SEGURIDAD.md`, `docs/openapi.json`, `docs/ReadmeLogsMejoras.md` (bitácora maestra), `docs/INSTALL.md`, `.github/SECURITY.md`,
  `PruebasLinux/ReadmeLogMejoras.md`; histórico en `docs/historico/`.

## Decisiones del propietario (no cambiarlas sin preguntar)

- **`.env` se queda versionado**: hoy lleva datos de prueba que el propietario cambiará. No sacarlo ni proponerlo como tarea.
- **MariaDB local**: el propietario tiene **MariaDB 13.1.1** (servicio `MariaDB`, puerto 3306) con las bases de prueba de
  `database/setup-local.sql` (usuario `sec`), así que `npm run test:all` funciona en local. El CI usa **MariaDB 10.11**: algo verde
  en uno no prueba el otro. Nunca usar ni leer la contraseña de root (el script lo ejecuta el propietario). No levantar
  contenedores ni descargar imágenes sin permiso (el equipo va justo de memoria). `.env` tiene `skip-worktree`: sus cambios locales
  (credenciales) no deben subirse nunca.
- Bases de datos: fase SQL (MariaDB/MySQL + PostgreSQL/Supabase) con adaptador de dialecto; MongoDB más adelante
  (`docs/BASES-DE-DATOS.md`, sección «Estado»). El motor se elige con `DB_CLIENT` en `src/config/db-drivers/` (el ÚNICO sitio que
  importa `mysql2`/`pg`; `test/test_db.js` lo comprueba). Todo driver cumple el contrato documentado allí. SQL nuevo, portable:
  `SUM(CASE WHEN … THEN 1 ELSE 0 END)`, nunca `SUM(condición)`. No afirmar soporte de PostgreSQL sin su job del CI en verde.
- Claves: el `.env` local ya tiene `KEY_EPOCH` (modo estable) y `AUTO_ROTATION_ENABLED=true`. La rotación automática es **semanal**
  (`KEY_ROTATION_CRON`, domingo 02:00): en mantenimiento no entra ni sale nada salvo el aviso de rotación fallida; todo cambio en
  la rotación debe mantener las pruebas de caídas reales de `test/test_rotation.js` (proceso hijo `test/helpers/rotation-child.js`).
- ClamAV local (1.5.4, servicio `ClamD` en arranque **manual**: `Start-Service ClamD`); instaladores con menú en `instalar.*` e
  `instalador/` (`docs/INSTALL.md`). Linux y macOS sin ejecutar todavía.
- Archivos en S3 con driver propio (`src/files/s3-store.js`); interfaz web con alcance completo.

## Flujo de git (obligatorio)

- **Ramas (decisión del propietario, 15-nov-2026):** solo existe **`main`**, la rama oficial. Cada tarea usa una **rama corta**
  que sale de `main` actualizada (p. ej. `deps/…`, `fix/…`, `docs/…`, `orden/…`).
  `pruebas`, `postproduccion`, `cierre/*`, `instalador` y `revision-codigo` se borraron (todo estaba fusionado en `main`); el único
  commit suelto que había (rama `claude/project-thread-qjkfd0`) se conserva en la etiqueta `archivo/project-thread-qjkfd0`.
- **El propietario valida antes de `main` (decisión del 15-nov-2026):** tras cada commit se sube **solo la rama corta**
  (`git push origin HEAD:<rama>`); **no** se avanza `main` ni se borra la rama hasta que el propietario la revise y dé el visto
  bueno. Con su validación: avance rápido de `main` (`git push origin <rama>:main`) y borrar la rama, local y remota.
- Si `main` avanzó mientras tanto (PR fusionados, correcciones automáticas de GitHub), primero `git fetch` + `git merge origin/main`
  en la rama y volver a subirla (nunca rebase).
- Nunca acumular commits solo en local. **Nunca** rebase de ramas publicadas ni `push --force` (tampoco a `main`).
- Comprobar tras cada subida que local = remoto en la rama; al pasar a `main`, `git merge-base --is-ancestor origin/main <rama>`.
- Historial: las fases `cierre/0-base` … `cierre/8-bd` ya están fusionadas en `main` (PR #26, #33–#35).
- Credencial: el Git Credential Manager tiene varias cuentas; este repositorio fija `credential.https://github.com.username=AshuraRhoAias`
  en su config local. Con eso `GCM_INTERACTIVE=never git push` no abre ventanas. Si vuelve a pedir usuario, revisar esa clave.

## Verificar en CI

- Jobs de `.github/workflows/ci.yml`: `test` (MariaDB 10.11), `web` (e2e en Chromium, Firefox y WebKit + axe), `compose`
  (2 réplicas + nginx + MariaDB + SeaweedFS), `pruebaslinux` (Semgrep propio como puerta), `production-install`.
- Los registros completos de Actions exigen sesión; los pasos que fallan publican sus líneas clave como **anotaciones**
  (`.github/scripts/annotate-log.sh`), legibles con la API pública: `GET /repos/AshuraRhoAias/secure-server/check-runs/<id>/annotations`.
  Límite sin autenticar: 60 peticiones/hora; consultar como mucho cada 5 minutos.
- No dar nada por verificado sin evidencia: si algo solo se probó en local, o no se ejecutó, decirlo.

## Invariantes de seguridad (no deshacer)

- SQL siempre con parámetros `?`; lo que no admite parámetro, con `sqlInt` / `sqlPlaceholders` / `sqlFragment` (`src/config/sql.js`).
- `jwt.verify` siempre con `{ algorithms: ['HS256'] }`. MFA: exactamente **un** factor por petición.
- `DISABLE_IP_BLOCKING` nunca actúa con `NODE_ENV=production` (el servidor no arranca).
- Los tokens nunca llegan al navegador: cookies `httpOnly` del BFF; el SSO entrega un **código de un solo uso**, no tokens en la URL.
- Nada de secretos nuevos en el repositorio ni en `graphify-out/`. `test.js` tenía una contraseña real de una BD remota (sigue en el
  historial: la rotación es del propietario).
- La alerta de CodeQL `js/user-controlled-bypass` en `src/security/mfa.service.js` es un **falso positivo** analizado; no "arreglarla"
  debilitando la verificación.

## Documentación

- `docs/ReadmeLogsMejoras.md`: cada entrega es una entrada `#N` con **Estado, Archivos y módulos revisados, Problema detectado, Acciones
  realizadas, Pruebas ejecutadas, Puntuación, Problemas restantes, Siguiente mejora**; §C puntúa 7 criterios (F, S, Q, E, R, T, D)
  y distingue evaluado / parcial / no evaluado; actualizar también §A, §D, §E y §F en cada fase.
- Endpoints: código → `docs/openapi.json` → tabla del README (`npm run docs:endpoints -- --write`). Las pruebas fallan si se desincronizan.

## Lo que ya enseñó el CI (no reintroducir)

- En el contenedor el código es de solo lectura: nada escribe en `src/` (notificaciones en `NOTIFICATIONS_DIR`).
- `ALTER TABLE … ADD PRIMARY KEY (…) PARTITION BY …` va **sin coma** antes de `PARTITION BY`.
- Las imágenes de MinIO ya no se publican: el S3 de referencia es SeaweedFS, con `S3_SSE=none` (los archivos ya van cifrados).
- Playwright no intercepta peticiones que llegan por redirección (el IdP simulado atiende `/authorize`).
- Las pruebas que miden duraciones o leen streams deben tolerar runners lentos (sin carreras con temporizadores).

## Herramientas de contexto (obligatorio)

### graphify: para ENTENDER el código
Úsalo ANTES de leer o buscar archivos.
- Arquitectura o "¿cómo funciona X?" → `graphify query "<pregunta>"`
- Un símbolo concreto → `graphify explain "<Nombre>"`
- Relación entre dos cosas → `graphify path "A" "B"`
- Solo abre archivos después, y con rango de líneas (Read con offset/limit).
- Si el grafo no tiene el símbolo o está desactualizado → `graphify update .` y repite.
- Al terminar cambios que agreguen o borren archivos, funciones o imports → `graphify update .`

### context-mode: para EJECUTAR y LEER salidas grandes
Úsalo para cualquier comando o lectura que produzca más de ~50 líneas.
- Tests (`npm test`, `npm run coverage`) → `ctx_execute` con intent "lista de pruebas fallidas con su error"
- Logs (docker, PruebasLinux/logs, api.log) → `ctx_execute` filtrando errores
- `git log`, `git diff` grandes, `npm audit`, `semgrep` → `ctx_execute` o `ctx_batch`
- Documentación web → `ctx_index` + `ctx_search`
- Varios comandos relacionados → un solo `ctx_batch` con las queries que necesitas
- Después de una compactación → `ctx_resume` antes de continuar

### Regla de decisión
| Necesito… | Uso |
|---|---|
| Saber dónde está / cómo se conecta algo | graphify |
| Ver el resultado de algo que ejecuté | context-mode |
| Editar un archivo | Read con rango de líneas → Edit |

### Prohibido
- Grep/Glob masivo sobre `src/` sin consultar antes el grafo.
- `cat` de archivos completos > 300 líneas.
- Volcar salidas completas de tests o logs al contexto.

## Plugin ECC (obligatorio, junto con graphify y context-mode)

El plugin **ECC** (`/ecc:*`, skills `ecc:*` y agentes `ecc:*`) se usa en todo el flujo de trabajo. No sustituye a las reglas
anteriores: graphify sigue siendo el primer paso para entender código y context-mode para salidas grandes; ECC aporta los
flujos, las revisiones y las puertas de calidad. Si una skill de ECC choca con este archivo (idioma, flujo de git, invariantes,
decisiones del propietario), **manda este archivo**.

| Momento | Usar de ECC |
|---|---|
| Planificar una función o fase | `/ecc:plan` · agentes `ecc:planner` / `ecc:architect` |
| Función nueva / cambio / defecto | `/ecc:orch-add-feature` · `/ecc:orch-change-feature` · `/ecc:orch-fix-defect` (prueba que falla primero: skill `ecc:tdd-workflow`) |
| Tras escribir código | agentes `ecc:code-reviewer` y `ecc:security-reviewer` (siempre que toque entrada de usuario, auth, cripto o SQL) · `/ecc:code-review` |
| JS/TS, React/Next (`web/`) | agentes `ecc:typescript-reviewer`, `ecc:react-reviewer` · `/ecc:react-review` |
| SQL, esquema y migraciones | skills `ecc:mysql-patterns`, `ecc:postgres-patterns`, `ecc:database-migrations` · agente `ecc:database-reviewer` |
| Errores silenciosos / manejo de errores | agente `ecc:silent-failure-hunter` · skill `ecc:error-handling` |
| Build o tipos rotos | `/ecc:build-fix` · agente `ecc:build-error-resolver` |
| Pruebas e2e (Playwright) | skill `ecc:e2e-testing` · agente `ecc:e2e-runner` |
| Cobertura y calidad antes de commit | `/ecc:test-coverage` · `/ecc:quality-gate` · skill `ecc:verification-loop` |
| Seguridad del repositorio y la configuración | `/ecc:security-scan` · skill `ecc:security-review` |
| Commit y PR | `/ecc:prp-commit` · `/ecc:pr` (respetando el **Flujo de git** de arriba: se sube la rama, el propietario la valida y después `main` por avance rápido, sin force) |
| Documentación | `/ecc:update-docs` (además de las reglas de `docs/ReadmeLogsMejoras.md` y OpenAPI → README) |
| Dudas sobre qué usar de ECC | `/ecc:ecc-guide` |

- Los prompts de agentes `ecc:*` que exploren código deben incluir la regla de graphify (consultar el grafo antes de leer).
- Los hooks de ECC (p. ej. GateGuard, que pide declarar la petición y el propósito antes del primer comando Bash) se respetan;
  no desactivarlos sin que lo pida el propietario.
- Las skills `ecc:multi-*` y `ecc:council-multi-model` necesitan runtimes externos: solo si el propietario lo pide.

## graphify

This project has a knowledge graph at graphify-out/ with god nodes, community structure, and cross-file relationships.

Rules:
- When graphify-out/graph.json exists, run `graphify query "<question>"` before your first grep, search or source-file read for a codebase question, and put this rule in every subagent prompt that explores code. Read raw files only for lines the graph or an earlier read already located. Use `graphify path "<A>" "<B>"` for relationships and `graphify explain "<concept>"` for focused concepts. These return a scoped subgraph, usually much smaller than GRAPH_REPORT.md or raw grep output.
- If graphify-out/wiki/index.md exists, use it for broad navigation instead of raw source browsing.
- Read graphify-out/GRAPH_REPORT.md only for broad architecture review or when query/path/explain do not surface enough context.
- After modifying code, run `graphify update .` to keep the graph current (AST-only, no API cost).
- A committed graphify-out/graph.json is rewritten whole on every build, so a large diff to it in a pull request is expected. Do not flag it as churn or suggest skipping the graph rebuild or its hooks.
