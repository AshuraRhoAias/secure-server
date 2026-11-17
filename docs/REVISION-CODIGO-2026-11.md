# Revisión del código — 12-nov-2026

Revisión de `src/` (92 archivos, ≈ 14 000 líneas), `scripts/` (14), `web/src/` (52) y la configuración. Cada hallazgo dice **cómo se
verificó** y si **se corrigió** en esta entrega o **se propone** (lo que cambia el comportamiento o necesita una decisión del propietario
no se toca sin su visto bueno). Lo que no se pudo comprobar se dice.

## 1. Estado general (con evidencia)

| Comprobación | Resultado |
|---|---|
| Suite completa del API en local (Windows, MariaDB 13.1, ClamAV 1.5.4) | **602/603** tras las correcciones, 0 fallos, 1 omitida (`SIGHUP`, no existe en Windows) — 12-nov |
| Cobertura (`npm run coverage`) | ver §4 |
| Lint de seguridad (`eslint src scripts`, 0 avisos permitidos) | 0 avisos |
| `npm audit --omit=dev` (raíz y `web/`) | **0 vulnerabilidades** |
| CI (MariaDB 10.11, e2e, compose) del adaptador de BD | **no verificado** desde este equipo (la API pública de GitHub no responde) |
| `web/`: tokens en el navegador, `innerHTML`, `eval` | ninguno: `localStorage` solo guarda el tema; `Authorization` solo en el servidor del BFF |

Falsos positivos descartados al leer el código (no son problemas): 8 respuestas con `error.message` (todas son errores de dominio
tipados con mensajes pensados para el cliente), 6 «TODO» (es la palabra española), `setInterval` sin `unref` (son del cierre ordenado),
`Math.random` (elige plantillas e identificadores, nada criptográfico).

## 2. Hallazgos por gravedad

| # | Gravedad | Hallazgo | Dónde | Evidencia | Estado |
|---|---|---|---|---|---|
| 1 | **Alta** (configuración) | El `.env` local tiene `NODE_ENV=production` y **no tiene `KEY_EPOCH`**: el servidor usa el modo de claves `legacy`, en el que la clave de cifrado **cambia cada día UTC**. Lo cifrado un día (notas, nombres de usuario, secretos de MFA) no se descifra al siguiente. El servidor arranca así en producción con solo un aviso. | `src/crypto/key-provider.js:14-17,71-84`; `.env` | Lectura del código (el propio comentario lo dice) y del `.env` (solo las líneas `NODE_ENV` y `KEY_EPOCH`) | **Corregido en el `.env` local** (12-nov, a petición del propietario): `KEY_EPOCH` definida; la BD local no tenía datos de la aplicación (el usuario del `.env` no existe en esa MariaDB), así que no había nada que migrar. Sigue propuesto (§3.1.2): no arrancar en producción con claves `legacy` |
| 2 | Media | `getSecret()` devolvía una clave **fija y pública** (`scrypt('fallback_<tipo>', 'dynamic_salt')`) si faltaba un secreto, en vez de fallar | `src/config/secure-env.js:69-71` | Lectura; hoy inalcanzable desde el servidor (siempre hay secretos derivados), pero es una trampa | **Corregido**: lanza un error |
| 3 | Media-baja | En modo `legacy`, sin `BASE_SEED` las claves salían de la cadena conocida `default_seed_change_this`. `index.js` exige `BASE_SEED`, pero `scripts/rotateKeys.js` y `scripts/emergencyRecovery.js` no pasan por él | `src/crypto/key-provider.js:72` | Lectura; ninguna prueba depende del valor por defecto | **Corregido**: `BASE_SEED` obligatoria también en `legacy` (se mantiene `jwt_default` para `JWT_SEED`: replica la fórmula antigua) |
| 4 | Baja | **Código muerto peligroso**: `cleanupEmptyUsernames()` borra usuarios y escribe en el registro hashes y textos cifrados; `validateDataIntegrity()`; `secureQuery()` (contaba mal: `result.affectedRows` sobre `[filas]` siempre daba 1) y su `logDatabaseAccess()` | `src/api/controllers/auth.controller.js:678-760`; `src/config/database.js:217-256` | Sin ningún llamante en `src/`, `scripts/`, pruebas ni `web/` | **Corregido**: eliminado |
| 5 | Baja | Las alertas por correo se «camuflan» como informes (seguridad por oscuridad) y la de rotación fallida incluye `error.message` (detalle interno) | `src/services/secure-communications.service.js:200`; `src/tasks/scheduleKeyRotation.js:113` | Lectura (no viajan claves: el nombre `encodeKeysInMessage` engaña) | Propuesto |
| 6 | Rendimiento | `/api/notes` pagina con `LIMIT … OFFSET`: coste lineal con la página | `src/api/controllers/notes.controller.js:46-56` | Lectura; el índice `(user_id, created_at)` existe | Propuesto: paginación por cursor (`id < ?`) |
| 7 | Rendimiento | El stream en vivo consulta la BD **por conexión** cada 2 s (≤ 100 por proceso → ≈ 150 consultas/s en el tope) | `src/observability/live-stream.js:117-179` | Lectura; está acotado y con `unref` | Propuesto: un sondeo compartido por proceso que reparte a cada cursor |
| 8 | Rendimiento | Cada cifrado/descifrado deriva la clave de campo con HKDF y valida el hex | `src/crypto/tripleEncryptor.js:36-42` | Lectura | Propuesto: memorizar por clave maestra (con microbenchmark y `test_rotation` en verde) |
| 9 | Rendimiento | El informe de rendimiento (`benchmarks/INFORME_RENDIMIENTO.md`) es del **21-oct**, anterior al cifrado v4 y a quitar la auditoría de cada lectura: sus 8,3 req/s de `/api/notes` **ya no describen** el código actual | — | Fecha del informe | Propuesto: volver a medir |
| 10 | Mantenibilidad | Módulos muy grandes: `auth.controller.js` (962 líneas), `secure-auth.service.js` (766), `rotation.service.js` (751), `index.js` (571) | — | `wc -l` y nodos centrales del grafo | Propuesto: dividir por responsabilidad (MFA, WebAuthn, sesiones) |
| 11 | Mantenibilidad | ≈ 100 `console.log` en `src/` sin niveles ni formato estructurado | `src/` | Recuento | Propuesto: registro con niveles (JSON) y `LOG_LEVEL` |
| 12 | Portabilidad | SQL acoplado a MySQL (fechas, upsert, `GET_LOCK`, esquema) | `docs/BASES-DE-DATOS.md` §2 | Inventario | En curso (pasos 2–4) |
| 13 | Dependencias | Actualizaciones menores disponibles (`@aws-sdk/*`, `axios` 1.21.1, `helmet` 8.3, `jose` 6.2.17, `@simplewebauthn/server` 14.1…) | `package.json` | `npm outdated` | Propuesto: dejar que Dependabot abra los PR |
| 14 | Pruebas | Instaladores de Linux y macOS sin ejecutar | `instalador/` | Solo hay Windows aquí | Propuesto: job del CI con `linux.sh --si` |

## 2 bis. Hallazgos de la revisión de la rotación (12-nov, #34)

| # | Gravedad | Hallazgo | Estado |
|---|---|---|---|
| 15 | **Alta** | `recover` trataba un error al consultar la BD como «no confirmado»: deshacía y borraba `.env.pending` (la única copia de las semillas nuevas) aunque la BD ya hubiera confirmado → datos cifrados con una clave perdida | **Corregido**: sin respuesta de la BD no decide nada |
| 16 | Media | La rotación no comprobaba que **seguía** teniendo el cerrojo de la BD antes de confirmar (si la BD cortó una rotación parada, otras máquinas podían haberse reabierto) | **Corregido** |
| 17 | Media | Durante el mantenimiento seguían la limpieza, la evaluación de alertas, los webhooks, los correos y los streams ya abiertos; `/health` daba 503 (un orquestador reiniciaría a mitad) | **Corregido**: sin entradas ni salidas salvo el aviso de fallo |
| 18 | Media | Una alerta enviada durante el mantenimiento se registraba **cifrada en la BD** con la clave del proceso, que podía ser ya la antigua → fila ilegible que haría abortar la rotación siguiente | **Corregido**: en mantenimiento no se escribe en la BD |
| 19 | Baja | La alerta de rotación fallida incluía `error.message`; `executeSessionCleanup` nunca informaba de lo borrado (`affectedRows` sobre `[filas]`) | **Corregido** |
| 20 | Baja | `node-cron` 4.2.1 calcula mal la próxima ejecución de expresiones semanales (devuelve 2034) | Se informa la programación (cron + zona) en vez de una fecha falsa |
| 21 | Información | Con este `.env` el servidor local no conecta a la MariaDB local: `NODE_ENV=production` exige TLS verificado (certificado autofirmado) y el usuario de BD del `.env` no existe allí | Propuesto: credenciales de prueba válidas o `NODE_ENV=development` en local |

## 3. Propuestas que necesitan decisión

### 3.1 Claves estables (hallazgo 1)
1. **Definir `KEY_EPOCH`** en el `.env` (lo hace el propietario: el `.env` tiene `skip-worktree`). Si ya hay datos cifrados en modo
   `legacy`, migrarlos antes con `node scripts/rotateKeys.js rotate --confirm --legacy-scan-days <días>` (ver `docs/SEGURIDAD.md`, rotación).
2. **Cambio de código propuesto** (no aplicado): con `NODE_ENV=production`, no arrancar en modo `legacy` (fallar cerrado, como ya se hace
   con `DISABLE_IP_BLOCKING`). El CI, Docker y las pruebas ya definen `KEY_EPOCH`, así que solo afectaría a un `.env` como el local actual.

La corrección del hallazgo 3 destapó que `test/test_api.js` cargaba las claves **sin `BASE_SEED`** (se derivaban, sin avisar, de la semilla
conocida): ahora define su propia semilla de pruebas. Pruebas nuevas en `test/test_rotation.js` («sin semilla no hay claves») fijan las
dos correcciones; la fórmula antigua sin `JWT_SEED` sigue comprobada.

## 4. Cobertura (`npm run coverage`, 12-nov, local con MariaDB 13.1 y ClamAV)

**Líneas 77,2 % · ramas 84,1 % · funciones 90,6 %** (602 pruebas: 601 bien, 1 omitida). Lo menos cubierto en `src/`:

| Archivo | Líneas | Ramas | Lectura |
|---|---:|---:|---|
| `src/crypto/disguiser.js` | 0 % | 0 % | el «camuflaje» de correos (hallazgo 5): ninguna prueba lo ejecuta |
| `src/index.js` | 7 % | 43 % | el arranque se prueba en procesos hijo (`test_scale`, `test_av`…) que c8 no mide; no es falta de pruebas |
| `src/tasks/scheduleKeyRotation.js` | 20 % | 80 % | la rotación **programada** (la rotación en sí está cubierta en `rotation.service.js`) |
| `src/services/secure-communications.service.js` | 35 % | 33 % | envío de alertas por correo/Telegram (sin servidor SMTP en pruebas) |
| `src/observability/cluster-status.js` | 45 % | 45 % | estado agregado del cluster (cubierto por el e2e de la web, no por c8) |
| `src/middleware/serverCheck.middleware.js` | 54 % | 53 % | comprobaciones de integridad del servidor |
| `src/api/controllers/auth.controller.js` | 63 % | 78 % | (antes de quitar 280 líneas de código muerto, hallazgo 4) |

Propuesto: pruebas de `scheduleKeyRotation` y de las notificaciones con un SMTP simulado; decidir si el camuflaje se mantiene (hallazgo 5)
antes de probarlo.

## 5. Lo que no se ha comprobado

- El **CI** de los últimos commits (MariaDB 10.11, e2e en tres navegadores, compose): no se pudo leer desde este equipo.
- `web/`: revisión de patrones de seguridad hecha; typecheck, pruebas y build **no** se han vuelto a ejecutar en esta revisión (el equipo
  va justo de memoria y se priorizó la suite del API). Sus resultados del CI del 10-nov estaban en verde.
- Instaladores de Linux y macOS (hallazgo 14).
