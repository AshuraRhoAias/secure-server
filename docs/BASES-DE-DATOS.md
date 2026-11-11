# Bases de datos: estado, portabilidad y plan

Decisión del propietario (10-nov-2026): **soporte SQL ahora** (MariaDB/MySQL y PostgreSQL, que incluye **Supabase**) detrás de
un adaptador de dialecto, con los dos motores probados en el CI. **MongoDB queda para una fase posterior**: no es SQL y exige una
capa de repositorios (ver §5).

## 1. Cómo accede hoy el código a la base de datos

- **Un único punto de entrada**: `src/config/database.js`, el único archivo que importa `mysql2`. Expone `query`, `readQuery`
  (réplica de lectura opcional), `withConnection`, `transaction`, `close`, `testConnection` y `secureQuery`.
- **39 archivos** lo usan con **≈ 230 consultas SQL escritas a mano**, todas parametrizadas (`?`; lo que no admite parámetro pasa
  por `sqlInt` / `sqlPlaceholders` / `sqlFragment` de `src/config/sql.js`).
- Los llamantes esperan la forma de `mysql2`: `const [rows] = await db.query(...)` y, en escrituras, `result.affectedRows` y
  `result.insertId`.
- Archivos con más consultas: `secure-auth.service.js` (27), `alerts.service.js` (21), `rotation.service.js` (19),
  `privacy.service.js` (14), `mfa.service.js` (14), `auth.controller.js` (12).

Conclusión: la arquitectura ya está centralizada (bien), pero el **SQL es dialecto MySQL**. Cambiar de driver no basta.

## 2. Inventario de acoplamiento a MySQL/MariaDB y su equivalente en PostgreSQL

| Construcción | Usos | Dónde | PostgreSQL / Supabase |
|---|---|---|---|
| Marcadores `?` | todas | todas | `$1, $2…` (el adaptador los traduce; cuidado con `?` dentro de literales) |
| `` `identificador` `` | 43 en 29 archivos | consultas y esquema | `"identificador"` o sin comillas |
| `NOW()` | 111 en 21 archivos | casi todos los servicios | `NOW()` existe (devuelve `timestamptz`): compatible |
| `DATE_SUB/DATE_ADD(NOW(), INTERVAL ? DAY)` | 86 en 11 archivos | sesiones, eventos, alertas, purgas | `NOW() - make_interval(days => $1)` → helper de dialecto |
| `ON DUPLICATE KEY UPDATE` / `INSERT IGNORE` | 8 en 7 archivos | guard, rotación, serverCheck, anomalías, limitador, auth, SAML | `ON CONFLICT (…) DO UPDATE / DO NOTHING` (exige nombrar la clave) |
| `result.insertId` | 15 en 8 archivos | auth, files, notes, aprobaciones, alertas, limitador, webauthn, usuarios federados | `INSERT … RETURNING id` (el adaptador lo añade y lo normaliza) |
| `result.affectedRows` | 42 en 19 archivos | escrituras condicionales (anti-replay, canjes de un solo uso) | `rowCount` (el adaptador lo normaliza) |
| `GET_LOCK` / `IS_USED_LOCK` / `RELEASE_LOCK` | 9 en 3 archivos | `tasks/leader.js`, `maintenance/guard.js`, `rotation.service.js` | `pg_try_advisory_lock(hashtext(…))` / `pg_advisory_unlock`; **de sesión**: hay que retener una conexión dedicada (como ya hace `leader.js`) |
| `SUM(condición)` | 2 archivos | `observability/live-stream.js`, `rate-limiter.service.js` | **falla en PostgreSQL** (boolean): `COUNT(*) FILTER (WHERE …)` o `SUM(CASE WHEN … THEN 1 ELSE 0 END)` (portable) |
| `GREATEST` / `IFNULL` / `COALESCE` | 17 en 6 archivos | panel, stream | `GREATEST`/`COALESCE` existen; `IFNULL` → `COALESCE` (portable) |
| `UNIX_TIMESTAMP` / `TIMESTAMPDIFF` / `JSON_*` | 5 en 2 archivos | `index.js`, `secure-auth.service.js` | `EXTRACT(EPOCH FROM …)`, aritmética de fechas, `jsonb` |
| `SELECT … FOR UPDATE` | 2 archivos | `files.controller.js`, rotación | igual en PostgreSQL |
| `TO_DAYS` + `PARTITION BY RANGE` + `information_schema.PARTITIONS` | 3 archivos | `maintenance/events-partitions.js` | particionado declarativo de PostgreSQL (`PARTITION BY RANGE (created_at)`): **implementación propia por dialecto** o desactivado fuera de MySQL |
| `information_schema` (otras) | 4 archivos | rotación, auditoría | existe en PostgreSQL con otras columnas: revisar caso a caso |
| `multipleStatements` | `database.js` | carga del esquema en pruebas | `pg` ejecuta varias sentencias en una consulta simple (sin parámetros) |
| **Esquema** | 23 tablas | `database/schema.sql` + migraciones | `ENUM` (15) → `CHECK` o tipo `ENUM`; `AUTO_INCREMENT` (29) → `GENERATED … AS IDENTITY`; `datetime(3)` → `timestamp(3)`; `ENGINE=InnoDB`/`CHARSET` fuera; `ON UPDATE current_timestamp` (3) → trigger |

## 3. Diseño elegido (fase SQL)

1. **Adaptador en `src/config/database.js`**: `DB_CLIENT=mysql` (por defecto; MariaDB y MySQL) o `postgres` (PostgreSQL y
   Supabase). Ambos devuelven la **misma forma** que hoy (`[rows]`, y en escrituras `{ affectedRows, insertId }`), así los ≈ 230
   llamantes no cambian de golpe.
2. **Helpers de dialecto en `src/config/sql.js`** para lo que no se puede traducir de forma segura: intervalos de fecha, upsert,
   insert-ignore, cerrojos con nombre. Se sustituyen las construcciones de la tabla de §2 por esos helpers, módulo a módulo.
3. **Esquema por dialecto**: `database/schema.sql` (MySQL) y `database/postgres/schema.sql`, con una prueba que compare tablas y
   columnas de los dos para que no diverjan.
4. **Particionado de eventos**: se mantiene para MySQL; en PostgreSQL, implementación propia o desactivado (documentado).
5. **CI**: el job `test` actual (MariaDB 10.11) más un job nuevo con PostgreSQL que ejecute las mismas suites. **Sin ese job no se
   afirma soporte de PostgreSQL.**

Orden: primero el adaptador **solo con MySQL** y todo en verde (local y CI); después PostgreSQL, módulo a módulo.

### Estado (11-nov-2026)

| Paso | Estado |
|---|---|
| 1. Adaptador con el driver MySQL | **Hecho.** `src/config/db-drivers/index.js` (elige el motor con `DB_CLIENT` y documenta el **contrato**) y `db-drivers/mysql.js` (único archivo de `src/` y `scripts/` que importa `mysql2`). `database.js` ya no conoce el driver. `DB_CLIENT=postgres` da un error claro hasta que el paso 4 esté en verde. `test_db.js`: elección del motor, «un único punto de entrada» y el contrato contra la base real (`[filas]`, `insertId`, `affectedRows` de los canjes de un solo uso, transacciones, conexión retenida con `destroy`), que es lo mismo que tendrá que pasar el driver de PostgreSQL. |
| 2. SQL portable sin cambiar resultados en MySQL (`SUM(CASE …)`, `COALESCE`, helpers de intervalos/upsert/cerrojos) | Pendiente |
| 3. Esquema `database/postgres/schema.sql` + prueba de paridad | Pendiente |
| 4. Driver `postgres` (`pg`, traducción de `?`, `RETURNING id`, `rowCount`) + job del CI con PostgreSQL | Pendiente |

**Contrato del driver** (detalle en `src/config/db-drivers/index.js`): es el subconjunto de `mysql2/promise` que usa el proyecto,
para que los ≈ 230 llamantes no cambien: `pool.getConnection()` / `pool.end()`; `conn.execute|query(sql, params)` → `[filas]` o
`[{ affectedRows, insertId }]`; `beginTransaction` / `commit` / `rollback` / `release` / `destroy` / `on('error')`. Las consultas siguen
con `?`; un driver que use `$1…` los traduce él.

## 4. MariaDB local (Windows)

- Servidor del propietario: **MariaDB 13.1.1**, servicio `MariaDB`, puerto 3306. El CI usa **MariaDB 10.11**: algo verde en uno no
  prueba el otro.
- Preparación de las bases de prueba (las mismas que el CI): `database/setup-local.sql`, que ejecuta el propietario con su cuenta
  de administrador. El proyecto no usa ni guarda la contraseña de root.
- Credenciales: nunca en `.env` (está versionado y el repositorio es público). Lo local va en `.env.local` (ignorado) o en el
  propio entorno; el `.env` tiene `skip-worktree` para que un cambio local no se suba por accidente.

## 5. MongoDB (fase posterior)

No es un cambio de dialecto: no hay SQL, ni transacciones multi-tabla iguales, ni `GET_LOCK`, ni claves foráneas. Requiere una
**capa de repositorios** (una por entidad: usuarios, sesiones, eventos, alertas, archivos…) con dos implementaciones (SQL y Mongo),
índices únicos equivalentes, cerrojos con documentos con TTL y otro diseño para particionado y purgas. Se planifica cuando la fase
SQL esté en verde.
