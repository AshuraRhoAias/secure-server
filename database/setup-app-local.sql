-- Preparación de la base de datos REAL de la aplicación en una MariaDB/MySQL LOCAL, con un usuario propio y de mínimos privilegios.
-- (setup-local.sql crea solo las bases de PRUEBA; la aplicación nunca debe conectarse como root.)
--
-- ANTES DE EJECUTARLO: sustituye el marcador CAMBIA_ESTA_CLAVE (aparece dos veces) por una contraseña propia y larga, y usa
-- esa MISMA contraseña en el .env (ver docs/INSTALL.md, «Base de datos de la aplicación (local)»). No subas la clave elegida
-- al repositorio: edita una copia local o sustitúyela solo en el momento de ejecutarlo.
--
-- Lo ejecuta el propietario con su cuenta de administrador; el proyecto nunca usa ni guarda la contraseña de root.
--
--   PowerShell:  Get-Content database\setup-app-local.sql | & "C:\Program Files\MariaDB 13.1\bin\mariadb.exe" -uroot -p
--   bash:        mariadb -uroot -p < database/setup-app-local.sql
--
-- Es idempotente: se puede ejecutar varias veces (CREATE ... IF NOT EXISTS; el ALTER USER final deja siempre la contraseña
-- vigente que pongas en este archivo).
--
-- ESQUEMA: la aplicación NO crea sus tablas al arrancar (solo crypto_meta, en la rotación de claves). Después de este script
-- hay que importar el esquema, ya con el usuario secure_app (no con root):
--
--   PowerShell:  Get-Content database\schema.sql | & "C:\Program Files\MariaDB 13.1\bin\mariadb.exe" -u secure_app -p secure_platform
--   bash:        mariadb -u secure_app -p secure_platform < database/schema.sql
--
-- schema.sql ya incluye todas las migraciones (database/migrations/NNN_*.sql solo se aplican a una base creada antes).
--
-- Sin REQUIRE SSL a propósito: `npm run dev` y las pruebas se conectan sin TLS. En producción la aplicación exige TLS por su
-- lado (DB_SSL=verify, ver docs/INSTALL.md «TLS hacia MariaDB»).

CREATE DATABASE IF NOT EXISTS secure_platform CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- Por TCP (127.0.0.1) o por nombre (localhost): según la resolución, el servidor ve uno u otro.
-- IDENTIFIED BY usa el plugin de autenticación por defecto, igual que `sec` (que funciona con mysql2).
CREATE USER IF NOT EXISTS 'secure_app'@'localhost'  IDENTIFIED BY 'CAMBIA_ESTA_CLAVE';
CREATE USER IF NOT EXISTS 'secure_app'@'127.0.0.1' IDENTIFIED BY 'CAMBIA_ESTA_CLAVE';

-- Si el usuario ya existía, el CREATE anterior no cambia su clave: la dejamos al día (idempotente).
ALTER USER 'secure_app'@'localhost'  IDENTIFIED BY 'CAMBIA_ESTA_CLAVE';
ALTER USER 'secure_app'@'127.0.0.1' IDENTIFIED BY 'CAMBIA_ESTA_CLAVE';

-- Privilegios SOLO sobre secure_platform.* (nunca *.*, ni GRANT OPTION, ni SUPER/FILE/PROCESS):
--   SELECT, INSERT, UPDATE, DELETE  consultas normales de la API; la copia de seguridad lee todo y la restauración borra e inserta.
--   CREATE      CREATE TABLE IF NOT EXISTS crypto_meta (rotación de claves) y la restauración de una copia (recrea tablas ausentes);
--               también para importar schema.sql con este usuario.
--   ALTER       particiones de security_events (src/maintenance/events-partitions.js: PARTITION BY, REORGANIZE y DROP PARTITION)
--               y migraciones nuevas (database/migrations).
--   DROP        ALTER TABLE ... DROP PARTITION (caducar meses enteros) exige este privilegio sobre la tabla.
--   INDEX       índices de schema.sql y de las migraciones (CREATE INDEX / ADD KEY).
--   REFERENCES  claves foráneas del esquema (FOREIGN KEY ... REFERENCES).
-- No hacen falta: LOCK TABLES (los cerrojos son GET_LOCK(), que no requiere privilegio), CREATE TEMPORARY TABLES, TRIGGER,
-- EVENT, CREATE VIEW ni ROUTINE (el esquema no los usa).
GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, DROP, INDEX, REFERENCES ON secure_platform.* TO 'secure_app'@'localhost';
GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, DROP, INDEX, REFERENCES ON secure_platform.* TO 'secure_app'@'127.0.0.1';
FLUSH PRIVILEGES;

SELECT 'OK: base secure_platform y usuario secure_app listos (falta importar database/schema.sql)' AS resultado;
