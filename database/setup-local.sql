-- Preparación de una MariaDB/MySQL LOCAL para ejecutar las pruebas con base de datos (las mismas que crea el CI).
-- Lo ejecuta el propietario con su cuenta de administrador; el proyecto nunca usa ni guarda la contraseña de root.
--
--   PowerShell:  Get-Content database\setup-local.sql | & "C:\Program Files\MariaDB 13.1\bin\mysql.exe" -uroot -p
--   bash:        mariadb -uroot -p < database/setup-local.sql
--
-- Es idempotente (se puede ejecutar varias veces). El usuario `sec` / `sec_test_pw` es SOLO de pruebas (el mismo que el CI,
-- público en .github/workflows/ci.yml) y solo tiene permisos sobre las dos bases de prueba. No lo uses para datos reales.
--
-- Después:  npm run test:all     (test_helpers/env.js usa mysql://sec:sec_test_pw@127.0.0.1:3306/secure_platform_test_app;
--                                 otra URL con TEST_APP_DB_URL)

CREATE DATABASE IF NOT EXISTS secure_platform_test     CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE DATABASE IF NOT EXISTS secure_platform_test_app CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- Las pruebas se conectan por TCP a 127.0.0.1; según la resolución de nombres el servidor lo ve como 'localhost' o '127.0.0.1'
CREATE USER IF NOT EXISTS 'sec'@'localhost' IDENTIFIED BY 'sec_test_pw';
CREATE USER IF NOT EXISTS 'sec'@'127.0.0.1' IDENTIFIED BY 'sec_test_pw';

GRANT ALL PRIVILEGES ON secure_platform_test.*     TO 'sec'@'localhost';
GRANT ALL PRIVILEGES ON secure_platform_test_app.* TO 'sec'@'localhost';
GRANT ALL PRIVILEGES ON secure_platform_test.*     TO 'sec'@'127.0.0.1';
GRANT ALL PRIVILEGES ON secure_platform_test_app.* TO 'sec'@'127.0.0.1';
FLUSH PRIVILEGES;

SELECT 'OK: bases de prueba y usuario sec listos' AS resultado;
