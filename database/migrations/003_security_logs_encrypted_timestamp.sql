-- Migración 003: security_logs.encrypted_timestamp pasa de DATETIME a LONGTEXT
--
-- El código (auth.controller, audit.service, ...) guarda ahí la fecha CIFRADA (texto hex), que no
-- cabe en un DATETIME. En MySQL/MariaDB en modo estricto (el predeterminado) cada INSERT falla con
-- "Incorrect datetime value" y el evento de auditoría se pierde en silencio; en modo no estricto
-- se guardaba '0000-00-00 00:00:00' y el dato cifrado se descartaba.
--
-- Los valores que no sean texto cifrado (ceros de DATETIME) se ponen a NULL.

SET SESSION sql_mode = '';

ALTER TABLE `security_logs` MODIFY `encrypted_timestamp` longtext DEFAULT NULL;

UPDATE `security_logs`
   SET `encrypted_timestamp` = NULL
 WHERE `encrypted_timestamp` IS NOT NULL
   AND `encrypted_timestamp` NOT REGEXP '^[0-9a-f]{24}:';
