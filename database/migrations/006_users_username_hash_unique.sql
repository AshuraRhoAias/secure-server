-- Migración 006: índice ÚNICO sobre users.username_hash
--
-- Sin él, dos registros simultáneos del mismo usuario podían crear dos filas con el mismo hash
-- y el login de esa cuenta quedaba ambiguo. (NULL se permite repetido: usuarios muy antiguos.)
--
-- Si falla con "Duplicate entry", hay usuarios duplicados que hay que resolver a mano antes:
--   SELECT username_hash, COUNT(*) FROM users GROUP BY username_hash HAVING COUNT(*) > 1;

ALTER TABLE `users` ADD UNIQUE KEY `uq_users_username_hash` (`username_hash`);
