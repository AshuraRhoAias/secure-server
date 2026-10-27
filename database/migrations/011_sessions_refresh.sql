-- Migración 011: sesiones con access token corto + refresh token con rotación
--
-- Antes: un JWT de 5 días por sesión, identificado por su hash. Ahora el JWT de acceso dura minutos y la sesión
-- (esta fila) se renueva con un refresh token opaco que ROTA en cada uso. Solo se guarda el hash del refresh.
--
--   expires_at           caducidad por INACTIVIDAD de la sesión (deslizante)
--   absolute_expires_at  tope absoluto: pasado este momento hay que iniciar sesión de nuevo
--   prev_refresh_hash    refresh anterior: si alguien lo presenta fuera de la gracia, el token fue robado => se revoca la sesión
--
-- IMPORTANTE: se quita el ON UPDATE de expires_at. Con él, cualquier UPDATE de la fila que no lo fijara
-- explícitamente reiniciaba la caducidad.

ALTER TABLE `user_sessions`
  MODIFY `expires_at` timestamp NOT NULL DEFAULT current_timestamp(),
  ADD COLUMN IF NOT EXISTS `session_uid` char(36) DEFAULT NULL AFTER `jwt_token_hash`,
  ADD COLUMN IF NOT EXISTS `refresh_hash` char(64) DEFAULT NULL AFTER `session_uid`,
  ADD COLUMN IF NOT EXISTS `prev_refresh_hash` char(64) DEFAULT NULL AFTER `refresh_hash`,
  ADD COLUMN IF NOT EXISTS `refreshed_at` timestamp NULL DEFAULT NULL AFTER `prev_refresh_hash`,
  ADD COLUMN IF NOT EXISTS `absolute_expires_at` timestamp NULL DEFAULT NULL AFTER `expires_at`,
  ADD COLUMN IF NOT EXISTS `last_used_at` timestamp NULL DEFAULT NULL AFTER `absolute_expires_at`,
  ADD COLUMN IF NOT EXISTS `amr` varchar(60) DEFAULT NULL AFTER `last_used_at`,
  ADD COLUMN IF NOT EXISTS `revoked_at` timestamp NULL DEFAULT NULL AFTER `amr`,
  ADD COLUMN IF NOT EXISTS `revoked_reason` varchar(40) DEFAULT NULL AFTER `revoked_at`,
  ADD UNIQUE KEY IF NOT EXISTS `uq_sessions_uid` (`session_uid`),
  ADD KEY IF NOT EXISTS `idx_sessions_refresh` (`refresh_hash`),
  ADD KEY IF NOT EXISTS `idx_sessions_prev_refresh` (`prev_refresh_hash`);
