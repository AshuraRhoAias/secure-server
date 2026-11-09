-- Migración 007: origen (IP o /64) en login_attempts
--
-- Permite que el bloqueo de cuenta sea POR ORIGEN: quien falla 5 veces desde una IP se bloquea a sí
-- mismo, no al dueño de la cuenta que entra desde otro sitio. También permite reconocer los
-- "orígenes de confianza" de un usuario (desde donde ya inició sesión con éxito).

ALTER TABLE `login_attempts`
  ADD COLUMN IF NOT EXISTS `ip_subject` varchar(45) NOT NULL DEFAULT '' AFTER `ip_address`,
  ADD KEY `idx_la_user_subject` (`username_hash`, `ip_subject`, `success`, `id`);
