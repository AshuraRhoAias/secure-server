-- Migración 008: autenticación en dos pasos (TOTP) y códigos de recuperación
--
--   users.mfa_secret_encrypted   secreto TOTP, cifrado con v4 (registrado en encrypted-columns.js: la
--                                rotación de claves lo re-cifra)
--   users.mfa_enabled            1 cuando el usuario completó el alta con un código válido
--   users.mfa_last_step          último paso de 30 s aceptado: un código no se puede reutilizar
--   user_recovery_codes          códigos de un solo uso (solo se guarda su hash)

ALTER TABLE `users`
  ADD COLUMN IF NOT EXISTS `mfa_secret_encrypted` longtext DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS `mfa_enabled` tinyint(1) NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS `mfa_last_step` bigint(20) unsigned DEFAULT NULL;

CREATE TABLE IF NOT EXISTS `user_recovery_codes` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `user_id` int(11) NOT NULL,
  `code_hash` char(64) NOT NULL,
  `used_at` timestamp NULL DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_recovery_user_hash` (`user_id`, `code_hash`),
  CONSTRAINT `user_recovery_codes_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
