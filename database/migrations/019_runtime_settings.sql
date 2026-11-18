-- 019: configuración en caliente desde la interfaz web (FASE 2).
--
-- runtime_settings: un ajuste operativo seguro por fila (catálogo cerrado en src/config/runtime-settings.js).
--   value_json: valor validado (número, booleano o texto, en JSON). Sin fila = se usa el .env o el valor por defecto.
--   updated_by: administrador que lo cambió (NULL si ese usuario se borró).
-- Idempotente: se puede ejecutar dos veces.

CREATE TABLE IF NOT EXISTS `runtime_settings` (
  `setting_key` varchar(64) NOT NULL,
  `value_json` text NOT NULL,
  `updated_by` int(11) DEFAULT NULL,
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`setting_key`),
  KEY `idx_runtime_settings_user` (`updated_by`),
  CONSTRAINT `runtime_settings_user_fk` FOREIGN KEY (`updated_by`) REFERENCES `users` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
