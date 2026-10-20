-- Migración 001: roles de usuario + tabla de ejemplo para la API de notas
-- Compatible con MariaDB 10.x (el dump original usa current_timestamp()).
-- En MySQL 8 quita "IF NOT EXISTS" de ADD COLUMN y ejecútala una sola vez.

ALTER TABLE `users`
  ADD COLUMN IF NOT EXISTS `role` enum('user','admin') NOT NULL DEFAULT 'user';

CREATE TABLE IF NOT EXISTS `user_notes` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `user_id` int(11) NOT NULL,
  `title_encrypted` longtext NOT NULL,
  `content_encrypted` longtext DEFAULT NULL,
  `encryption_version` varchar(10) DEFAULT 'v3.1.0',
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `idx_notes_user_id` (`user_id`, `created_at`),
  CONSTRAINT `user_notes_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
