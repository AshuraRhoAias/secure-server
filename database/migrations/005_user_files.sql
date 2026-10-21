-- Migración 005: archivos de usuario (API /api/files)
--
-- Los BYTES del archivo viven cifrados en disco (FILES_DIR, por defecto ./storage), nunca en la BD.
-- Aquí solo hay metadatos. Cada archivo se cifra con su propia clave aleatoria de 256 bits
-- (key_encrypted = esa clave envuelta con la clave maestra), así que rotar la clave maestra solo
-- re-envuelve estas claves: no hace falta re-cifrar gigabytes de archivos.
--
-- filename_encrypted y key_encrypted están registradas en src/crypto/encrypted-columns.js.

CREATE TABLE IF NOT EXISTS `user_files` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `user_id` int(11) NOT NULL,
  `storage_name` char(36) NOT NULL,
  `filename_encrypted` longtext NOT NULL,
  `key_encrypted` longtext NOT NULL,
  `mime_type` varchar(100) NOT NULL,
  `category` enum('image','video','audio','document','text') NOT NULL,
  `size_bytes` bigint(20) unsigned NOT NULL,
  `sha256` char(64) NOT NULL,
  `cipher_version` varchar(10) NOT NULL DEFAULT 'f1',
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_files_storage_name` (`storage_name`),
  KEY `idx_files_user` (`user_id`, `id`),
  KEY `idx_files_user_category` (`user_id`, `category`, `id`),
  CONSTRAINT `user_files_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
