-- Migración 002: marcador de claves (crypto_meta)
-- Una sola fila con la huella de la clave de cifrado en uso. La rotación la actualiza DENTRO de la
-- misma transacción que re-cifra los datos, y el servidor la compara con la suya: si no coinciden
-- (p. ej. una instancia que no ha cargado las claves nuevas) se niega a atender peticiones en vez
-- de escribir datos con una clave equivocada.

CREATE TABLE IF NOT EXISTS `crypto_meta` (
  `id` tinyint(4) NOT NULL,
  `key_fingerprint` varchar(64) NOT NULL,
  `key_epoch` varchar(64) NOT NULL,
  `rotation_id` varchar(64) DEFAULT NULL,
  `rotated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
