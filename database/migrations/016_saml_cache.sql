-- Migración 016: caché de SAML en la base de datos
--
-- Guarda (1) el ID de cada AuthnRequest que enviamos, para exigir que la respuesta del proveedor lo mencione
-- (InResponseTo) y que solo valga UNA vez, y (2) el ID de cada aserción ya aceptada, para rechazar su repetición.
-- Está en la BD y no en memoria para que la respuesta pueda llegar a otra instancia. Las filas caducan solas.

CREATE TABLE IF NOT EXISTS `saml_cache` (
  `cache_key` varchar(190) NOT NULL,
  `cache_value` varchar(512) NOT NULL,
  `expires_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`cache_key`),
  KEY `idx_saml_cache_exp` (`expires_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
