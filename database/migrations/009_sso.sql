-- Migración 009: SSO por OpenID Connect
--
--   user_identities     vincula un usuario local con una identidad del proveedor (emisor + sujeto).
--                       Solo se guarda el HASH de (emisor|sujeto), no el identificador del proveedor.
--   oidc_login_state    estado de cada inicio de login (state, nonce y verificador PKCE). Vive en la BD,
--                       no en memoria: el callback puede llegar a OTRA instancia. El verificador PKCE va
--                       cifrado (v4) y se registra en encrypted-columns.js. Caduca a los 10 minutos y es
--                       de un solo uso.

CREATE TABLE IF NOT EXISTS `user_identities` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `user_id` int(11) NOT NULL,
  `issuer` varchar(255) NOT NULL,
  `identity_hash` char(64) NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `last_login_at` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_identity_hash` (`identity_hash`),
  KEY `idx_identity_user` (`user_id`),
  CONSTRAINT `user_identities_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `oidc_login_state` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `state_hash` char(64) NOT NULL,
  `nonce` varchar(64) NOT NULL,
  `code_verifier_encrypted` longtext NOT NULL,
  `ip_subject` varchar(45) DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `expires_at` datetime NOT NULL,
  `used_at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_oidc_state` (`state_hash`),
  KEY `idx_oidc_expires` (`expires_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
