-- 017: entrega del login SSO (OIDC/SAML) a la interfaz web SIN que los tokens pasen por el navegador.
--
-- Antes, con SSO_POST_LOGIN_URL / SAML_POST_LOGIN_URL, el API redirigía con los tokens en el fragmento de la URL (#token=…): el
-- JavaScript de la página los veía. Con SSO_HANDOFF_URL el flujo es como PKCE:
--   1. el BFF genera un verificador (en una cookie httpOnly) y pide /api/sso/login?handoff=<sha256(verificador)>
--   2. tras el login en el proveedor, el API guarda los tokens CIFRADOS aquí y redirige a SSO_HANDOFF_URL?code=<código>
--   3. el BFF canjea código + verificador en POST /api/sso/exchange (servidor a servidor): un solo uso, 60 s
-- Un código robado (historial, registros de un proxy) no sirve sin el verificador del navegador que empezó el login.
--
--   mysql -u <usuario> -p <base_de_datos> < database/migrations/017_sso_handoff.sql

CREATE TABLE IF NOT EXISTS `sso_handoffs` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `begin_hash` char(64) NOT NULL,
  `provider` enum('oidc','saml') NOT NULL,
  `challenge` char(43) NOT NULL,
  `code_hash` char(64) DEFAULT NULL,
  `payload_encrypted` longtext DEFAULT NULL,
  `user_id` int(11) DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `expires_at` datetime NOT NULL,
  `code_expires_at` datetime DEFAULT NULL,
  `used_at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_handoff_begin` (`begin_hash`),
  UNIQUE KEY `uq_handoff_code` (`code_hash`),
  KEY `idx_handoff_expires` (`expires_at`),
  KEY `idx_handoff_user` (`user_id`),
  CONSTRAINT `sso_handoffs_user_fk` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
