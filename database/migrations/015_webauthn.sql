-- Migración 015: passkeys / llaves de seguridad (WebAuthn) como segundo factor
--
-- webauthn_credentials  una fila por llave registrada. Solo la clave PÚBLICA (nada secreto sale del dispositivo).
--                       counter: contador de firmas; si una firma trae un contador no mayor, la llave se clonó.
-- webauthn_challenges   retos de un solo uso (registro o login) con caducidad de 5 min, ligados a un usuario.

CREATE TABLE IF NOT EXISTS `webauthn_credentials` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `user_id` int(11) NOT NULL,
  `credential_id` varchar(512) NOT NULL,
  `public_key` text NOT NULL,
  `counter` bigint(20) unsigned NOT NULL DEFAULT 0,
  `transports` varchar(100) DEFAULT NULL,
  `device_type` enum('singleDevice','multiDevice') NOT NULL DEFAULT 'singleDevice',
  `backed_up` tinyint(1) NOT NULL DEFAULT 0,
  `aaguid` char(36) DEFAULT NULL,
  `name` varchar(60) NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `last_used_at` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_webauthn_credential` (`credential_id`),
  KEY `idx_webauthn_user` (`user_id`),
  CONSTRAINT `webauthn_credentials_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `webauthn_challenges` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `challenge` varchar(128) NOT NULL,
  `purpose` enum('register','login') NOT NULL,
  `user_id` int(11) NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `expires_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_webauthn_challenge` (`challenge`),
  KEY `idx_webauthn_challenge_exp` (`expires_at`),
  CONSTRAINT `webauthn_challenges_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
