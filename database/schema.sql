-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Servidor: 127.0.0.1
-- Tiempo de generación: 19-08-2025 a las 03:10:45
-- Versión del servidor: 10.4.32-MariaDB
-- Versión de PHP: 8.0.30

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Base de datos: `secure_platform`
--

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `blocked_ips`
--

CREATE TABLE `blocked_ips` (
  `id` int(11) NOT NULL,
  `ip_address` varchar(45) NOT NULL,
  `reason` text DEFAULT NULL,
  `blocked_until` timestamp NULL DEFAULT NULL,
  `block_count` int(11) DEFAULT 1,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `encryption_keys`
--

CREATE TABLE `encryption_keys` (
  `id` int(11) NOT NULL,
  `key_version` varchar(20) NOT NULL,
  `encrypted_key_data` longtext NOT NULL,
  `is_active` tinyint(1) DEFAULT 0,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `expires_at` timestamp NULL DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `known_devices`
--

CREATE TABLE `known_devices` (
  `id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `device_fingerprint` varchar(255) NOT NULL,
  `device_name` varchar(255) DEFAULT NULL,
  `last_seen` timestamp NOT NULL DEFAULT current_timestamp(),
  `is_trusted` tinyint(1) DEFAULT 0,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `security_logs`
--

CREATE TABLE `security_logs` (
  `id` int(11) NOT NULL,
  `event_type` varchar(100) NOT NULL,
  `encrypted_details` longtext DEFAULT NULL,
  `ip_address` varchar(45) DEFAULT NULL,
  `user_agent` text DEFAULT NULL,
  `risk_score` int(11) DEFAULT 0,
  `timestamp` timestamp NOT NULL DEFAULT current_timestamp(),
  `severity` enum('low','medium','high','critical') DEFAULT 'medium',
  `encrypted_timestamp` longtext DEFAULT NULL,
  `encryption_version` varchar(10) DEFAULT NULL,
  `created_at` datetime DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Volcado de datos para la tabla `security_logs`
--

--
-- Estructura de tabla para la tabla `security_metrics`
--

CREATE TABLE `security_metrics` (
  `id` int(11) NOT NULL,
  `metric_name` varchar(100) NOT NULL,
  `metric_value` decimal(10,2) NOT NULL,
  `timestamp` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `server_integrity`
--

CREATE TABLE `server_integrity` (
  `id` int(11) NOT NULL,
  `fingerprint_hash` varchar(255) NOT NULL,
  `system_data_encrypted` longtext DEFAULT NULL,
  `last_check` timestamp NOT NULL DEFAULT current_timestamp(),
  `status` enum('secure','compromised','unknown') DEFAULT 'secure'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


--
-- Estructura de tabla para la tabla `users`
--

CREATE TABLE `users` (
  `id` int(11) NOT NULL,
  `email_encrypted` longtext DEFAULT NULL,
  `password_hash` text NOT NULL,
  `personal_data_encrypted` longtext DEFAULT NULL,
  `metadata_encrypted` longtext DEFAULT NULL,
  `device_fingerprint` varchar(255) DEFAULT NULL,
  `risk_level` longtext DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  `encryption_version` varchar(10) DEFAULT 'v1',
  `username_hash` varchar(255) DEFAULT NULL,
  `username_encrypted` longtext DEFAULT NULL,
  `risk_level_encrypted` longtext DEFAULT NULL,
  `encrypted_metadata` longtext DEFAULT NULL,
  `role` enum('user','auditor','operator','admin') NOT NULL DEFAULT 'user',
  `mfa_secret_encrypted` longtext DEFAULT NULL,
  `mfa_enabled` tinyint(1) NOT NULL DEFAULT 0,
  `mfa_last_step` bigint(20) unsigned DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `user_sessions`
--

CREATE TABLE `user_sessions` (
  `id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `jwt_token_hash` varchar(255) NOT NULL,
  `session_uid` char(36) DEFAULT NULL,
  `refresh_hash` char(64) DEFAULT NULL,
  `prev_refresh_hash` char(64) DEFAULT NULL,
  `refreshed_at` timestamp NULL DEFAULT NULL,
  `ip_address` varchar(45) DEFAULT NULL,
  `user_agent` text DEFAULT NULL,
  `device_fingerprint` varchar(255) DEFAULT NULL,
  `risk_level` enum('low','medium','high') DEFAULT 'low',
  `location_country` varchar(2) DEFAULT NULL,
  `is_suspicious` tinyint(1) DEFAULT 0,
  `expires_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `absolute_expires_at` timestamp NULL DEFAULT NULL,
  `last_used_at` timestamp NULL DEFAULT NULL,
  `amr` varchar(60) DEFAULT NULL,
  `revoked_at` timestamp NULL DEFAULT NULL,
  `revoked_reason` varchar(40) DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


--
-- Indices de la tabla `blocked_ips`
--
ALTER TABLE `blocked_ips`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `ip_address` (`ip_address`),
  ADD KEY `idx_blocked_ips_expires` (`blocked_until`);

--
-- Indices de la tabla `encryption_keys`
--
ALTER TABLE `encryption_keys`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `key_version` (`key_version`);

--
-- Indices de la tabla `known_devices`
--
ALTER TABLE `known_devices`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `unique_user_device` (`user_id`,`device_fingerprint`);

--
-- Indices de la tabla `security_logs`
--
ALTER TABLE `security_logs`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idx_logs_timestamp` (`timestamp`),
  ADD KEY `idx_logs_severity` (`severity`),
  ADD KEY `idx_logs_event_type` (`event_type`);

--
-- Indices de la tabla `security_metrics`
--
ALTER TABLE `security_metrics`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idx_metric_time` (`metric_name`,`timestamp`);

--
-- Indices de la tabla `server_integrity`
--
ALTER TABLE `server_integrity`
  ADD PRIMARY KEY (`id`);

--
-- Indices de la tabla `users`
--
ALTER TABLE `users`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `uq_users_username_hash` (`username_hash`);

--
-- Indices de la tabla `user_sessions`
--
ALTER TABLE `user_sessions`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idx_sessions_user_id` (`user_id`),
  ADD KEY `idx_sessions_expires` (`expires_at`),
  ADD KEY `idx_sessions_suspicious` (`is_suspicious`),
  ADD UNIQUE KEY `uq_sessions_uid` (`session_uid`),
  ADD KEY `idx_sessions_refresh` (`refresh_hash`),
  ADD KEY `idx_sessions_prev_refresh` (`prev_refresh_hash`);

--
-- AUTO_INCREMENT de las tablas volcadas
--

--
-- AUTO_INCREMENT de la tabla `blocked_ips`
--
ALTER TABLE `blocked_ips`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT de la tabla `encryption_keys`
--
ALTER TABLE `encryption_keys`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT de la tabla `known_devices`
--
ALTER TABLE `known_devices`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=6;

--
-- AUTO_INCREMENT de la tabla `security_logs`
--
ALTER TABLE `security_logs`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=105;

--
-- AUTO_INCREMENT de la tabla `security_metrics`
--
ALTER TABLE `security_metrics`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT de la tabla `server_integrity`
--
ALTER TABLE `server_integrity`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=19;

--
-- AUTO_INCREMENT de la tabla `users`
--
ALTER TABLE `users`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=10;

--
-- AUTO_INCREMENT de la tabla `user_sessions`
--
ALTER TABLE `user_sessions`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=11;

--
-- Restricciones para tablas volcadas
--

--
-- Filtros para la tabla `known_devices`
--
ALTER TABLE `known_devices`
  ADD CONSTRAINT `known_devices_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE;

--
-- Filtros para la tabla `user_sessions`
--
ALTER TABLE `user_sessions`
  ADD CONSTRAINT `user_sessions_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE;

-- --------------------------------------------------------

--
-- (Se crea después de las restricciones porque referencia a `users`)
-- Estructura de tabla para la tabla `user_notes` (API de ejemplo: /api/notes)
--

CREATE TABLE `user_notes` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `user_id` int(11) NOT NULL,
  `title_encrypted` longtext NOT NULL,
  `content_encrypted` longtext DEFAULT NULL,
  `encryption_version` varchar(10) DEFAULT 'v4.0.0',
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `idx_notes_user_id` (`user_id`, `created_at`),
  CONSTRAINT `user_notes_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `crypto_meta` (huella de la clave de cifrado en uso)
--

CREATE TABLE `crypto_meta` (
  `id` tinyint(4) NOT NULL,
  `key_fingerprint` varchar(64) NOT NULL,
  `key_epoch` varchar(64) NOT NULL,
  `rotation_id` varchar(64) DEFAULT NULL,
  `rotated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


-- --------------------------------------------------------

--
-- Estado de seguridad en tablas (migración 004): análisis de anomalías, contadores y login
--

CREATE TABLE IF NOT EXISTS `security_events` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `created_at` datetime(3) NOT NULL DEFAULT current_timestamp(3),
  `event_type` varchar(64) NOT NULL,
  `rule` varchar(64) DEFAULT NULL,
  `severity` enum('info','low','medium','high','critical') NOT NULL DEFAULT 'low',
  `risk_score` tinyint(3) unsigned NOT NULL DEFAULT 0,
  `action_taken` enum('logged','rate_limited','rejected','blocked_ip','locked_account') NOT NULL DEFAULT 'logged',
  `ip_address` varchar(45) DEFAULT NULL,
  `user_id` int(11) DEFAULT NULL,
  `username_hash` char(64) DEFAULT NULL,
  `method` varchar(10) DEFAULT NULL,
  `path` varchar(255) DEFAULT NULL,
  `status_code` smallint(5) unsigned DEFAULT NULL,
  `user_agent` varchar(255) DEFAULT NULL,
  `country` char(2) DEFAULT NULL,
  `details` longtext DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_se_created` (`created_at`),
  KEY `idx_se_ip` (`ip_address`, `created_at`),
  KEY `idx_se_type` (`event_type`, `created_at`),
  KEY `idx_se_rule` (`rule`, `created_at`),
  KEY `idx_se_user` (`user_id`, `created_at`),
  KEY `idx_se_severity` (`severity`, `created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `rate_limit_counters` (
  `scope` varchar(24) NOT NULL,
  `subject` varchar(64) NOT NULL,
  `window_start` int(10) unsigned NOT NULL,
  `hits` int(10) unsigned NOT NULL DEFAULT 0,
  PRIMARY KEY (`scope`, `subject`, `window_start`),
  KEY `idx_rlc_window` (`window_start`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `login_attempts` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `created_at` datetime(3) NOT NULL DEFAULT current_timestamp(3),
  `username_hash` char(64) NOT NULL,
  `ip_address` varchar(45) NOT NULL,
  `ip_subject` varchar(45) NOT NULL DEFAULT '',
  `user_id` int(11) DEFAULT NULL,
  `success` tinyint(1) NOT NULL,
  `reason` varchar(32) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_la_user` (`username_hash`, `id`),
  KEY `idx_la_user_subject` (`username_hash`, `ip_subject`, `success`, `id`),
  KEY `idx_la_ip` (`ip_address`, `created_at`),
  KEY `idx_la_created` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Archivos de usuario (migración 005): metadatos; los bytes viven cifrados en disco
--

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
  `scan_status` enum('clean','skipped','unscanned') NOT NULL DEFAULT 'unscanned',
  `sanitize_status` enum('none','reencoded','inspected') NOT NULL DEFAULT 'none',
  `cipher_version` varchar(10) NOT NULL DEFAULT 'f1',
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_files_storage_name` (`storage_name`),
  KEY `idx_files_user` (`user_id`, `id`),
  KEY `idx_files_user_category` (`user_id`, `category`, `id`),
  CONSTRAINT `user_files_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


-- --------------------------------------------------------

--
-- Códigos de recuperación de MFA (migración 008)
--

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

-- --------------------------------------------------------

--
-- SSO por OpenID Connect (migración 009)
--

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

COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;

-- Aprobación de dos administradores (migración 012)
CREATE TABLE `admin_approvals` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `action` varchar(40) NOT NULL,
  `target_user_id` int(11) DEFAULT NULL,
  `params` text DEFAULT NULL,
  `reason` varchar(255) NOT NULL,
  `status` enum('pending','approved','executed','failed','rejected','cancelled') NOT NULL DEFAULT 'pending',
  `requested_by` int(11) NOT NULL,
  `approved_by` int(11) DEFAULT NULL,
  `requested_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `expires_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `decided_at` timestamp NULL DEFAULT NULL,
  `executed_at` timestamp NULL DEFAULT NULL,
  `result` text DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_approvals_status` (`status`, `requested_at`),
  KEY `idx_approvals_target` (`target_user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
