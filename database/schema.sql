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
  `encrypted_timestamp` datetime DEFAULT NULL,
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
  `encrypted_metadata` longtext DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `user_sessions`
--

CREATE TABLE `user_sessions` (
  `id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `jwt_token_hash` varchar(255) NOT NULL,
  `ip_address` varchar(45) DEFAULT NULL,
  `user_agent` text DEFAULT NULL,
  `device_fingerprint` varchar(255) DEFAULT NULL,
  `risk_level` enum('low','medium','high') DEFAULT 'low',
  `location_country` varchar(2) DEFAULT NULL,
  `is_suspicious` tinyint(1) DEFAULT 0,
  `expires_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
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
  ADD PRIMARY KEY (`id`);

--
-- Indices de la tabla `user_sessions`
--
ALTER TABLE `user_sessions`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idx_sessions_user_id` (`user_id`),
  ADD KEY `idx_sessions_expires` (`expires_at`),
  ADD KEY `idx_sessions_suspicious` (`is_suspicious`);

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
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
