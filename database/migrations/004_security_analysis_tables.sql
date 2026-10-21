-- Migración 004: estado de seguridad en TABLAS (ya no en memoria del proceso)
--
-- Antes el límite de peticiones, las IP bloqueadas, los intentos de login fallidos y el historial
-- de anomalías vivían en Map/Set de cada proceso: se perdían al reiniciar, no se compartían entre
-- instancias y no se podían analizar después. Ahora:
--
--   security_events       tabla de ANÁLISIS: una fila por evento sospechoso (inyección, límite
--                         superado, login fallido, cuenta bloqueada, archivo rechazado...). Está en
--                         claro a propósito para poder consultarla con SQL; nunca guarda contraseñas,
--                         tokens ni cabeceras de autorización.
--   rate_limit_counters   contadores por ventana de tiempo, atómicos entre procesos
--   login_attempts        intentos de login (éxito/fallo) por hash de usuario e IP
--   blocked_ips           ya existía; ahora es la ÚNICA fuente de verdad del bloqueo
--
-- Compatible con MariaDB 10.x y MySQL 8.

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
  `user_id` int(11) DEFAULT NULL,
  `success` tinyint(1) NOT NULL,
  `reason` varchar(32) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_la_user` (`username_hash`, `id`),
  KEY `idx_la_ip` (`ip_address`, `created_at`),
  KEY `idx_la_created` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
