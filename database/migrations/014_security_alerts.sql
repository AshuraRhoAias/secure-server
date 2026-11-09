-- Migración 014: alertas de seguridad automáticas
--
-- Un evaluador periódico (src/security/alerts.service.js) lee security_events y levanta una alerta cuando algo
-- cruza un umbral (ráfaga de fallos de login desde muchas IP, evento crítico, escáner antivirus caído...).
-- Una alerta ABIERTA por (regla, sujeto) como máximo: si la condición sigue, se actualiza (last_seen, count) en vez de
-- duplicarse. Un administrador la reconoce (acknowledged) y la resuelve. Las abiertas no se cierran solas.
--
--   active_key  columna generada: dedupe_key mientras la alerta NO está resuelta, NULL cuando sí. El índice único sobre
--               ella garantiza una sola alerta activa por clave aunque dos instancias evalúen a la vez.

CREATE TABLE IF NOT EXISTS `security_alerts` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `rule` varchar(64) NOT NULL,
  `subject` varchar(120) NOT NULL DEFAULT 'global',
  `dedupe_key` varchar(190) NOT NULL,
  `severity` enum('low','medium','high','critical') NOT NULL,
  `title` varchar(160) NOT NULL,
  `status` enum('open','acknowledged','resolved') NOT NULL DEFAULT 'open',
  `event_count` int(10) unsigned NOT NULL DEFAULT 1,
  `first_seen` timestamp NOT NULL DEFAULT current_timestamp(),
  `last_seen` timestamp NOT NULL DEFAULT current_timestamp(),
  `details` text DEFAULT NULL,
  `acknowledged_by` int(11) DEFAULT NULL,
  `acknowledged_at` timestamp NULL DEFAULT NULL,
  `resolved_by` int(11) DEFAULT NULL,
  `resolved_at` timestamp NULL DEFAULT NULL,
  `notified_at` timestamp NULL DEFAULT NULL,
  `notify_error` varchar(120) DEFAULT NULL,
  `active_key` varchar(190) AS (IF(`status` = 'resolved', NULL, `dedupe_key`)) STORED,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_alerts_active` (`active_key`),
  KEY `idx_alerts_status` (`status`, `last_seen`),
  KEY `idx_alerts_rule` (`rule`, `status`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
