-- 020: pruebas en vivo desde la interfaz web (FASE 3).
--
-- ops_runs: una ejecución (diagnóstico, simulación de ataques o suite de pruebas).
--   active_kind: igual a `kind` mientras la ejecución está viva (queued/running) y NULL al terminar. Su índice ÚNICO impide dos
--     ejecuciones activas del mismo tipo en TODO el cluster, sin cerrojos ni transacciones (varias NULL no chocan).
--   host: `<máquina>:<pid>` del proceso que la ejecuta (para marcar como interrumpidas las que dejó un reinicio).
--   summary_json: contadores y progreso (pasos hechos/total, ✓/✗/avisos).
-- ops_run_events: el registro en vivo (una fila por línea). El navegador lo sondea con `seq > afterSeq`.
-- Idempotente: se puede ejecutar dos veces.

CREATE TABLE IF NOT EXISTS `ops_runs` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `kind` enum('diagnostic','attack_sim','test_suite') NOT NULL,
  `target` varchar(64) DEFAULT NULL,
  `status` enum('queued','running','passed','failed','cancelled','error') NOT NULL DEFAULT 'queued',
  `active_kind` varchar(16) DEFAULT NULL,
  `requested_by` int(11) DEFAULT NULL,
  `started_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `finished_at` timestamp NULL DEFAULT NULL,
  `summary_json` text DEFAULT NULL,
  `host` varchar(64) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_ops_runs_active` (`active_kind`),
  KEY `idx_ops_runs_started` (`started_at`),
  KEY `idx_ops_runs_user` (`requested_by`),
  CONSTRAINT `ops_runs_user_fk` FOREIGN KEY (`requested_by`) REFERENCES `users` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `ops_run_events` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `run_id` int(11) NOT NULL,
  `seq` int(11) NOT NULL,
  `level` enum('info','pass','fail','warn','error','output') NOT NULL DEFAULT 'info',
  `step` varchar(80) NOT NULL DEFAULT '',
  `message` varchar(500) NOT NULL DEFAULT '',
  `data_json` text DEFAULT NULL,
  `created_at` timestamp(3) NOT NULL DEFAULT current_timestamp(3),
  PRIMARY KEY (`id`),
  KEY `idx_ops_events_run` (`run_id`, `seq`),
  CONSTRAINT `ops_run_events_run_fk` FOREIGN KEY (`run_id`) REFERENCES `ops_runs` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
