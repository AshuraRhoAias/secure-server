-- 021: trabajador de suites de pruebas (npm run ops:test-runner).
--
-- ops_workers: latido de los procesos trabajadores independientes. El servidor (src/) no ejecuta procesos externos: solo encola las
-- suites (ops_runs.status = 'queued') y comprueba aquí que haya un trabajador vivo (last_seen de menos de 15 s) antes de aceptarlas.
--   host: `<máquina>:<pid>` del trabajador · kind: qué ejecuta (hoy solo 'test_suite') · last_seen: último latido (hora de la BD).
-- Idempotente: se puede ejecutar dos veces.

CREATE TABLE IF NOT EXISTS `ops_workers` (
  `host` varchar(64) NOT NULL,
  `kind` varchar(32) NOT NULL,
  `pid` int(11) NOT NULL,
  `last_seen` timestamp(3) NOT NULL DEFAULT current_timestamp(3),
  PRIMARY KEY (`host`),
  KEY `idx_ops_workers_kind_seen` (`kind`, `last_seen`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
