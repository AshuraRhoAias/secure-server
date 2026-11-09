-- Migración 010: resultado del antivirus por archivo
--   clean      escaneado por ClamAV y limpio
--   skipped    superaba el límite del escáner y FILE_SCAN_ON_OVERSIZE=skip permitió guardarlo sin escanear
--   unscanned  no se escaneó (FILE_SCAN=off, o el escáner falló con FILE_SCAN=optional)
-- Los archivos anteriores a esta migración quedan como 'unscanned' (scripts/rescanFiles.js los revisa).

ALTER TABLE `user_files`
  ADD COLUMN IF NOT EXISTS `scan_status` enum('clean','skipped','unscanned') NOT NULL DEFAULT 'unscanned' AFTER `sha256`;
