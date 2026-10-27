-- Migración 013: qué saneamiento recibió cada archivo
--   reencoded  imagen decodificada y vuelta a codificar: sin EXIF/XMP/ICC ni datos ocultos (src/files/sanitize.js)
--   inspected  PDF inspeccionado: sin JavaScript, adjuntos ni acciones (el contenido no se modifica)
--   none       otro tipo, saneamiento desactivado, o archivo anterior a esta migración
-- Los archivos anteriores quedan como 'none'.

ALTER TABLE `user_files`
  ADD COLUMN IF NOT EXISTS `sanitize_status` enum('none','reencoded','inspected') NOT NULL DEFAULT 'none' AFTER `scan_status`;
