-- 018: gestión de usuarios desde la interfaz web (FASE 1).
--
-- must_change_password: un administrador crea la cuenta con una contraseña temporal; mientras valga 1, el usuario solo puede
--   cambiarla (POST /api/auth/password), ver su perfil, renovar o cerrar sesión. Pasa a 0 al cambiarla.
-- created_by: id del administrador que creó la cuenta (NULL = registro propio o anterior a esta migración).
-- Idempotente: se puede ejecutar dos veces.

ALTER TABLE `users`
  ADD COLUMN IF NOT EXISTS `must_change_password` tinyint(1) NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS `created_by` int(11) DEFAULT NULL;
