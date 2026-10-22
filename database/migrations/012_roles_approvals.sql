-- Migración 012: roles finos y aprobación de dos administradores
--
-- users.role: user | auditor (solo lectura) | operator (auditor + desbloquear cuentas/IPs) | admin.
-- Los permisos de cada rol están en src/security/permissions.js. El rol se asigna con `npm run set-role`
-- (no hay endpoint para subirse el rol a uno mismo).
--
-- admin_approvals: acciones destructivas (reiniciar el MFA de alguien, borrar datos personales) que un
-- administrador SOLICITA y OTRO administrador distinto aprueba. Guarda el historial completo (quién, cuándo, por qué).
-- ADMIN_APPROVALS_REQUIRED=1 permite ejecutar sin segundo admin (instalaciones con un solo administrador).

ALTER TABLE `users`
  MODIFY `role` enum('user','auditor','operator','admin') NOT NULL DEFAULT 'user';

CREATE TABLE IF NOT EXISTS `admin_approvals` (
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
