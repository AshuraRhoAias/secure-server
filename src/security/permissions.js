// Roles y permisos. Un permiso nuevo se declara AQUÍ y las rutas lo piden por nombre con
// roleMiddleware.requirePermission('...'): un permiso mal escrito falla al arrancar, no deja la ruta abierta.
//
//   user      usuario normal (sin acceso a /api/system)
//   auditor   solo lectura: estado, logs, eventos y resumen de seguridad
//   operator  auditor + desbloquear cuentas e IPs (la operación diaria, sin poder tocar claves ni datos de usuarios)
//   admin     todo, incluido lo que exige la aprobación de un SEGUNDO administrador
//
// La operación y observabilidad nuevas (alertas, panel, métricas, exportar/borrar datos personales, revocar
// sesiones ajenas) son SOLO admin.

const ROLES = Object.freeze(['user', 'auditor', 'operator', 'admin']);

const PERMISSIONS = Object.freeze({
    'system:read': ['auditor', 'operator', 'admin'],        // status, logs, rotación, IPs bloqueadas
    'security:read': ['auditor', 'operator', 'admin'],      // tabla de eventos y resumen
    'ips:unblock': ['operator', 'admin'],
    'accounts:unlock': ['operator', 'admin'],
    'accounts:mfa-reset': ['admin'],                        // además exige aprobación de otro admin
    'system:operate': ['admin'],                            // comprobación de integridad, rotación, prueba de avisos
    'approvals:read': ['admin'],
    'approvals:decide': ['admin'],
    'alerts:read': ['admin'],
    'alerts:manage': ['admin'],
    'dashboard:read': ['admin'],
    'metrics:read': ['admin'],
    'privacy:export': ['admin'],
    'privacy:erase': ['admin'],                             // además exige aprobación de otro admin
    'sessions:revoke-any': ['admin']
});

function can(role, permission) {
    const allowed = PERMISSIONS[permission];
    if (!allowed) throw new Error(`Permiso desconocido: ${permission}`);
    return allowed.includes(role);
}

const isKnownRole = (role) => ROLES.includes(role);
// Cualquier rol con acceso a /api/system: es el que debe llevar segundo factor si MFA_REQUIRED_FOR_ADMINS=true
const isPrivileged = (role) => isKnownRole(role) && role !== 'user';

module.exports = { ROLES, PERMISSIONS, can, isKnownRole, isPrivileged };
