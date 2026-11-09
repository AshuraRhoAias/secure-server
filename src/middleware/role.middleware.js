const db = require('../config/database');
const permissions = require('../security/permissions');

// Control de acceso por rol. Debe usarse DESPUÉS de authMiddleware.verifyJWT.
//
//   router.use(authMiddleware.verifyJWT, roleMiddleware.requireRole('admin'));
//
// El rol se lee de la base de datos en cada petición (no del JWT), así que
// quitar un rol a un usuario surte efecto de inmediato.
// Roles y permisos: src/security/permissions.js.
class RoleMiddleware {
    // Compatibilidad: acceso por rol. Para rutas nuevas, mejor requirePermission().
    requireRole(...allowedRoles) {
        return this.guard((role) => allowedRoles.includes(role));
    }

    // Acceso por permiso (ver src/security/permissions.js). Un permiso desconocido lanza AL DEFINIR la ruta.
    requirePermission(permission) {
        permissions.can('user', permission); // valida el nombre ya
        return this.guard((role) => permissions.can(role, permission));
    }

    guard(isAllowed) {
        return async (req, res, next) => {
            try {
                if (!req.user?.id) {
                    return res.status(401).json({
                        success: false,
                        message: 'Autenticación requerida',
                        code: 'MISSING_TOKEN'
                    });
                }

                const [rows] = await db.query('SELECT role FROM users WHERE id = ?', [req.user.id]);
                const role = rows[0]?.role;

                if (!role || !permissions.isKnownRole(role) || !isAllowed(role)) {
                    return res.status(403).json({
                        success: false,
                        message: 'No tienes permisos para esta operación',
                        code: 'FORBIDDEN'
                    });
                }

                // Con MFA_REQUIRED_FOR_ADMINS=true cualquier rol con privilegios solo opera si inició sesión con
                // segundo factor (otp/recovery/passkey) o por SSO/SAML (el proveedor de identidad ya lo gestiona)
                if (permissions.isPrivileged(role) && process.env.MFA_REQUIRED_FOR_ADMINS === 'true') {
                    const amr = req.user.amr || [];
                    if (!amr.some(method => ['otp', 'recovery', 'hwk', 'sso', 'saml'].includes(method))) {
                        return res.status(403).json({
                            success: false,
                            message: 'Los roles con privilegios necesitan autenticación en dos pasos',
                            code: 'MFA_REQUIRED'
                        });
                    }
                }

                req.user.role = role;
                next();
            } catch (error) {
                if (error.code === 'ER_BAD_FIELD_ERROR') {
                    console.error('❌ Falta la columna users.role. Ejecuta database/migrations/001_roles_and_notes.sql');
                    return res.status(503).json({
                        success: false,
                        message: 'Migración de base de datos pendiente',
                        code: 'MIGRATION_REQUIRED'
                    });
                }
                console.error('❌ Error verificando rol:', error);
                return res.status(500).json({
                    success: false,
                    message: 'Error interno del servidor',
                    code: 'INTERNAL_ERROR'
                });
            }
        };
    }
}

module.exports = new RoleMiddleware();
