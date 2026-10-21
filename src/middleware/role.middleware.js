const db = require('../config/database');

// Control de acceso por rol. Debe usarse DESPUÉS de authMiddleware.verifyJWT.
//
//   router.use(authMiddleware.verifyJWT, roleMiddleware.requireRole('admin'));
//
// El rol se lee de la base de datos en cada petición (no del JWT), así que
// quitar un rol a un usuario surte efecto de inmediato.
class RoleMiddleware {
    requireRole(...allowedRoles) {
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

                if (!role || !allowedRoles.includes(role)) {
                    return res.status(403).json({
                        success: false,
                        message: 'No tienes permisos para esta operación',
                        code: 'FORBIDDEN'
                    });
                }

                // Con MFA_REQUIRED_FOR_ADMINS=true un administrador solo opera si inició sesión con segundo
                // factor (otp/recovery) o por SSO (el proveedor de identidad ya lo gestiona)
                if (role === 'admin' && process.env.MFA_REQUIRED_FOR_ADMINS === 'true') {
                    const amr = req.user.amr || [];
                    if (!amr.some(method => ['otp', 'recovery', 'sso'].includes(method))) {
                        return res.status(403).json({
                            success: false,
                            message: 'Los administradores necesitan autenticación en dos pasos',
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
