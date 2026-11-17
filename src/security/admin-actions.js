// Acciones que exigen aprobación de un segundo administrador (ver admin-approvals.service.js).
// Cada una recibe { targetUserId, params, requestedBy, approvedBy } y devuelve un resumen guardable.

const approvals = require('./admin-approvals.service');
const events = require('./security-events.service');

// Dispositivo perdido y sin códigos de recuperación: se desactiva el MFA de ese usuario. Es la acción más
// peligrosa del sistema para el dueño de la cuenta (quita su segundo factor), por eso necesita dos administradores
// y cierra TODAS sus sesiones: si alguien ya estaba dentro con una sesión robada, también se queda fuera.
approvals.registerAction('mfa_reset', {
    async execute({ targetUserId, requestedBy, approvedBy }) {
        const mfa = require('./mfa.service');
        const secureAuth = require('./secure-auth.service');

        await mfa.disable(targetUserId);
        const sessionsClosed = await secureAuth.revokeAllSessions(targetUserId, { reason: 'mfa_reset' });
        await events.record({
            type: 'MFA_RESET_BY_ADMIN', severity: 'high', riskScore: 40, userId: targetUserId,
            details: { requestedBy, approvedBy, sessionsClosed }
        });
        return { mfaDisabled: true, sessionsClosed };
    }
});

// Borrado de todos los datos de un usuario (derecho de supresión). Irreversible: dos administradores.
approvals.registerAction('user_erase', {
    erasesTarget: true,
    async execute({ targetUserId }) {
        return require('./privacy.service').eraseUser(targetUserId);
    }
});

// Dar el rol admin (o cualquier cambio de rol que se haya abierto como aprobación). Cambia el rol, cierra TODAS las
// sesiones del usuario y deja evento de seguridad `high` (USER_ROLE_CHANGED). El rol viaja en params: { role }.
approvals.registerAction('user_set_role', {
    // Dar admin a una cuenta que aún tiene la contraseña temporal permitiría a quien la creó (que la conoce) entrar como
    // ese admin: la segunda firma quedaría puenteada. Se espera a que el titular la cambie; la solicitud sigue pendiente.
    async precheck({ targetUserId, params }) {
        if (params.role !== 'admin') return;
        const db = require('../config/database');
        const [rows] = await db.query('SELECT must_change_password FROM users WHERE id = ?', [targetUserId]);
        if (rows[0] && Number(rows[0].must_change_password) === 1) {
            throw new approvals.ApprovalError('TARGET_NOT_READY',
                'El usuario aún tiene la contraseña temporal (quien creó la cuenta la conoce): apruébalo cuando la haya cambiado', 409);
        }
    },
    async execute({ targetUserId, params, requestedBy, approvedBy }) {
        const result = await require('./user-admin.service').applyRole(targetUserId, params.role, {
            actor: requestedBy, approvedBy, source: 'approval'
        });
        return { role: result.to, previousRole: result.from, sessionsClosed: result.sessionsClosed };
    }
});

module.exports = approvals;
