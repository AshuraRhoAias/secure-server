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

// Cambio en caliente de un ajuste operativo que REDUCE la seguridad (o vuelta al entorno que la reduce). params: { key, value } o { key, reset: true }
// (restablecer al entorno). Se vuelve a validar al ejecutar: el catálogo es cerrado y el rango se comprueba
// otra vez, y si entre la solicitud y la aprobación el valor ya cambió, se aplica igualmente lo aprobado (queda en auditoría).
approvals.registerAction('settings_change', {
    async execute({ params, requestedBy, approvedBy }) {
        const settings = require('../config/runtime-settings');
        const reset = params.reset === true;
        // Si el valor cambió desde la solicitud (p. ej. otro admin lo endureció), aplicar lo aprobado revertiría esa mejora:
        // la solicitud queda obsoleta (falla con STALE_REQUEST) y hay que pedirla de nuevo sobre el valor actual
        if (Object.prototype.hasOwnProperty.call(params, 'from')) {
            const now = await settings.getFresh(params.key);
            if (now.value !== params.from) {
                throw new approvals.ApprovalError('STALE_REQUEST', `El ajuste cambió desde la solicitud (${params.from} → ${now.value}): vuelve a pedirla`, 409);
            }
        }
        const result = reset ? await settings.reset(params.key, { actor: requestedBy }) : await settings.set(params.key, params.value, { actor: requestedBy });
        await events.record({
            type: 'SETTING_CHANGED', severity: 'high', riskScore: 40,
            details: { key: params.key, from: result.previous, to: result.current, reset, requestedBy, approvedBy, source: 'approval' }
        });
        return { key: params.key, previous: result.previous, current: result.current, reset };
    }
});

module.exports = approvals;
