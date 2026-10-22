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

module.exports = approvals;
