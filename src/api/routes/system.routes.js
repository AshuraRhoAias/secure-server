const express = require('express');
const router = express.Router();
const systemController = require('../controllers/system.controller');
const roleMiddleware = require('../../middleware/role.middleware');
const protectionMiddleware = require('../../middleware/protection.middleware');
const validate = require('../utils/validate');

// Montada en /api/system (el cargador ya exige JWT). Cada ruta pide su PERMISO (src/security/permissions.js):
// auditor lee, operator además desbloquea, admin lo hace todo. No hay ninguna ruta sin permiso: la prueba
// test_rbac.js recorre el router y falla si aparece una.
const allow = (permission) => roleMiddleware.requirePermission(permission);
const idParam = validate.params({ id: { type: 'integer', required: true, min: 1 } });

router.get('/status', allow('system:read'), systemController.getSystemStatus);
router.get('/logs', allow('system:read'), systemController.getSecurityLogs);
router.get('/rotation', allow('system:read'), systemController.getRotationStatus);
router.get('/blocked-ips', allow('system:read'), systemController.getBlockedIPs);

// Tabla de análisis de anomalías (security_events)
router.get('/security-events',
    allow('security:read'),
    validate.query({
        type: { type: 'string', max: 64 },
        rule: { type: 'string', max: 64 },
        severity: { type: 'enum', values: ['info', 'low', 'medium', 'high', 'critical'] },
        ip: { type: 'string', max: 45 },
        userId: { type: 'integer', min: 1 },
        hours: { type: 'integer', min: 1, max: 8760, default: 24 },
        before: { type: 'integer', min: 1 },
        limit: { type: 'integer', min: 1, max: 500, default: 100 }
    }),
    systemController.getSecurityEvents
);
router.get('/security-summary',
    allow('security:read'),
    validate.query({ hours: { type: 'integer', min: 1, max: 2160, default: 24 } }),
    systemController.getSecuritySummary
);
router.delete('/blocked-ips/:ip', allow('ips:unblock'), systemController.unblockIP);
router.post('/accounts/unlock',
    allow('accounts:unlock'),
    protectionMiddleware.highSecurity(),
    validate.body({ username: { type: 'string', required: true, min: 1, max: 64 } }),
    systemController.unlockAccount
);

// Aprobación de dos administradores
router.post('/accounts/mfa-reset',
    allow('accounts:mfa-reset'),
    protectionMiddleware.highSecurity(),
    validate.body({
        username: { type: 'string', required: true, min: 1, max: 64 },
        reason: { type: 'string', required: true, min: 10, max: 255 }
    }),
    systemController.resetMfa
);
router.get('/approvals',
    allow('approvals:read'),
    validate.query({ status: { type: 'enum', values: ['pending', 'approved', 'executed', 'failed', 'rejected', 'cancelled'] } }),
    systemController.listApprovals
);
router.post('/approvals/:id/approve', allow('approvals:decide'), protectionMiddleware.highSecurity(), idParam, systemController.approveApproval);
router.post('/approvals/:id/reject', allow('approvals:decide'), protectionMiddleware.highSecurity(), idParam, systemController.rejectApproval);

// Alertas automáticas y panel (SOLO admin)
router.get('/alerts',
    allow('alerts:read'),
    validate.query({
        status: { type: 'enum', values: ['open', 'acknowledged', 'resolved'] },
        severity: { type: 'enum', values: ['low', 'medium', 'high', 'critical'] },
        before: { type: 'integer', min: 1 },
        limit: { type: 'integer', min: 1, max: 500, default: 100 }
    }),
    systemController.listAlerts
);
router.post('/alerts/evaluate', allow('alerts:manage'), protectionMiddleware.highSecurity(), systemController.evaluateAlerts);
router.post('/alerts/:id/ack', allow('alerts:manage'), idParam, systemController.acknowledgeAlert);
router.post('/alerts/:id/resolve', allow('alerts:manage'), idParam, systemController.resolveAlert);
router.get('/dashboard',
    allow('dashboard:read'),
    validate.query({ hours: { type: 'integer', min: 1, max: 720, default: 24 } }),
    systemController.getDashboard
);

// Datos personales e incidentes (SOLO admin)
router.get('/users/:id/export', allow('privacy:export'), protectionMiddleware.highSecurity(), idParam, systemController.exportUserData);
router.post('/users/:id/erase',
    allow('privacy:erase'),
    protectionMiddleware.highSecurity(),
    idParam,
    validate.body({
        reason: { type: 'string', required: true, min: 10, max: 255 },
        confirmUsername: { type: 'string', required: true, min: 1, max: 64 }
    }),
    systemController.requestUserErase
);
router.post('/users/:id/revoke-sessions',
    allow('sessions:revoke-any'),
    protectionMiddleware.highSecurity(),
    idParam,
    validate.body({ reason: { type: 'string', required: true, min: 10, max: 255 } }),
    systemController.revokeUserSessions
);
router.post('/sessions/revoke-all',
    allow('sessions:revoke-any'),
    protectionMiddleware.highSecurity(),
    validate.body({
        reason: { type: 'string', required: true, min: 10, max: 255 },
        confirm: { type: 'string', required: true, pattern: /^REVOKE-ALL-SESSIONS$/ }
    }),
    systemController.revokeAllSessions
);

// Operaciones sensibles: rate limit muy restrictivo (10 req/min)
router.post('/integrity-check', allow('system:operate'), protectionMiddleware.highSecurity(), systemController.performIntegrityCheck);
router.post('/rotate-keys', allow('system:operate'), protectionMiddleware.highSecurity(), systemController.rotateKeys); // 501: ver el controlador
router.post('/test-communications', allow('system:operate'), protectionMiddleware.highSecurity(), systemController.testCommunications);

module.exports = router;
