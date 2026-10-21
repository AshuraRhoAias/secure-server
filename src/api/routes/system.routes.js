const express = require('express');
const router = express.Router();
const systemController = require('../controllers/system.controller');
const roleMiddleware = require('../../middleware/role.middleware');
const protectionMiddleware = require('../../middleware/protection.middleware');
const validate = require('../utils/validate');

// Montada en /api/system (el cargador ya exige JWT).
// Todo lo de esta ruta es administrativo: solo usuarios con role = 'admin'.
router.use(roleMiddleware.requireRole('admin'));

router.get('/status', systemController.getSystemStatus);
router.get('/logs', systemController.getSecurityLogs);
router.get('/rotation', systemController.getRotationStatus);
router.get('/blocked-ips', systemController.getBlockedIPs);

// Tabla de análisis de anomalías (security_events)
router.get('/security-events',
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
    validate.query({ hours: { type: 'integer', min: 1, max: 2160, default: 24 } }),
    systemController.getSecuritySummary
);
router.delete('/blocked-ips/:ip', systemController.unblockIP);

// Operaciones sensibles: rate limit muy restrictivo (10 req/min)
router.post('/integrity-check', protectionMiddleware.highSecurity(), systemController.performIntegrityCheck);
router.post('/rotate-keys', protectionMiddleware.highSecurity(), systemController.rotateKeys); // 501: ver el controlador
router.post('/test-communications', protectionMiddleware.highSecurity(), systemController.testCommunications);

module.exports = router;
