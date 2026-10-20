const express = require('express');
const router = express.Router();
const systemController = require('../controllers/system.controller');
const roleMiddleware = require('../../middleware/role.middleware');
const protectionMiddleware = require('../../middleware/protection.middleware');

// Montada en /api/system (el cargador ya exige JWT).
// Todo lo de esta ruta es administrativo: solo usuarios con role = 'admin'.
router.use(roleMiddleware.requireRole('admin'));

router.get('/status', systemController.getSystemStatus);
router.get('/logs', systemController.getSecurityLogs);
router.get('/rotation', systemController.getRotationStatus);
router.get('/blocked-ips', systemController.getBlockedIPs);
router.delete('/blocked-ips/:ip', systemController.unblockIP);

// Operaciones sensibles: rate limit muy restrictivo (10 req/min)
router.post('/integrity-check', protectionMiddleware.highSecurity(), systemController.performIntegrityCheck);
router.post('/rotate-keys', protectionMiddleware.highSecurity(), systemController.rotateKeys); // 501: ver el controlador
router.post('/test-communications', protectionMiddleware.highSecurity(), systemController.testCommunications);

module.exports = router;
