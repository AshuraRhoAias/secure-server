const express = require('express');
const crypto = require('crypto');
const router = express.Router();
const authMiddleware = require('../../middleware/auth.middleware');
const roleMiddleware = require('../../middleware/role.middleware');
const metrics = require('../../observability/metrics');

// GET /api/metrics -> formato de texto de Prometheus. SOLO administradores (permiso metrics:read).
//
// Un scraper (Prometheus) no puede renovar un JWT de 15 minutos. Por eso, SI el administrador define METRICS_TOKEN
// (mínimo 32 caracteres), ese token estático también vale para ESTA ruta y para nada más. Por defecto está desactivado.
// Se compara en tiempo constante.

const sha256 = (value) => crypto.createHash('sha256').update(value).digest();

function scraperToken(req) {
    const configured = process.env.METRICS_TOKEN;
    if (!configured || configured.length < 32) return false;
    const header = req.headers.authorization || '';
    if (!header.startsWith('Bearer ')) return false;
    return crypto.timingSafeEqual(sha256(header.slice(7)), sha256(configured));
}

const requireAdminOrScraper = (req, res, next) => (scraperToken(req) ? next() : authMiddleware.verifyJWT(req, res, (err) => (err ? next(err) : roleMiddleware.requirePermission('metrics:read')(req, res, next))));

router.get('/', requireAdminOrScraper, async (req, res) => {
    try {
        res.set('Content-Type', metrics.registry.contentType);
        res.set('Cache-Control', 'no-store');
        res.send(await metrics.registry.metrics());
    } catch (error) {
        console.error('❌ Error generando métricas:', error.code || error.message);
        res.status(500).json({ success: false, message: 'Error generando métricas' });
    }
});

router.access = 'custom'; // gestiona su propia autenticación (admin JWT o METRICS_TOKEN)
module.exports = router;
