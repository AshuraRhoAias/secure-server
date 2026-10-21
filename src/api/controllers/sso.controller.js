const oidc = require('../../sso/oidc.service');
const { SsoError } = oidc;
const events = require('../../security/security-events.service');
const anomalyDetection = require('../../security/anomaly-detection.service');
const audit = require('../../services/audit.service');
const { normalizeIp } = require('../../security/ip');

class SsoController {
    constructor() {
        Object.getOwnPropertyNames(SsoController.prototype)
            .filter(name => name !== 'constructor')
            .forEach(name => { this[name] = this[name].bind(this); });
    }

    status(req, res) {
        res.json({ success: true, enabled: oidc.isConfigured(), provider: 'oidc' });
    }

    notConfigured(res) {
        return res.status(404).json({ success: false, message: 'SSO no está configurado', code: 'SSO_NOT_CONFIGURED' });
    }

    // Inicio: redirige al proveedor (o devuelve la URL con ?format=json, para aplicaciones de una sola página)
    async login(req, res) {
        if (!oidc.isConfigured()) return this.notConfigured(res);
        try {
            const { url } = await oidc.beginLogin({ ip: normalizeIp(req.ip) });
            if (req.query.format === 'json') return res.json({ success: true, url });
            res.redirect(302, url);
        } catch (error) {
            this.fail(req, res, error);
        }
    }

    async callback(req, res) {
        if (!oidc.isConfigured()) return this.notConfigured(res);
        const ip = normalizeIp(req.ip);

        try {
            const result = await oidc.handleCallback({
                code: typeof req.query.code === 'string' ? req.query.code : '',
                state: typeof req.query.state === 'string' ? req.query.state : '',
                error: typeof req.query.error === 'string' ? req.query.error : '',
                ip, userAgent: req.headers['user-agent']
            });

            await audit.log('SSO_LOGIN', { userId: result.userId, provisioned: result.provisioned }, { req });
            await events.record({
                type: 'SSO_LOGIN', severity: 'info', ip, userId: result.userId, req,
                details: { provisioned: result.provisioned, role: result.role }
            });

            // Aplicación web: se redirige a una URL FIJA (de la configuración, nunca de la petición) con el token en el fragmento
            if (process.env.SSO_POST_LOGIN_URL) {
                const target = new URL(process.env.SSO_POST_LOGIN_URL);
                target.hash = new URLSearchParams({ token: result.token, expiresAt: result.expiresAt.toISOString() }).toString();
                res.set('Cache-Control', 'no-store');
                return res.redirect(302, target.toString());
            }

            res.set('Cache-Control', 'no-store');
            res.json({
                success: true, message: 'Autenticación exitosa', token: result.token, expiresAt: result.expiresAt,
                riskLevel: result.riskLevel, authMethods: result.amr
            });
        } catch (error) {
            await this.recordFailure(req, error);
            this.fail(req, res, error);
        }
    }

    async recordFailure(req, error) {
        if (!(error instanceof SsoError)) return;
        const ip = normalizeIp(req.ip);
        await events.record({
            type: 'SSO_FAILED', rule: error.rule, severity: error.status >= 500 ? 'low' : 'medium', riskScore: 40,
            action: 'rejected', ip, req, status: error.status
        });
        // Quien insiste con states falsos o id_token inválidos acaba bloqueado
        if (['SSO_STATE_INVALID', 'SSO_ID_TOKEN_INVALID', 'SSO_BAD_CALLBACK'].includes(error.code)) {
            await anomalyDetection.strike(ip, 'sso', { threshold: 10 });
        }
    }

    fail(req, res, error) {
        if (error instanceof SsoError) {
            return res.status(error.status).json({ success: false, message: error.message, code: error.code });
        }
        console.error('❌ Error en SSO:', error.code || error.message);
        res.status(500).json({ success: false, message: 'Error interno del servidor' });
    }
}

module.exports = new SsoController();
