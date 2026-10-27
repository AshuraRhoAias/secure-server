const saml = require('../../sso/saml.service');
const { SsoError } = require('../../sso/errors');
const events = require('../../security/security-events.service');
const anomalyDetection = require('../../security/anomaly-detection.service');
const audit = require('../../services/audit.service');
const { normalizeIp } = require('../../security/ip');

class SamlController {
    constructor() {
        Object.getOwnPropertyNames(SamlController.prototype)
            .filter(name => name !== 'constructor')
            .forEach(name => { this[name] = this[name].bind(this); });
    }

    status(req, res) {
        res.json({ success: true, enabled: saml.isConfigured(), provider: 'saml' });
    }

    notConfigured(res) {
        return res.status(404).json({ success: false, message: 'SAML no está configurado', code: 'SAML_NOT_CONFIGURED' });
    }

    // Metadatos del proveedor de servicio (entityID, URL ACS, certificado): lo que se pega en el IdP
    async metadata(req, res) {
        if (!saml.isConfigured()) return this.notConfigured(res);
        try {
            res.set('Content-Type', 'application/samlmetadata+xml; charset=utf-8');
            res.send(await saml.metadata());
        } catch (error) {
            this.fail(res, error);
        }
    }

    // Inicio: redirige al IdP (o devuelve la URL con ?format=json, para aplicaciones de una sola página)
    async login(req, res) {
        if (!saml.isConfigured()) return this.notConfigured(res);
        try {
            const { url } = await saml.beginLogin();
            res.set('Cache-Control', 'no-store');
            if (req.query.format === 'json') return res.json({ success: true, url });
            res.redirect(302, url);
        } catch (error) {
            this.fail(res, error);
        }
    }

    // ACS: el navegador del usuario trae aquí (POST) la respuesta firmada del IdP
    async acs(req, res) {
        if (!saml.isConfigured()) return this.notConfigured(res);
        const ip = normalizeIp(req.ip);

        try {
            const result = await saml.handleResponse({ samlResponse: req.body?.SAMLResponse, ip, userAgent: req.headers['user-agent'] });

            await audit.log('SSO_LOGIN', { userId: result.userId, provisioned: result.provisioned, provider: 'saml' }, { req });
            await events.record({ type: 'SSO_LOGIN', severity: 'info', ip, userId: result.userId, req, details: { provider: 'saml', provisioned: result.provisioned, role: result.role } });

            res.set('Cache-Control', 'no-store');
            // Aplicación web: se redirige a una URL FIJA (de la configuración, nunca de la petición) con el token en el fragmento
            if (process.env.SAML_POST_LOGIN_URL) {
                const target = new URL(process.env.SAML_POST_LOGIN_URL);
                target.hash = new URLSearchParams({
                    token: result.token, refreshToken: result.refreshToken, expiresAt: result.expiresAt.toISOString()
                }).toString();
                return res.redirect(303, target.toString());
            }
            res.json({
                success: true, message: 'Autenticación exitosa', token: result.token, refreshToken: result.refreshToken,
                expiresAt: result.expiresAt, expiresIn: result.expiresIn, refreshExpiresAt: result.refreshExpiresAt,
                sessionExpiresAt: result.sessionExpiresAt, riskLevel: result.riskLevel, authMethods: result.amr
            });
        } catch (error) {
            await this.recordFailure(req, error);
            this.fail(res, error);
        }
    }

    async recordFailure(req, error) {
        if (!(error instanceof SsoError)) return;
        const ip = normalizeIp(req.ip);
        await events.record({
            type: 'SSO_FAILED', rule: error.rule, severity: error.status >= 500 ? 'low' : 'medium', riskScore: 40,
            action: 'rejected', ip, req, status: error.status, details: { provider: 'saml' }
        });
        // Quien insiste con respuestas falsas o repetidas acaba bloqueado
        if (['SAML_RESPONSE_INVALID', 'SAML_BAD_RESPONSE'].includes(error.code)) {
            await anomalyDetection.strike(ip, 'sso', { threshold: 10 });
        }
    }

    fail(res, error) {
        if (error instanceof SsoError) {
            return res.status(error.status).json({ success: false, message: error.message, code: error.code });
        }
        console.error('❌ Error en SAML:', error.code || error.message);
        res.status(500).json({ success: false, message: 'Error interno del servidor' });
    }
}

module.exports = new SamlController();
