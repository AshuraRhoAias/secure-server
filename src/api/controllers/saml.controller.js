const saml = require('../../sso/saml.service');
const { SsoError } = require('../../sso/errors');
const events = require('../../security/security-events.service');
const anomalyDetection = require('../../security/anomaly-detection.service');
const audit = require('../../services/audit.service');
const { normalizeIp } = require('../../security/ip');
const handoff = require('../../sso/handoff.service');
const crypto = require('crypto');

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
    // Con ?handoff=… (interfaz web) se genera un RelayState aleatorio que el IdP devuelve en el POST al ACS: asa de la entrega
    // por código de un solo uso (src/sso/handoff.service.js). Sin handoff, como siempre (RelayState vacío).
    async login(req, res) {
        if (!saml.isConfigured()) return this.notConfigured(res);
        try {
            const query = req.validated?.query || req.query;
            const relayState = query.handoff ? crypto.randomBytes(32).toString('base64url') : '';
            if (query.handoff) await handoff.begin({ provider: 'saml', beginHandle: relayState, challenge: query.handoff });
            const { url } = await saml.beginLogin({ relayState });
            res.set('Cache-Control', 'no-store');
            if (query.format === 'json') return res.json({ success: true, url });
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
            // Interfaz web (BFF): código de un solo uso en SSO_HANDOFF_URL; los tokens no pasan por el navegador
            const relayState = typeof req.body?.RelayState === 'string' && /^[A-Za-z0-9_-]{43}$/.test(req.body.RelayState) ? req.body.RelayState : null;
            const handoffTarget = await handoff.complete({ beginHandle: relayState, result });
            if (handoffTarget) return res.redirect(303, handoffTarget);

            // Aplicación web (modo antiguo): URL FIJA (de la configuración, nunca de la petición) con el token en el fragmento.
            // Preferible SSO_HANDOFF_URL: con el fragmento, el JavaScript de esa página ve los tokens.
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
