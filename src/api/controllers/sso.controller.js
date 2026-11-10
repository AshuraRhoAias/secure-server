const oidc = require('../../sso/oidc.service');
const { SsoError } = oidc;
const events = require('../../security/security-events.service');
const anomalyDetection = require('../../security/anomaly-detection.service');
const audit = require('../../services/audit.service');
const { normalizeIp } = require('../../security/ip');
const handoff = require('../../sso/handoff.service');

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

    // Inicio: redirige al proveedor (o devuelve la URL con ?format=json, para aplicaciones de una sola página).
    // Con ?handoff=<base64url(sha256(verificador))> (lo usa el BFF de la interfaz web) el resultado se entrega por código de un
    // solo uso en SSO_HANDOFF_URL en lugar de devolver los tokens (ver src/sso/handoff.service.js).
    async login(req, res) {
        if (!oidc.isConfigured()) return this.notConfigured(res);
        try {
            const query = req.validated?.query || req.query;
            const { url, state } = await oidc.beginLogin({ ip: normalizeIp(req.ip) });
            if (query.handoff) await handoff.begin({ provider: 'oidc', beginHandle: state, challenge: query.handoff });
            res.set('Cache-Control', 'no-store');
            if (query.format === 'json') return res.json({ success: true, url });
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

            // Interfaz web (BFF): código de un solo uso en SSO_HANDOFF_URL; los tokens no pasan por el navegador
            const handoffTarget = await handoff.complete({ beginHandle: req.query.state, result });
            if (handoffTarget) {
                res.set('Cache-Control', 'no-store');
                return res.redirect(302, handoffTarget);
            }

            // Aplicación web (modo antiguo): URL FIJA (de la configuración, nunca de la petición) con el token en el fragmento.
            // Preferible SSO_HANDOFF_URL: con el fragmento, el JavaScript de esa página ve los tokens.
            if (process.env.SSO_POST_LOGIN_URL) {
                const target = new URL(process.env.SSO_POST_LOGIN_URL);
                target.hash = new URLSearchParams({
                    token: result.token, refreshToken: result.refreshToken, expiresAt: result.expiresAt.toISOString()
                }).toString();
                res.set('Cache-Control', 'no-store');
                return res.redirect(302, target.toString());
            }

            res.set('Cache-Control', 'no-store');
            res.json({
                success: true, message: 'Autenticación exitosa', token: result.token, refreshToken: result.refreshToken,
                expiresAt: result.expiresAt, expiresIn: result.expiresIn, refreshExpiresAt: result.refreshExpiresAt,
                sessionExpiresAt: result.sessionExpiresAt, riskLevel: result.riskLevel, authMethods: result.amr
            });
        } catch (error) {
            await this.recordFailure(req, error);
            this.fail(req, res, error);
        }
    }

    // Canje del código de entrega por los tokens (lo llama el BFF, servidor a servidor). Sirve para OIDC y SAML.
    async exchange(req, res) {
        try {
            const tokens = await handoff.exchange({ code: req.body.code, verifier: req.body.verifier });
            res.set('Cache-Control', 'no-store');
            res.json({ success: true, message: 'Autenticación exitosa', ...tokens });
        } catch (error) {
            if (error instanceof SsoError && error.critical) {
                await events.record({
                    type: 'SSO_HANDOFF_STOLEN', rule: error.rule, severity: 'critical', riskScore: 90, action: 'rejected',
                    ip: normalizeIp(req.ip), userId: error.userId ?? null, req, status: 401
                });
            }
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
        // Quien insiste con states falsos, id_token inválidos o códigos de entrega inventados acaba bloqueado
        if (['SSO_STATE_INVALID', 'SSO_ID_TOKEN_INVALID', 'SSO_BAD_CALLBACK', 'SSO_HANDOFF_INVALID'].includes(error.code)) {
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
