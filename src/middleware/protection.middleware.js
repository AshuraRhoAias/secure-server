const anomalyDetection = require('../security/anomaly-detection.service');
const rateLimiter = require('../security/rate-limiter.service');
const events = require('../security/security-events.service');
const { scanRequest } = require('../security/injection-detector');
const { ipSubject } = require('../security/ip');

// Capa de protección HTTP. TODO el estado (bloqueos, contadores, historial) está en MySQL:
// ver src/security/*.service.js y database/migrations/004_security_analysis_tables.sql.
//
// Orden de comprobaciones de autoProtect():
//   1. IP bloqueada                           → 403
//   2. límite global por IP (ventana 60 s)    → 429 (y bloqueo si se multiplica por 3)
//   3. ruta típica de escáner (.env, wp-admin) → se registra; varias seguidas → bloqueo
//   4. firmas de inyección en URL/cabeceras/query/params/cuerpo
//                                             → 403/400 + evento + "strike" (varios → bloqueo)
//   5. ráfaga de 401/403 desde la misma IP    → bloqueo (fuerza bruta / enumeración)
//
// Si la base de datos de seguridad no responde, se responde 503 (falla CERRADO): sin ella no hay
// forma de saber si la IP está bloqueada, y tampoco funcionaría ninguna ruta autenticada.

const intEnv = (name, fallback) => {
    const n = Number(process.env[name]);
    return Number.isInteger(n) && n > 0 ? n : fallback;
};

const config = () => ({
    globalPerMin: intEnv('RATE_LIMIT_GLOBAL_PER_MIN', 600),
    sensitivePerMin: intEnv('SENSITIVE_RATE_LIMIT_PER_MIN', 10),
    strikesToBlock: intEnv('INJECTION_STRIKES_TO_BLOCK', 5),
    scannerHitsToBlock: intEnv('SCANNER_HITS_TO_BLOCK', 5),
    authFailuresToBlock: intEnv('AUTH_FAILURES_TO_BLOCK', 30),
    // Qué hacer con firmas de inyección en el CUERPO de la petición:
    //   'critical' (por defecto)  se rechazan solo en las rutas de INJECTION_BLOCK_PATHS; en el resto se registran
    //   'block'                   se rechazan en todas las rutas
    //   'log'                     solo se registran
    // La defensa real contra SQLi son las consultas parametrizadas; el detector por reglas puede equivocarse con
    // texto legítimo (una nota que habla de SQL), así que solo corta donde nunca hay texto libre legítimo.
    bodyMode: ['block', 'log'].includes(process.env.INJECTION_BODY_MODE) ? process.env.INJECTION_BODY_MODE : 'critical',
    criticalPaths: (process.env.INJECTION_BLOCK_PATHS || '/api/auth,/api/system,/api/sso')
        .split(',').map(p => p.trim().toLowerCase().replace(/\/+$/, '')).filter(Boolean)
});

const isCriticalPath = (path, criticalPaths) => {
    const clean = String(path || '').toLowerCase();
    return criticalPaths.some(prefix => clean === prefix || clean.startsWith(`${prefix}/`));
};

const SCANNER_PATH = /(?:^|\/)\.(?:env|git|svn|hg|aws|ssh|ds_store|htaccess|htpasswd)\b|wp-(?:admin|login|content|includes)|xmlrpc\.php|phpmyadmin|cgi-bin|\.(?:php\d?|asp|aspx|jsp|cgi)$|\/(?:actuator|manager\/html|solr|boaform)(?:\/|$)/i;

const unavailable = (res) => res.status(503).json({
    success: false,
    message: 'Servicio temporalmente no disponible',
    code: 'SECURITY_BACKEND_UNAVAILABLE'
});

class ProtectionMiddleware {
    autoProtect() {
        return async (req, res, next) => {
            this.addSecurityHeaders(req, res);

            // Bypass explícito para pruebas de carga. Por defecto DESACTIVADO.
            if (process.env.DISABLE_IP_BLOCKING === 'true') return next();

            // /health y /health/ready: las sondas de un balanceador no se cuentan ni se limitan (y /health no toca la BD)
            if (req.path === '/health' || req.path === '/health/ready') return next();

            try {
                const cfg = config();
                const subject = ipSubject(req.ip);

                // 1. IP bloqueada
                if (await anomalyDetection.isIPBlocked(req.ip)) {
                    return res.status(403).json({ success: false, message: 'Acceso denegado', code: 'IP_BLOCKED' });
                }

                // 2. Límite global por IP
                const rate = await rateLimiter.hit('ip', subject, 60);
                if (rate.count > cfg.globalPerMin) {
                    // Se registra el primer exceso de la ventana y luego cada 100, no cada petición
                    const excess = rate.count - cfg.globalPerMin;
                    if (excess === 1 || excess % 100 === 0) {
                        await events.record({
                            type: 'RATE_LIMITED', rule: 'GLOBAL_IP_LIMIT', severity: 'medium', riskScore: 40,
                            action: 'rate_limited', req, status: 429, details: { count: rate.count, limit: cfg.globalPerMin }
                        });
                    }
                    if (rate.count > cfg.globalPerMin * 3) await anomalyDetection.blockIP(req.ip, 'HIGH_REQUEST_RATE');

                    res.set('Retry-After', String(rate.retryAfter));
                    return res.status(429).json({
                        success: false, message: 'Demasiadas solicitudes', code: 'RATE_LIMITED', retryAfter: rate.retryAfter
                    });
                }

                // 3. Rutas típicas de escáneres
                if (SCANNER_PATH.test(req.path)) {
                    await events.record({
                        type: 'SCANNER_PATH', rule: 'SENSITIVE_PATH_PROBE', severity: 'low', riskScore: 20,
                        req, details: { path: req.path.slice(0, 200) }
                    });
                    await anomalyDetection.strike(req.ip, 'scanner', { threshold: cfg.scannerHitsToBlock });
                }

                // 4. Inyecciones
                const rejection = await this.checkInjection(req, cfg);
                if (rejection) return res.status(rejection.status).json(rejection.body);

                // 5. Ráfagas de 401/403 (solo cuentan las que genera el resto de la aplicación)
                res.once('finish', () => this.trackAuthFailures(req, res, cfg));

                next();
            } catch (error) {
                console.error('❌ Error en la capa de protección:', error.code || error.message);
                return unavailable(res);
            }
        };
    }

    async checkInjection(req, cfg) {
        const { findings } = scanRequest(req);
        if (findings.length === 0) return null;

        // Rechazable: severidad alta fuera del cuerpo; en el cuerpo, según la política (ver config)
        const bodyBlocks = cfg.bodyMode === 'block' || (cfg.bodyMode === 'critical' && isCriticalPath(req.path, cfg.criticalPaths));
        const blockable = findings.filter(f => f.severity === 'high' && (!f.bodyLike || bodyBlocks));

        // Se registran hasta 3 hallazgos por petición (los más graves primero) para no inundar la tabla
        const ordered = [...findings].sort((a, b) => (b.severity === 'high') - (a.severity === 'high')).slice(0, 3);
        for (const finding of ordered) {
            await events.record({
                type: 'INJECTION_ATTEMPT',
                rule: finding.rule,
                severity: finding.severity === 'high' ? 'high' : 'medium',
                riskScore: finding.severity === 'high' ? 80 : 30,
                action: blockable.length ? 'rejected' : 'logged',
                req,
                status: blockable.length ? (blockable[0].bodyLike ? 400 : 403) : null,
                details: { family: finding.family, location: finding.location, field: finding.field, sample: finding.sample }
            });
        }

        if (blockable.length === 0) return null;

        await anomalyDetection.strike(req.ip, 'injection', { threshold: cfg.strikesToBlock });

        const fromBody = blockable[0].bodyLike;
        return {
            status: fromBody ? 400 : 403,
            body: {
                success: false,
                message: fromBody ? 'La entrada contiene contenido no permitido' : 'Solicitud rechazada por razones de seguridad',
                code: 'MALICIOUS_INPUT'
            }
        };
    }

    async trackAuthFailures(req, res, cfg) {
        if (res.statusCode !== 401 && res.statusCode !== 403) return;
        try {
            const result = await anomalyDetection.strike(req.ip, 'authfail', { threshold: cfg.authFailuresToBlock });
            if (result.blocked) {
                await events.record({
                    type: 'AUTH_FAILURE_BURST', rule: 'REPEATED_401_403', severity: 'high', riskScore: 70,
                    action: 'blocked_ip', req, status: res.statusCode, details: { failures: result.count }
                });
            }
        } catch (error) {
            console.error('❌ Error contando fallos de autenticación:', error.code || error.message);
        }
    }

    // Limitador reutilizable para rutas concretas. Por defecto cuenta por IP;
    // `key` permite contar por otra cosa (p. ej. por usuario autenticado).
    //
    //   router.post('/', protection.limit({ scope: 'upload', limit: 20, key: req => `u:${req.user.id}` }), ...)
    limit({ scope, limit, windowSec = 60, key = (req) => ipSubject(req.ip), code = 'RATE_LIMITED', message = 'Demasiadas solicitudes' }) {
        return async (req, res, next) => {
            if (process.env.DISABLE_IP_BLOCKING === 'true') return next();

            try {
                const max = typeof limit === 'function' ? limit() : limit;
                const rate = await rateLimiter.hit(scope, String(key(req)).slice(0, 64), windowSec);

                if (rate.count > max) {
                    if (rate.count === max + 1) {
                        await events.record({
                            type: 'RATE_LIMITED', rule: `${scope}_LIMIT`.toUpperCase().slice(0, 64), severity: 'medium', riskScore: 35,
                            action: 'rate_limited', req, status: 429, details: { count: rate.count, limit: max }
                        });
                    }
                    res.set('Retry-After', String(rate.retryAfter));
                    return res.status(429).json({ success: false, message, code, retryAfter: rate.retryAfter });
                }
                next();
            } catch (error) {
                console.error('❌ Error en el limitador de peticiones:', error.code || error.message);
                return unavailable(res);
            }
        };
    }

    // Rate limiting estricto para operaciones sensibles (login, registro, tareas administrativas)
    highSecurity() {
        return this.limit({
            scope: 'sensitive',
            limit: () => config().sensitivePerMin,
            code: 'HIGH_SECURITY_RATE_LIMITED',
            message: 'Límite de solicitudes excedido para esta operación sensible'
        });
    }

    addSecurityHeaders(req, res) {
        res.setHeader('X-Content-Type-Options', 'nosniff');
        res.setHeader('X-Frame-Options', 'DENY');
        res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
        res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
        res.setHeader('Cross-Origin-Resource-Policy', 'same-site');
        // (No se fija X-XSS-Protection: el valor "1; mode=block" está desaconsejado; helmet envía "0")

        // Respuestas de la API: nada se cachea en intermediarios (las descargas de archivos lo sobrescriben)
        if (req.path.startsWith('/api/')) res.setHeader('Cache-Control', 'no-store');

        res.removeHeader('X-Powered-By');
        res.setHeader('Server', 'SecureServer');
    }

    async getProtectionStats() {
        return rateLimiter.stats();
    }
}

module.exports = new ProtectionMiddleware();
module.exports.isCriticalPath = isCriticalPath;
