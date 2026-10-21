const db = require('../config/database');
const { sqlInt } = require('../config/sql');
const rateLimiter = require('./rate-limiter.service');
const { normalizeIp, ipSubject } = require('./ip');

// Tabla de ANÁLISIS de seguridad (`security_events`): una fila por cosa sospechosa que pasa.
//
// Está en claro a propósito: sirve para consultarla con SQL después ("¿quién probó inyecciones
// esta semana?", "¿qué IPs fallan logins en ráfaga?"). Por eso NUNCA se guardan contraseñas,
// tokens ni cabeceras de autorización: los campos con nombre sensible se sustituyen por [redactado]
// y todo texto se acota. Los detalles que sí son confidenciales van a `security_logs`, que está cifrada.

const SENSITIVE_KEY = /pass(?:word|wd)?|secret|token|authorization|api[-_]?key|cookie|credential/i;
const MAX_DETAILS_CHARS = 4000;
const SEVERITIES = ['info', 'low', 'medium', 'high', 'critical'];
const ACTIONS = ['logged', 'rate_limited', 'rejected', 'blocked_ip', 'locked_account'];

// Tope de eventos por (IP, tipo) y minuto: sin él, quien inunda la API de ataques inundaría también esta
// tabla. Lo que excede se descarta y queda UNA fila EVENTS_THROTTLED que lo señala.
const eventCap = () => Number(process.env.SECURITY_EVENTS_MAX_PER_MINUTE) || 30;
const NEVER_THROTTLED = new Set(['IP_BLOCKED', 'FILE_INTEGRITY_FAILURE', 'EVENTS_THROTTLED']);

function sanitize(value, depth = 0) {
    if (value === null || value === undefined) return value;
    if (typeof value === 'string') return value.length > 300 ? `${value.slice(0, 300)}…` : value;
    if (typeof value !== 'object') return value;
    if (depth > 4) return '[profundidad máxima]';
    if (Array.isArray(value)) return value.slice(0, 20).map(v => sanitize(v, depth + 1));

    const out = {};
    for (const [key, val] of Object.entries(value).slice(0, 40)) {
        out[key] = SENSITIVE_KEY.test(key) ? '[redactado]' : sanitize(val, depth + 1);
    }
    return out;
}

function serializeDetails(details) {
    if (details === null || details === undefined) return null;
    const json = JSON.stringify(sanitize(details));
    return json.length <= MAX_DETAILS_CHARS ? json : JSON.stringify({ truncated: true, preview: json.slice(0, MAX_DETAILS_CHARS - 40) });
}

function countryOf(ip) {
    try {
        return require('geoip-lite').lookup(ip)?.country || null;
    } catch {
        return null;
    }
}

class SecurityEvents {
    // Nunca lanza: registrar un evento no debe romper la petición que lo originó.
    async record({
        type, rule = null, severity = 'low', riskScore = 0, action = 'logged',
        req = null, ip = null, userId = null, usernameHash = null, status = null, details = null
    }) {
        try {
            const address = normalizeIp(ip || req?.ip);

            if (!NEVER_THROTTLED.has(type) && address !== 'unknown') {
                const { count } = await rateLimiter.hit(`evt:${type}`.slice(0, 24), ipSubject(address), 60);
                if (count > eventCap()) {
                    if (count === eventCap() + 1) {
                        await this.record({ type: 'EVENTS_THROTTLED', rule: String(type).slice(0, 64), severity: 'medium', ip: address, details: { cap: eventCap() } });
                    }
                    return;
                }
            }

            const sev = SEVERITIES.includes(severity) ? severity : 'low';
            const act = ACTIONS.includes(action) ? action : 'logged';

            await db.query(
                `INSERT INTO security_events
                    (event_type, rule, severity, risk_score, action_taken, ip_address, user_id, username_hash,
                     method, path, status_code, user_agent, country, details)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                [
                    String(type).slice(0, 64),
                    rule ? String(rule).slice(0, 64) : null,
                    sev,
                    Math.max(0, Math.min(255, Math.round(riskScore))),
                    act,
                    address === 'unknown' ? null : address,
                    userId ?? req?.user?.id ?? null,
                    usernameHash,
                    req?.method ? String(req.method).slice(0, 10) : null,
                    req ? String(req.originalUrl || req.url || '').split('?')[0].slice(0, 255) : null,
                    status,
                    req?.headers?.['user-agent'] ? String(req.headers['user-agent']).slice(0, 255) : null,
                    address === 'unknown' ? null : countryOf(address),
                    serializeDetails(details)
                ]
            );
        } catch (error) {
            console.error('❌ No se pudo registrar el evento de seguridad:', error.code || error.message);
        }
    }

    // Consulta filtrable (usada por GET /api/system/security-events). Una sola consulta fija:
    // los filtros opcionales son `(? IS NULL OR columna = ?)`, sin construir SQL con texto.
    async list({ type, rule, severity, ip, userId, sinceHours = 24, beforeId, limit = 100 } = {}) {
        const n = (v) => (v === undefined || v === '' ? null : v);
        const [rows] = await db.query(
            `SELECT id, created_at, event_type, rule, severity, risk_score, action_taken, ip_address, user_id,
                    username_hash, method, path, status_code, user_agent, country, details
             FROM security_events
             WHERE created_at >= DATE_SUB(NOW(), INTERVAL ? HOUR)
               AND (? IS NULL OR event_type = ?)
               AND (? IS NULL OR rule = ?)
               AND (? IS NULL OR severity = ?)
               AND (? IS NULL OR ip_address = ?)
               AND (? IS NULL OR user_id = ?)
               AND (? IS NULL OR id < ?)
             ORDER BY id DESC
             LIMIT ${sqlInt(limit, { min: 1, max: 500 })}`,
            [
                Number(sqlInt(sinceHours, { min: 1, max: 24 * 365 })),
                n(type), n(type), n(rule), n(rule), n(severity), n(severity),
                n(ip), n(ip), n(userId), n(userId), n(beforeId), n(beforeId)
            ]
        );
        return rows.map(row => ({ ...row, details: row.details ? safeParse(row.details) : null }));
    }

    // Resumen para ver de un vistazo qué pasó en las últimas `hours` horas
    async summary({ hours = 24 } = {}) {
        const h = Number(sqlInt(hours, { min: 1, max: 24 * 90 }));
        const [byType] = await db.query(
            `SELECT event_type, severity, COUNT(*) AS total FROM security_events WHERE created_at >= DATE_SUB(NOW(), INTERVAL ? HOUR) GROUP BY event_type, severity ORDER BY total DESC LIMIT 50`, [h]);
        const [topIps] = await db.query(
            `SELECT ip_address, COUNT(*) AS total, MAX(risk_score) AS max_risk, MAX(country) AS country
             FROM security_events WHERE created_at >= DATE_SUB(NOW(), INTERVAL ? HOUR) AND ip_address IS NOT NULL GROUP BY ip_address ORDER BY total DESC LIMIT 10`, [h]);
        const [topRules] = await db.query(
            `SELECT rule, COUNT(*) AS total FROM security_events WHERE created_at >= DATE_SUB(NOW(), INTERVAL ? HOUR) AND rule IS NOT NULL GROUP BY rule ORDER BY total DESC LIMIT 10`, [h]);
        const [timeline] = await db.query(
            `SELECT DATE_FORMAT(created_at, '%Y-%m-%d %H:00') AS hour, COUNT(*) AS total
             FROM security_events WHERE created_at >= DATE_SUB(NOW(), INTERVAL ? HOUR) GROUP BY hour ORDER BY hour`, [h]);
        const [[blocked]] = await db.query('SELECT COUNT(*) AS active FROM blocked_ips WHERE blocked_until > NOW()');

        return { windowHours: h, byType, topIps, topRules, timeline, activeBlockedIps: blocked.active };
    }

    async purge(retentionDays = Number(process.env.SECURITY_EVENTS_RETENTION_DAYS) || 90) {
        const days = Number(sqlInt(retentionDays, { min: 1, max: 3650 }));
        const [result] = await db.query('DELETE FROM security_events WHERE created_at < DATE_SUB(NOW(), INTERVAL ? DAY) LIMIT 5000', [days]);
        return result.affectedRows;
    }
}

function safeParse(text) {
    try { return JSON.parse(text); } catch { return text; }
}

module.exports = new SecurityEvents();
module.exports.sanitize = sanitize;
