const crypto = require('crypto');
const db = require('../config/database');
const { sqlInt, sqlPlaceholders } = require('../config/sql');
const events = require('./security-events.service');
const metrics = require('../observability/metrics');

// Alertas de seguridad AUTOMÁTICAS sobre la tabla de análisis (security_events).
//
// Un evaluador periódico (cada ALERT_EVAL_INTERVAL_SECONDS, 60) ejecuta unas reglas fijas, cada una con UNA consulta
// parametrizada, y levanta una alerta cuando algo cruza su umbral. Una sola alerta ACTIVA por (regla, sujeto): si la
// condición persiste se actualiza en vez de duplicarse (índice único sobre active_key: seguro con varias instancias).
//
//   ALERT_WINDOW_MINUTES (10)          ventana que miran las reglas
//   ALERT_LOGIN_FAILURES (50)          fallos de login en la ventana ...
//   ALERT_LOGIN_FAILURE_IPS (10)       ... desde al menos estas IP distintas  => ataque distribuido
//   ALERT_ACCOUNT_FAILURES (15)        fallos contra UNA cuenta
//   ALERT_MFA_FAILURES (10)            códigos MFA erróneos contra UN usuario
//   ALERT_INJECTION_ATTEMPTS (20)      intentos de inyección en la ventana
//   ALERT_IP_BLOCKS (10)               bloqueos de IP en la ventana
//   ALERT_AUTO_RESOLVE_MINUTES (60)    una alerta RECONOCIDA sin recurrencia se resuelve sola; las abiertas NO
//   ALERT_WEBHOOK_URL / ALERT_WEBHOOK_SECRET / ALERT_NOTIFY_MIN_SEVERITY (high)
//
// La alerta avisa, no actúa: no bloquea ni cierra nada por sí sola.

const SEVERITIES = ['low', 'medium', 'high', 'critical'];
const intEnv = (name, fallback) => {
    const n = Number(process.env[name]);
    return Number.isInteger(n) && n > 0 ? n : fallback;
};
const cfg = () => ({
    window: intEnv('ALERT_WINDOW_MINUTES', 10),
    loginFailures: intEnv('ALERT_LOGIN_FAILURES', 50),
    loginFailureIps: intEnv('ALERT_LOGIN_FAILURE_IPS', 10),
    accountFailures: intEnv('ALERT_ACCOUNT_FAILURES', 15),
    mfaFailures: intEnv('ALERT_MFA_FAILURES', 10),
    injections: intEnv('ALERT_INJECTION_ATTEMPTS', 20),
    ipBlocks: intEnv('ALERT_IP_BLOCKS', 10),
    autoResolve: intEnv('ALERT_AUTO_RESOLVE_MINUTES', 60)
});

const SENSITIVE_ADMIN_TYPES = ['ADMIN_APPROVAL_EXECUTED', 'MFA_RESET_BY_ADMIN', 'PRIVACY_EXPORT', 'USER_ERASED', 'SESSIONS_REVOKED_ALL'];

// Cada regla devuelve una lista de { subject, severity, title, count, details }. Las consultas son fijas.
const RULES = [
    {
        id: 'EVENT_CRITICAL',
        async find(c) {
            const [rows] = await db.query(
                `SELECT event_type, COALESCE(rule, '-') AS rule, COUNT(*) AS n, COUNT(DISTINCT ip_address) AS ips
                 FROM security_events WHERE severity = 'critical' AND created_at > DATE_SUB(NOW(), INTERVAL ? MINUTE)
                 GROUP BY event_type, rule`, [c.window]);
            return rows.map(r => ({
                subject: `${r.event_type}/${r.rule}`.slice(0, 120), severity: 'critical', count: Number(r.n),
                title: `Evento crítico: ${r.event_type}`, details: { rule: r.rule, distinctIps: Number(r.ips) }
            }));
        }
    },
    {
        id: 'LOGIN_FAILURES_DISTRIBUTED',
        async find(c) {
            const [[r]] = await db.query(
                `SELECT COUNT(*) AS n, COUNT(DISTINCT ip_address) AS ips FROM security_events
                 WHERE event_type = 'LOGIN_FAILED' AND created_at > DATE_SUB(NOW(), INTERVAL ? MINUTE)`, [c.window]);
            if (Number(r.n) < c.loginFailures || Number(r.ips) < c.loginFailureIps) return [];
            return [{ subject: 'global', severity: 'high', count: Number(r.n), title: 'Fallos de login masivos desde muchas IP (credential stuffing)', details: { failures: Number(r.n), distinctIps: Number(r.ips), windowMinutes: c.window } }];
        }
    },
    {
        id: 'ACCOUNT_UNDER_ATTACK',
        async find(c) {
            const [rows] = await db.query(
                `SELECT username_hash, COUNT(*) AS n, COUNT(DISTINCT ip_address) AS ips FROM security_events
                 WHERE event_type IN ('LOGIN_FAILED', 'LOGIN_BLOCKED') AND username_hash IS NOT NULL AND created_at > DATE_SUB(NOW(), INTERVAL ? MINUTE)
                 GROUP BY username_hash HAVING COUNT(*) >= ? LIMIT 20`, [c.window, c.accountFailures]);
            return rows.map(r => ({ subject: `account:${r.username_hash.slice(0, 16)}`, severity: 'medium', count: Number(r.n), title: 'Una cuenta recibe muchos intentos fallidos', details: { distinctIps: Number(r.ips), windowMinutes: c.window } }));
        }
    },
    {
        id: 'MFA_CODE_GUESSING',
        async find(c) {
            const [rows] = await db.query(
                `SELECT user_id, COUNT(*) AS n FROM security_events
                 WHERE event_type = 'LOGIN_FAILED' AND rule IN ('BAD_MFA_CODE', 'MFA_CODE_REPLAY') AND user_id IS NOT NULL
                   AND created_at > DATE_SUB(NOW(), INTERVAL ? MINUTE)
                 GROUP BY user_id HAVING COUNT(*) >= ? LIMIT 20`, [c.window, c.mfaFailures]);
            return rows.map(r => ({ subject: `user:${r.user_id}`, severity: 'high', count: Number(r.n), title: 'Alguien conoce la contraseña de un usuario y prueba códigos MFA', details: { userId: r.user_id, windowMinutes: c.window } }));
        }
    },
    {
        id: 'INJECTION_WAVE',
        async find(c) {
            const [[r]] = await db.query(
                `SELECT COUNT(*) AS n, COUNT(DISTINCT ip_address) AS ips FROM security_events
                 WHERE event_type = 'INJECTION_ATTEMPT' AND created_at > DATE_SUB(NOW(), INTERVAL ? MINUTE)`, [c.window]);
            if (Number(r.n) < c.injections) return [];
            return [{ subject: 'global', severity: 'medium', count: Number(r.n), title: 'Oleada de intentos de inyección', details: { distinctIps: Number(r.ips), windowMinutes: c.window } }];
        }
    },
    {
        id: 'ANTIVIRUS_UNAVAILABLE',
        async find() {
            const [[r]] = await db.query(
                `SELECT COUNT(*) AS n FROM security_events
                 WHERE (event_type = 'SCANNER_UNAVAILABLE' OR (event_type = 'FILE_REJECTED' AND rule = 'SCANNER_UNAVAILABLE'))
                   AND created_at > DATE_SUB(NOW(), INTERVAL 30 MINUTE)`);
            if (Number(r.n) < 1) return [];
            return [{ subject: 'global', severity: 'high', count: Number(r.n), title: 'El antivirus no responde: las subidas se rechazan o pasan sin escanear', details: { windowMinutes: 30 } }];
        }
    },
    {
        id: 'SERVER_INTEGRITY',
        async find() {
            const [rows] = await db.query(
                `SELECT event_type, COUNT(*) AS n FROM security_events
                 WHERE event_type IN ('SERVER_INTEGRITY_BREACH', 'INTEGRITY_CHECK_FAILED') AND created_at > DATE_SUB(NOW(), INTERVAL 60 MINUTE)
                 GROUP BY event_type`);
            return rows.map(r => ({ subject: r.event_type, severity: 'critical', count: Number(r.n), title: 'Fallo de integridad del servidor', details: { windowMinutes: 60 } }));
        }
    },
    {
        id: 'IP_BLOCK_SPIKE',
        async find(c) {
            const [[r]] = await db.query(
                `SELECT COUNT(*) AS n FROM security_events WHERE event_type = 'IP_BLOCKED' AND created_at > DATE_SUB(NOW(), INTERVAL ? MINUTE)`, [c.window]);
            if (Number(r.n) < c.ipBlocks) return [];
            return [{ subject: 'global', severity: 'medium', count: Number(r.n), title: 'Muchas IP bloqueadas en poco tiempo', details: { windowMinutes: c.window } }];
        }
    },
    {
        id: 'EVENT_FLOOD',
        async find(c) {
            const [[r]] = await db.query(
                `SELECT COUNT(*) AS n FROM security_events WHERE event_type = 'EVENTS_THROTTLED' AND created_at > DATE_SUB(NOW(), INTERVAL ? MINUTE)`, [c.window]);
            if (Number(r.n) < 1) return [];
            return [{ subject: 'global', severity: 'medium', count: Number(r.n), title: 'Alguien inunda la tabla de eventos (se está recortando)', details: { windowMinutes: c.window } }];
        }
    },
    {
        // No es un ataque: es que alguien hizo algo delicado. Queda a la vista para que otra persona lo confirme.
        id: 'SENSITIVE_ADMIN_ACTIVITY',
        async find() {
            const [rows] = await db.query(
                `SELECT event_type, COUNT(*) AS n FROM security_events
                 WHERE event_type IN (${sqlPlaceholders(SENSITIVE_ADMIN_TYPES.length)}) AND created_at > DATE_SUB(NOW(), INTERVAL 30 MINUTE)
                 GROUP BY event_type`, SENSITIVE_ADMIN_TYPES);
            return rows.map(r => ({ subject: r.event_type, severity: 'medium', count: Number(r.n), title: `Actividad administrativa sensible: ${r.event_type}`, details: { windowMinutes: 30 } }));
        }
    }
];

// ------------------------------------------------------------------ aviso externo
function severityAtLeast(severity, minimum) {
    return SEVERITIES.indexOf(severity) >= SEVERITIES.indexOf(SEVERITIES.includes(minimum) ? minimum : 'high');
}

async function notify(alert) {
    const url = process.env.ALERT_WEBHOOK_URL;
    if (!url || !severityAtLeast(alert.severity, process.env.ALERT_NOTIFY_MIN_SEVERITY || 'high')) return { skipped: true };

    try {
        const target = new URL(url);
        const insecure = target.protocol !== 'https:';
        if (insecure && (target.protocol !== 'http:' || (process.env.NODE_ENV === 'production' && process.env.ALERT_WEBHOOK_ALLOW_HTTP !== 'true'))) {
            throw new Error('ALERT_WEBHOOK_URL debe ser https://');
        }
        const body = JSON.stringify({
            text: `[${alert.severity.toUpperCase()}] ${alert.title}`,
            alert: { id: alert.id, rule: alert.rule, subject: alert.subject, severity: alert.severity, count: alert.count, details: alert.details }
        });
        const headers = { 'Content-Type': 'application/json' };
        if (process.env.ALERT_WEBHOOK_SECRET) {
            headers['X-Signature-256'] = `sha256=${crypto.createHmac('sha256', process.env.ALERT_WEBHOOK_SECRET).update(body).digest('hex')}`;
        }
        const res = await fetch(target, { method: 'POST', headers, body, redirect: 'error', signal: AbortSignal.timeout(5000) });
        if (!res.ok) throw new Error(`el destino respondió ${res.status}`);
        return { sent: true };
    } catch (error) {
        return { error: String(error.message).slice(0, 120) };
    }
}

// ------------------------------------------------------------------ evaluador
let evaluating = false;

async function raise(rule, finding) {
    const dedupeKey = `${rule.id}|${finding.subject}`.slice(0, 190);
    const details = JSON.stringify(finding.details || {});
    const [existing] = await db.query('SELECT id, severity FROM security_alerts WHERE active_key = ?', [dedupeKey]);

    const update = async (row) => {
        const higher = SEVERITIES.indexOf(finding.severity) > SEVERITIES.indexOf(row.severity) ? finding.severity : row.severity;
        await db.query('UPDATE security_alerts SET last_seen = NOW(), event_count = ?, details = ?, severity = ? WHERE id = ?', [finding.count, details, higher, row.id]);
        return { created: false, id: row.id };
    };
    if (existing[0]) return update(existing[0]);

    try {
        const [inserted] = await db.query(
            `INSERT INTO security_alerts (rule, subject, dedupe_key, severity, title, event_count, details) VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [rule.id, finding.subject.slice(0, 120), dedupeKey, finding.severity, finding.title.slice(0, 160), finding.count, details]
        );
        const alert = { id: inserted.insertId, rule: rule.id, subject: finding.subject, severity: finding.severity, title: finding.title, count: finding.count, details: finding.details };
        metrics.alertsRaised.inc({ rule: rule.id, severity: finding.severity });

        const sent = await notify(alert);
        if (sent.sent) await db.query('UPDATE security_alerts SET notified_at = NOW() WHERE id = ?', [alert.id]);
        else if (sent.error) await db.query('UPDATE security_alerts SET notify_error = ? WHERE id = ?', [sent.error, alert.id]);
        return { created: true, id: alert.id };
    } catch (error) {
        if (error.code !== 'ER_DUP_ENTRY') throw error;   // otra instancia la creó justo ahora
        const [again] = await db.query('SELECT id, severity FROM security_alerts WHERE active_key = ?', [dedupeKey]);
        return again[0] ? update(again[0]) : { created: false, id: null };
    }
}

async function evaluate() {
    if (evaluating) return { skipped: true };
    evaluating = true;
    const summary = { created: 0, updated: 0, autoResolved: 0, errors: [] };
    try {
        const c = cfg();
        for (const rule of RULES) {
            try {
                for (const finding of await rule.find(c)) {
                    const outcome = await raise(rule, finding);
                    outcome.created ? summary.created++ : summary.updated++;
                }
            } catch (error) {
                summary.errors.push(`${rule.id}: ${error.code || error.message}`);
            }
        }
        // Solo las RECONOCIDAS se cierran solas; una alerta abierta que nadie ha visto no desaparece
        const [auto] = await db.query(
            `UPDATE security_alerts SET status = 'resolved', resolved_at = NOW()
             WHERE status = 'acknowledged' AND last_seen < DATE_SUB(NOW(), INTERVAL ? MINUTE)`, [c.autoResolve]);
        summary.autoResolved = auto.affectedRows;
        return summary;
    } finally {
        evaluating = false;
    }
}

// ------------------------------------------------------------------ consulta y gestión
const publicAlert = (row) => ({
    id: Number(row.id), rule: row.rule, subject: row.subject, severity: row.severity, title: row.title, status: row.status,
    count: row.event_count, firstSeen: row.first_seen, lastSeen: row.last_seen,
    details: row.details ? safeParse(row.details) : null,
    acknowledgedBy: row.acknowledged_by, acknowledgedAt: row.acknowledged_at, resolvedBy: row.resolved_by, resolvedAt: row.resolved_at,
    notified: Boolean(row.notified_at), notifyError: row.notify_error
});
function safeParse(text) { try { return JSON.parse(text); } catch { return null; } }

async function list({ status = null, severity = null, beforeId = null, limit = 100 } = {}) {
    const [rows] = await db.query(
        `SELECT * FROM security_alerts
         WHERE (? IS NULL OR status = ?) AND (? IS NULL OR severity = ?) AND (? IS NULL OR id < ?)
         ORDER BY id DESC LIMIT ${sqlInt(limit, { min: 1, max: 500 })}`,
        [status, status, severity, severity, beforeId, beforeId]
    );
    return rows.map(publicAlert);
}

class AlertError extends Error {
    constructor(code, message, status) { super(message); this.code = code; this.status = status; }
}

async function transition(id, userId, to) {
    const [result] = to === 'acknowledged'
        ? await db.query("UPDATE security_alerts SET status = 'acknowledged', acknowledged_by = ?, acknowledged_at = NOW() WHERE id = ? AND status = 'open'", [userId, id])
        : await db.query("UPDATE security_alerts SET status = 'resolved', resolved_by = ?, resolved_at = NOW() WHERE id = ? AND status <> 'resolved'", [userId, id]);
    if (result.affectedRows === 1) return;
    const [rows] = await db.query('SELECT status FROM security_alerts WHERE id = ?', [id]);
    if (!rows[0]) throw new AlertError('NOT_FOUND', 'Alerta no encontrada', 404);
    throw new AlertError('INVALID_STATE', `La alerta ya está "${rows[0].status}"`, 409);
}
const acknowledge = (id, userId) => transition(id, userId, 'acknowledged');
const resolve = (id, userId) => transition(id, userId, 'resolved');

// ------------------------------------------------------------------ programación
let timer = null;
function start() {
    if (timer || process.env.ALERTS_DISABLED === 'true') return;
    timer = setInterval(() => { evaluate().catch(() => {}); }, intEnv('ALERT_EVAL_INTERVAL_SECONDS', 60) * 1000);
    timer.unref();
}
function stop() {
    if (timer) clearInterval(timer);
    timer = null;
}

module.exports = { evaluate, list, acknowledge, resolve, start, stop, notify, AlertError, RULES, SEVERITIES };
