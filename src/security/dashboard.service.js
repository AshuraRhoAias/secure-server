const db = require('../config/database');
const { sqlInt } = require('../config/sql');
const events = require('./security-events.service');

// Panel de operación (GET /api/system/dashboard, SOLO admin): una foto de cómo está la seguridad ahora mismo.
// Son consultas de lectura con índice; no incluye secretos, tokens ni contenidos de usuarios.

const count = async (sql, params = []) => Number((await db.query(sql, params))[0][0].n);

// Peticiones idénticas simultáneas (varios administradores con el panel abierto, o varias pestañas) comparten UN cálculo: son ~13
// consultas. No hay caché con caducidad: en cuanto termina, la siguiente petición vuelve a calcular con datos frescos.
const inflight = new Map();

function snapshot({ hours = 24 } = {}) {
    const h = Number(sqlInt(hours, { min: 1, max: 24 * 30 }));
    if (!inflight.has(h)) inflight.set(h, compute(h).finally(() => inflight.delete(h)));
    return inflight.get(h);
}

async function compute(h) {
    const secureAuth = require('./secure-auth.service');
    const lockout = secureAuth.lockout;

    const [
        alertRows, openAlerts, severityRows, loginRows, topUsersTargeted, activeSessions, refreshReuse,
        pendingApprovals, blockedIps, fileRows, rejectedUploads, summary, dbPing
    ] = await Promise.all([
        db.query("SELECT severity, COUNT(*) AS n FROM security_alerts WHERE status <> 'resolved' GROUP BY severity"),
        db.query("SELECT id, rule, subject, severity, title, status, event_count, first_seen, last_seen FROM security_alerts WHERE status <> 'resolved' ORDER BY FIELD(severity, 'critical', 'high', 'medium', 'low'), id DESC LIMIT 10"),
        db.query('SELECT severity, COUNT(*) AS n FROM security_events WHERE created_at >= DATE_SUB(NOW(), INTERVAL ? HOUR) GROUP BY severity', [h]),
        db.query('SELECT success, COUNT(*) AS n FROM login_attempts WHERE created_at >= DATE_SUB(NOW(), INTERVAL ? HOUR) GROUP BY success', [h]),
        db.query(`SELECT username_hash, COUNT(*) AS n FROM login_attempts
                  WHERE success = 0 AND created_at >= DATE_SUB(NOW(), INTERVAL ? SECOND) GROUP BY username_hash HAVING COUNT(*) >= ? LIMIT 20`, [lockout.windowSec, lockout.maxFailures]),
        count("SELECT COUNT(*) AS n FROM user_sessions WHERE revoked_at IS NULL AND expires_at > NOW() AND (absolute_expires_at IS NULL OR absolute_expires_at > NOW())"),
        count("SELECT COUNT(*) AS n FROM security_events WHERE event_type = 'REFRESH_TOKEN_REUSE' AND created_at >= DATE_SUB(NOW(), INTERVAL ? HOUR)", [h]),
        count("SELECT COUNT(*) AS n FROM admin_approvals WHERE status = 'pending' AND expires_at > NOW()"),
        count('SELECT COUNT(*) AS n FROM blocked_ips WHERE blocked_until > NOW()'),
        db.query('SELECT scan_status, sanitize_status, COUNT(*) AS n, COALESCE(SUM(size_bytes), 0) AS bytes FROM user_files GROUP BY scan_status, sanitize_status'),
        count("SELECT COUNT(*) AS n FROM security_events WHERE event_type = 'FILE_REJECTED' AND created_at >= DATE_SUB(NOW(), INTERVAL ? HOUR)", [h]),
        events.summary({ hours: h }),
        count('SELECT 1 AS n')
    ]);

    const bySeverity = Object.fromEntries(severityRows[0].map(r => [r.severity, Number(r.n)]));
    const logins = Object.fromEntries(loginRows[0].map(r => [r.success ? 'success' : 'failed', Number(r.n)]));
    const filesByScan = {}, filesBySanitize = {};
    let fileTotal = 0, fileBytes = 0;
    for (const r of fileRows[0]) {
        fileTotal += Number(r.n); fileBytes += Number(r.bytes);
        filesByScan[r.scan_status] = (filesByScan[r.scan_status] || 0) + Number(r.n);
        filesBySanitize[r.sanitize_status] = (filesBySanitize[r.sanitize_status] || 0) + Number(r.n);
    }

    return {
        generatedAt: new Date().toISOString(),
        windowHours: h,
        alerts: {
            open: Object.fromEntries(alertRows[0].map(r => [r.severity, Number(r.n)])),
            latest: openAlerts[0].map(a => ({ id: Number(a.id), rule: a.rule, subject: a.subject, severity: a.severity, title: a.title, status: a.status, count: a.event_count, firstSeen: a.first_seen, lastSeen: a.last_seen }))
        },
        events: {
            bySeverity,
            total: Object.values(bySeverity).reduce((a, b) => a + b, 0),
            topTypes: summary.byType.slice(0, 10),
            topRules: summary.topRules,
            topIps: summary.topIps,
            timeline: summary.timeline
        },
        auth: {
            logins: { success: logins.success || 0, failed: logins.failed || 0 },
            accountsAtLockThreshold: topUsersTargeted[0].length,
            activeSessions,
            refreshTokenReuse: refreshReuse
        },
        files: { total: fileTotal, bytes: fileBytes, byScanStatus: filesByScan, bySanitizeStatus: filesBySanitize, rejectedInWindow: rejectedUploads },
        approvals: { pending: pendingApprovals },
        blockedIps: { active: blockedIps },
        system: {
            database: dbPing === 1 ? 'ok' : 'error',
            uptimeSeconds: Math.round(process.uptime()),
            node: process.version,
            config: {
                mfaRequiredForPrivilegedRoles: process.env.MFA_REQUIRED_FOR_ADMINS === 'true',
                adminApprovalsRequired: Number(process.env.ADMIN_APPROVALS_REQUIRED) >= 1 ? Number(process.env.ADMIN_APPROVALS_REQUIRED) : 2,
                fileScan: process.env.FILE_SCAN || 'off',
                imageSanitize: (process.env.IMAGE_SANITIZE || 'on') !== 'off',
                pdfActiveContent: process.env.PDF_ACTIVE_CONTENT || 'reject',
                kmsProvider: process.env.KMS_PROVIDER || null,
                alertWebhook: Boolean(process.env.ALERT_WEBHOOK_URL),
                otlpExport: Boolean(process.env.OTEL_EXPORTER_OTLP_TRACES_ENDPOINT || process.env.OTEL_EXPORTER_OTLP_ENDPOINT)
            }
        }
    };
}

module.exports = { snapshot };
