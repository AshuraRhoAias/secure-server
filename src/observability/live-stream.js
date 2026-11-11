// GET /api/system/stream — novedades en vivo para la interfaz de operación (Server-Sent Events). SOLO admin (dashboard:read).
//
// Por qué SSE y cómo:
//   - Es HTTP normal (una respuesta que no termina): pasa por el BFF, por proxies y balanceadores, no necesita otro puerto ni
//     protocolo, y el navegador reconecta solo (EventSource) retomando desde el último id (cabecera Last-Event-ID).
//   - Cada conexión consulta la BD cada STREAM_POLL_MS (2 s) con un CURSOR (id > último enviado): no hay estado compartido entre
//     procesos, así que funciona igual con un proceso, con el cluster o con varias máquinas detrás de un balanceador. Son una o dos
//     consultas por índice primario por conexión; para un puñado de administradores es despreciable (límites abajo).
//   - Solo viajan resúmenes: id, tipo, regla, severidad, ruta, estado, IP y usuario de cada evento (lo mismo que ya ve un admin en
//     /security-events), nunca `details`, cabeceras ni cuerpos.
//
// Seguridad de una conexión larga:
//   - El token se REVALIDA cada STREAM_AUTH_RECHECK_MS (30 s): sesión revocada, cuenta bloqueada o rol retirado → evento
//     `reauth` y se cierra. Además la conexión se cierra cuando caduca el JWT (15 min): el BFF renueva y el navegador reconecta.
//   - Límites: STREAM_MAX_CONNECTIONS por proceso (100) y STREAM_MAX_PER_USER (5) → 429 STREAM_LIMIT.
//   - En el cierre ordenado del servidor se envía `bye` y se cierran todas (no retrasan el apagado).

const jwt = require('jsonwebtoken');
const db = require('../config/database');
const secureAuth = require('../security/secure-auth.service');
const permissions = require('../security/permissions');
const { sqlInt, sqlPlaceholders } = require('../config/sql');

const intEnv = (name, fallback, min = 1) => {
    const n = Number(process.env[name]);
    return Number.isInteger(n) && n >= min ? n : fallback;
};
const config = () => ({
    pollMs: intEnv('STREAM_POLL_MS', 2000, 250),
    heartbeatMs: intEnv('STREAM_HEARTBEAT_MS', 15000, 1000),
    recheckMs: intEnv('STREAM_AUTH_RECHECK_MS', 30000, 1000),
    maxConnections: intEnv('STREAM_MAX_CONNECTIONS', 100),
    maxPerUser: intEnv('STREAM_MAX_PER_USER', 5),
    batch: 100
});

const SEVERITIES = ['info', 'low', 'medium', 'high', 'critical'];
const PERMISSION = 'dashboard:read';

// Last-Event-ID: "e<id del último evento>.a<id de la última alerta>" (lo genera este servicio; cualquier otra cosa se ignora)
function parseCursor(header) {
    const match = /^e(\d{1,15})\.a(\d{1,15})$/.exec(String(header || ''));
    return match ? { eventId: Number(match[1]), alertId: Number(match[2]) } : null;
}

const toIso = (value) => (value instanceof Date ? value.toISOString() : value ? new Date(value).toISOString() : null);

class LiveStream {
    constructor() {
        this.clients = new Set();
        this.handler = this.handler.bind(this);
    }

    stats() {
        const perUser = {};
        for (const c of this.clients) perUser[c.userId] = (perUser[c.userId] || 0) + 1;
        return { open: this.clients.size, users: Object.keys(perUser).length };
    }

    async stillAllowed(client) {
        const validation = await secureAuth.validateToken(client.token, client.ip);
        if (!validation.valid || validation.userId !== client.userId) return false;
        const [rows] = await db.query('SELECT role FROM users WHERE id = ?', [client.userId]);
        const role = rows[0]?.role;
        return Boolean(role && permissions.isKnownRole(role) && permissions.can(role, PERMISSION));
    }

    async handler(req, res) {
        const cfg = config();
        const userId = req.user.id;
        if (this.clients.size >= cfg.maxConnections || [...this.clients].filter(c => c.userId === userId).length >= cfg.maxPerUser) {
            res.set('Retry-After', '30');
            return res.status(429).json({ success: false, message: 'Demasiadas conexiones de streaming abiertas', code: 'STREAM_LIMIT' });
        }
        const minSeverity = SEVERITIES.includes(req.validated?.query?.minSeverity) ? req.validated.query.minSeverity : 'medium';
        const severities = SEVERITIES.slice(SEVERITIES.indexOf(minSeverity));

        // Punto de partida: lo que pida el navegador al reconectar, o "desde ahora" (no se repite el historial: para eso está /security-events)
        let cursor = parseCursor(req.get('last-event-id'));
        if (!cursor) {
            const [[ev]] = await db.query('SELECT COALESCE(MAX(id), 0) AS id FROM security_events');
            const [[al]] = await db.query('SELECT COALESCE(MAX(id), 0) AS id FROM security_alerts');
            cursor = { eventId: Number(ev.id), alertId: Number(al.id) };
        }

        const token = String(req.headers.authorization || '').slice(7);
        const exp = Number(jwt.decode(token)?.exp) * 1000;
        const client = { userId, token, ip: req.ip, res, timers: [], closed: false, digest: null, cursor, busy: false };
        this.clients.add(client);

        res.status(200);
        res.set({
            'Content-Type': 'text/event-stream; charset=utf-8',
            // no-transform: el middleware de compresión NO comprime (comprimir obliga a acumular y rompe el streaming)
            'Cache-Control': 'no-store, no-transform',
            'X-Accel-Buffering': 'no',
            Connection: 'keep-alive'
        });
        res.flushHeaders();

        const write = (text) => { if (!client.closed) { res.write(text); res.flush?.(); } };
        const send = (event, data, withId = false) => write(`${withId ? `id: e${client.cursor.eventId}.a${client.cursor.alertId}\n` : ''}event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
        const close = (event, data) => {
            if (client.closed) return;
            if (event) send(event, data);
            client.closed = true;
            client.timers.forEach(t => clearInterval(t) || clearTimeout(t));
            this.clients.delete(client);
            res.end();
        };
        client.close = close;
        req.on('close', () => close());

        write(`retry: 5000\n\n`);
        send('hello', { pollMs: cfg.pollMs, minSeverity, serverTime: new Date().toISOString() }, true);

        const poll = async () => {
            if (client.closed || client.busy) return;
            client.busy = true;
            try {
                const [events] = await db.query(
                    `SELECT id, created_at, event_type, rule, severity, action_taken, ip_address, user_id, method, path, status_code
                     FROM security_events WHERE id > ? AND severity IN (${sqlPlaceholders(severities.length)}) ORDER BY id LIMIT ${sqlInt(cfg.batch, { min: 1, max: 500 })}`,
                    [client.cursor.eventId, ...severities]
                );
                const [alerts] = await db.query(
                    'SELECT id, rule, subject, severity, title, status, event_count, first_seen, last_seen FROM security_alerts WHERE id > ? ORDER BY id LIMIT 50',
                    [client.cursor.alertId]
                );
                // Resumen de alertas: cambia también al reconocer/resolver o al sumar eventos a una alerta ya abierta
                const [[digest]] = await db.query(
                    // SUM(CASE …): portable (en PostgreSQL SUM(condición) falla: la condición es boolean, no número)
                    `SELECT SUM(CASE WHEN status = 'open' THEN 1 ELSE 0 END) AS open,
                            SUM(CASE WHEN status = 'acknowledged' THEN 1 ELSE 0 END) AS acknowledged,
                            SUM(CASE WHEN status <> 'resolved' AND severity = 'critical' THEN 1 ELSE 0 END) AS critical,
                            MAX(GREATEST(last_seen, COALESCE(acknowledged_at, last_seen), COALESCE(resolved_at, last_seen))) AS changed
                     FROM security_alerts`
                );
                if (client.closed) return;

                for (const e of events) {
                    client.cursor.eventId = Number(e.id);
                    send('security-event', {
                        id: Number(e.id), createdAt: toIso(e.created_at), type: e.event_type, rule: e.rule, severity: e.severity,
                        action: e.action_taken, ip: e.ip_address, userId: e.user_id, method: e.method, path: e.path, status: e.status_code
                    }, true);
                }
                for (const a of alerts) {
                    client.cursor.alertId = Number(a.id);
                    send('alert', {
                        id: Number(a.id), rule: a.rule, subject: a.subject, severity: a.severity, title: a.title, status: a.status,
                        eventCount: Number(a.event_count), firstSeen: toIso(a.first_seen), lastSeen: toIso(a.last_seen)
                    }, true);
                }
                const summary = { open: Number(digest.open || 0), acknowledged: Number(digest.acknowledged || 0), critical: Number(digest.critical || 0), changedAt: toIso(digest.changed) };
                const fingerprint = JSON.stringify(summary);
                if (fingerprint !== client.digest) {
                    client.digest = fingerprint;
                    send('alerts-summary', summary);
                }
            } catch (error) {
                console.error('❌ Stream en vivo:', error.code || error.message);
                close('stream-error', { code: 'STREAM_BACKEND', message: 'Sin acceso a los datos: se reintentará' });
            } finally {
                client.busy = false;
            }
        };

        const recheck = async () => {
            try {
                if (!(await this.stillAllowed(client))) close('reauth', { code: 'SESSION_INVALID' });
            } catch {
                close('stream-error', { code: 'STREAM_BACKEND', message: 'No se pudo comprobar la sesión: se reintentará' });
            }
        };

        client.timers.push(setInterval(poll, cfg.pollMs));
        client.timers.push(setInterval(() => write(`: ping ${Date.now()}\n\n`), cfg.heartbeatMs));
        client.timers.push(setInterval(recheck, cfg.recheckMs));
        // Al caducar el JWT: cerrar para que el BFF renueve (el navegador reconecta con Last-Event-ID y no se pierde nada)
        if (Number.isFinite(exp)) client.timers.push(setTimeout(() => close('reauth', { code: 'TOKEN_EXPIRED' }), Math.max(1000, exp - Date.now())));
        client.timers.forEach(t => t.unref?.());
        poll();
    }

    // Cierre ordenado del servidor: avisa y cierra todas (si no, server.close() esperaría al plazo máximo)
    closeAll() {
        for (const client of [...this.clients]) client.close?.('bye', { code: 'SERVER_SHUTDOWN' });
    }
}

module.exports = new LiveStream();
module.exports.parseCursor = parseCursor;
