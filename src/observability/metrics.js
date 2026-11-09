const client = require('prom-client');

// Métricas Prometheus (GET /api/metrics, SOLO admin; ver api/routes/metrics.routes.js).
//
// Cardinalidad acotada a propósito: las etiquetas son siempre valores de un conjunto pequeño y fijo por el código
// (método, PLANTILLA de ruta, código de estado, tipo/severidad de evento...). Nunca una URL real, un usuario, una IP ni
// un texto que pueda elegir quien ataca: si no, una sola persona podría crear millones de series y tumbar el monitor.
// Tampoco hay datos personales en ninguna métrica.

const registry = new client.Registry();
client.collectDefaultMetrics({ register: registry, prefix: 'secure_server_' });

const counter = (name, help, labelNames = []) => new client.Counter({ name: `secure_server_${name}`, help, labelNames, registers: [registry] });
const histogram = (name, help, labelNames, buckets) => new client.Histogram({ name: `secure_server_${name}`, help, labelNames, buckets, registers: [registry] });
// `aggregator` solo importa en modo cluster (ver renderMetrics): los gauges que salen de la BD valen lo mismo en todos los procesos y se
// agregan con 'max' (con la 'sum' por defecto saldrían multiplicados por el número de procesos); los de cada proceso (pool) se suman.
const gauge = (name, help, labelNames, collect, aggregator = 'max') => new client.Gauge({ name: `secure_server_${name}`, help, labelNames, aggregator, registers: [registry], ...(collect && { async collect() { await collect(this); } }) });

const httpRequests = counter('http_requests_total', 'Peticiones HTTP', ['method', 'route', 'status']);
const httpDuration = histogram('http_request_duration_seconds', 'Duración de las peticiones HTTP', ['method', 'route'], [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30]);
const securityEvents = counter('security_events_total', 'Eventos de seguridad registrados', ['type', 'severity']);
const sessionsCreated = counter('sessions_created_total', 'Sesiones iniciadas', ['method']);
const refreshes = counter('session_refresh_total', 'Renovaciones de sesión', ['result']);
const fileUploads = counter('file_uploads_total', 'Subidas de archivos', ['result']);
const fileRejections = counter('file_rejections_total', 'Subidas rechazadas por motivo', ['code']);
const dbDuration = histogram('db_query_duration_seconds', 'Duración de las consultas SQL', ['operation'], [0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5]);
const dbErrors = counter('db_query_errors_total', 'Consultas SQL con error', ['operation']);
const otelExportFailures = counter('otel_export_failures_total', 'Lotes de trazas que no se pudieron exportar');
const alertsRaised = counter('alerts_raised_total', 'Alertas de seguridad creadas', ['rule', 'severity']);

// Gauges que se calculan al hacer el scrape (consultas baratas con índice)
const dbQuery = async (sql) => (await require('../config/database').query(sql))[0];
gauge('alerts_open', 'Alertas de seguridad sin resolver', ['severity'], async (g) => {
    g.reset();
    for (const row of await dbQuery("SELECT severity, COUNT(*) AS n FROM security_alerts WHERE status <> 'resolved' GROUP BY severity")) g.set({ severity: row.severity }, Number(row.n));
});
gauge('sessions_active', 'Sesiones activas', [], async (g) => {
    const [row] = await dbQuery("SELECT COUNT(*) AS n FROM user_sessions WHERE revoked_at IS NULL AND expires_at > NOW() AND (absolute_expires_at IS NULL OR absolute_expires_at > NOW())");
    g.set(Number(row.n));
});
gauge('blocked_ips_active', 'IPs bloqueadas ahora', [], async (g) => {
    const [row] = await dbQuery('SELECT COUNT(*) AS n FROM blocked_ips WHERE blocked_until > NOW()');
    g.set(Number(row.n));
});
gauge('approvals_pending', 'Solicitudes de aprobación pendientes', [], async (g) => {
    const [row] = await dbQuery("SELECT COUNT(*) AS n FROM admin_approvals WHERE status = 'pending' AND expires_at > NOW()");
    g.set(Number(row.n));
});
gauge('db_pool_connections', 'Conexiones del pool de la base de datos', ['state'], async (g) => {
    const pool = require('../config/database').pool?.pool;
    if (!pool) return;
    g.set({ state: 'total' }, pool._allConnections?.length ?? 0);
    g.set({ state: 'free' }, pool._freeConnections?.length ?? 0);
    g.set({ state: 'queued' }, pool._connectionQueue?.length ?? 0);
}, 'sum');

// Texto de /api/metrics. Con el cluster (src/cluster.js) cada proceso tiene SU registro: se pide al proceso principal que agregue el de
// todos (prom-client AggregatorRegistry) para que el scrape sea el mismo caiga en el proceso que caiga. Sin cluster, el registro local.
let nextRequest = 1;
const pending = new Map();
if (process.env.CLUSTER_METRICS === 'true' && typeof process.send === 'function') {
    // prom-client solo responde a las peticiones del principal si el worker construye un AggregatorRegistry; y hay que indicarle
    // que agregue NUESTRO registro (no el global)
    client.AggregatorRegistry.setRegistries([registry]);
    new client.AggregatorRegistry();
    process.on('message', (message) => {
        if (message?.type !== 'secure-server:metrics:result') return;
        const waiter = pending.get(message.id);
        if (!waiter) return;
        pending.delete(message.id);
        message.error ? waiter.reject(new Error(message.error)) : waiter.resolve(message.text);
    });
}

function renderMetrics() {
    if (!(process.env.CLUSTER_METRICS === 'true' && typeof process.send === 'function')) return registry.metrics();
    return new Promise((resolve, reject) => {
        const id = nextRequest++;
        const timer = setTimeout(() => { pending.delete(id); reject(new Error('el proceso principal no respondió a tiempo')); }, 5000);
        pending.set(id, { resolve: (text) => { clearTimeout(timer); resolve(text); }, reject: (error) => { clearTimeout(timer); reject(error); } });
        process.send({ type: 'secure-server:metrics', id });
    });
}

// Etiqueta de operación SQL: solo valores de una lista cerrada
const OPERATIONS = new Set(['select', 'insert', 'update', 'delete', 'replace', 'alter', 'create', 'drop']);
function sqlOperation(sql) {
    const word = /^\s*(\w+)/.exec(String(sql))?.[1]?.toLowerCase();
    return OPERATIONS.has(word) ? word : 'other';
}

// Middleware: cuenta y mide cada petición con la plantilla de ruta (o 'unmatched' si ninguna ruta la atendió)
function httpMiddleware() {
    const { routeLabel } = require('./tracing');
    return (req, res, next) => {
        const end = httpDuration.startTimer();
        res.on('finish', () => {
            const route = routeLabel(req);
            const method = ['GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'].includes(req.method) ? req.method : 'OTHER';
            httpRequests.inc({ method, route, status: String(res.statusCode) });
            end({ method, route });
        });
        next();
    };
}

module.exports = {
    registry, renderMetrics, httpMiddleware, sqlOperation,
    httpRequests, httpDuration, securityEvents, sessionsCreated, refreshes, fileUploads, fileRejections,
    dbDuration, dbErrors, otelExportFailures, alertsRaised
};
