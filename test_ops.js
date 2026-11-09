// Operación y observabilidad, SOLO admin: métricas Prometheus, trazas (W3C + OTLP), alertas automáticas, panel,
// exportación/borrado de datos personales y revocación de sesiones. MariaDB real y el servidor real.
//
//   npm run test:ops

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const fs = require('fs');
const http = require('http');

const { filesDir } = require('./test_helpers/env');
process.env.IMAGE_SANITIZE = 'off';
const helpers = require('./test_helpers/app');
const { api, registerAndLogin, testIp } = helpers;

let app, db, enabled = false, admin, adminB;
const events = () => require('./src/security/security-events.service');
const alertsService = () => require('./src/security/alerts.service');

test.before(async () => {
    enabled = await helpers.prepareDatabase();
    if (!enabled) return;
    db = require('./src/config/database');
    app = await helpers.startApp();
    admin = await roleUser('admin');
    adminB = await roleUser('admin');
});
test.after(async () => {
    if (app) await app.close();
    if (db?.pool) await db.pool.end();
    fs.rmSync(filesDir, { recursive: true, force: true });
});
const itDb = (name, fn) => test(name, async (t) => { if (!enabled) return t.skip('sin BD'); await fn(t); });
const withEnv = async (vars, fn) => {
    const saved = Object.fromEntries(Object.keys(vars).map(k => [k, process.env[k]]));
    Object.assign(process.env, vars);
    try { return await fn(); } finally {
        for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
    }
};
const wait = (ms) => new Promise(resolve => setTimeout(resolve, ms));

async function roleUser(role) {
    const ip = testIp();
    const user = await registerAndLogin(app.base, { ip });
    if (role !== 'user') await db.query('UPDATE users SET role = ? WHERE id = ?', [role, user.userId]);
    return { ...user, ip, role };
}
const call = (user, method, route, json, headers) => api(app.base, method, route, { token: user.token, ip: user.ip, json, headers });
const metricsText = async (user = admin) => (await call(user, 'GET', '/api/metrics')).text;
// Suma de las series `name{...}` que llevan todas las etiquetas pedidas (objeto clave -> valor); sin etiquetas, la serie plana
const sample = (text, name, labels = {}) => {
    let total = 0;
    for (const line of text.split('\n')) {
        const m = line.match(new RegExp(`^${name}(?:\\{([^}]*)\\})? (\\S+)$`));
        if (!m) continue;
        const present = m[1] || '';
        if (Object.entries(labels).every(([k, v]) => present.includes(`${k}="${v}"`))) total += Number(m[2]);
    }
    return total;
};

// Servidor HTTP mínimo que guarda lo que recibe (colector OTLP o destino de webhooks)
async function receiver(status = 200) {
    const received = [];
    const server = http.createServer((req, res) => {
        const chunks = [];
        req.on('data', c => chunks.push(c));
        req.on('end', () => { received.push({ url: req.url, headers: req.headers, body: Buffer.concat(chunks).toString('utf8') }); res.writeHead(status).end('{}'); });
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    return { received, url: `http://127.0.0.1:${server.address().port}`, close: () => new Promise(resolve => server.close(resolve)) };
}

// ============================================================================ métricas

itDb('/api/metrics: SOLO administradores (sin token 401; usuario, auditor y operator 403)', async () => {
    assert.strictEqual((await api(app.base, 'GET', '/api/metrics', { ip: testIp() })).status, 401);
    for (const role of ['user', 'auditor', 'operator']) {
        assert.strictEqual((await call(await roleUser(role), 'GET', '/api/metrics')).status, 403, role);
    }
    const ok = await call(admin, 'GET', '/api/metrics');
    assert.strictEqual(ok.status, 200);
    assert.match(ok.headers.get('content-type'), /^text\/plain/);
    assert.strictEqual(ok.headers.get('cache-control'), 'no-store');
    assert.match(ok.text, /^# HELP secure_server_http_requests_total/m);
    assert.match(ok.text, /secure_server_process_cpu_user_seconds_total/);
});

itDb('METRICS_TOKEN: un token de servicio opcional vale SOLO para /api/metrics (mín. 32 caracteres, tiempo constante)', async () => {
    const token = crypto.randomBytes(24).toString('hex');
    const scrape = (value) => api(app.base, 'GET', '/api/metrics', { ip: testIp(), headers: { Authorization: `Bearer ${value}` } });

    assert.strictEqual((await scrape(token)).status, 401, 'sin configurar, no existe');
    await withEnv({ METRICS_TOKEN: token }, async () => {
        assert.strictEqual((await scrape(token)).status, 200);
        assert.strictEqual((await scrape(token + 'x')).status, 401);
        assert.strictEqual((await scrape(token.slice(1))).status, 401);
        // el token de métricas NO abre ninguna otra ruta
        for (const route of ['/api/system/status', '/api/notes', '/api/auth/profile', '/api/system/dashboard']) {
            assert.strictEqual((await api(app.base, 'GET', route, { ip: testIp(), headers: { Authorization: `Bearer ${token}` } })).status, 401, route);
        }
    });
    await withEnv({ METRICS_TOKEN: 'corto' }, async () => {
        assert.strictEqual((await scrape('corto')).status, 401, 'un token corto se ignora');
    });
});

itDb('cardinalidad acotada: rutas inexistentes y atacantes NO crean series nuevas, y no hay datos personales', async () => {
    const ip = testIp();
    for (let i = 0; i < 30; i++) await api(app.base, 'GET', `/ruta-inventada-${crypto.randomBytes(6).toString('hex')}`, { ip: testIp() });
    const user = await registerAndLogin(app.base, { ip });
    for (const id of [101, 202, 303]) await call({ ...user, ip }, 'GET', `/api/notes/${id}`);
    await api(app.base, 'POST', '/api/auth/login', { ip, json: { username: user.username, password: 'mal-mal-mal-mal' } });

    const text = await metricsText();
    assert.ok(!text.includes('ruta-inventada'), 'la URL real no llega a las etiquetas');
    assert.ok(!/route="\/api\/notes\/(101|202|303)"/.test(text), 'ni los ids');
    assert.match(text, /route="\/api\/notes\/:id"/);
    assert.match(text, /route="unmatched"/);
    for (const personal of [user.username, ip, 'usuario@example.com', user.token]) assert.ok(!text.includes(personal), 'dato personal en las métricas');
    const routes = new Set([...text.matchAll(/secure_server_http_requests_total\{[^}]*route="([^"]*)"/g)].map(m => m[1]));
    assert.ok(routes.size < 40, `series de ruta: ${routes.size}`);
});

itDb('las métricas de negocio se mueven: eventos, sesiones, renovaciones, subidas, SQL y alertas', async () => {
    const before = await metricsText();
    const ip = testIp();
    const user = await registerAndLogin(app.base, { ip });
    await api(app.base, 'POST', '/api/auth/login', { ip, json: { username: user.username, password: 'mal-mal-mal-mal' } });
    assert.strictEqual((await api(app.base, 'POST', '/api/auth/refresh', { ip, json: { refreshToken: user.refreshToken } })).status, 200);
    const form = new FormData();
    form.append('file', new Blob([Buffer.from('#!/bin/sh\necho hola')]), 'script.png');
    await api(app.base, 'POST', '/api/files', { token: user.token, ip, form });

    const after = await metricsText();
    const delta = (name, labels) => sample(after, name, labels) - sample(before, name, labels);
    assert.ok(delta('secure_server_security_events_total', { type: 'LOGIN_FAILED', severity: 'medium' }) >= 1);
    assert.ok(delta('secure_server_sessions_created_total', { method: 'pwd' }) >= 1);
    assert.strictEqual(delta('secure_server_session_refresh_total', { result: 'ok' }), 1);
    assert.ok(delta('secure_server_file_uploads_total', { result: 'rejected' }) >= 1);
    assert.match(after, /secure_server_file_rejections_total\{code="EXECUTABLE_CONTENT"\}/);
    assert.match(after, /secure_server_db_query_duration_seconds_bucket\{[^}]*operation="select"/);
    assert.match(after, /secure_server_sessions_active \d+/);
    assert.match(after, /secure_server_db_pool_connections\{state="total"\}/);
});

// ============================================================================ trazas

itDb('traceparent: el traceId entrante se conserva (X-Request-Id), uno inválido se descarta y queda en los eventos', async () => {
    const traceId = crypto.randomBytes(16).toString('hex');
    const parentSpan = crypto.randomBytes(8).toString('hex');
    const ip = testIp();

    const res = await api(app.base, 'POST', '/api/auth/login', { ip, json: { username: 'nadie', password: 'mal-mal-mal-mal' }, headers: { traceparent: `00-${traceId}-${parentSpan}-01` } });
    assert.strictEqual(res.headers.get('x-request-id'), traceId);
    assert.match(res.headers.get('traceparent'), new RegExp(`^00-${traceId}-[0-9a-f]{16}-0[01]$`));
    assert.notStrictEqual(res.headers.get('traceparent').split('-')[2], parentSpan, 'el span de esta petición es nuevo');

    // el evento de seguridad lleva el traceId: de un evento sospechoso se llega a toda la petición
    const [rows] = await db.query("SELECT details FROM security_events WHERE event_type = 'LOGIN_FAILED' AND ip_address = ? ORDER BY id DESC LIMIT 1", [ip]);
    assert.strictEqual(JSON.parse(rows[0].details).traceId, traceId);

    const bad = [`00-${'0'.repeat(32)}-${parentSpan}-01`, `00-${traceId.toUpperCase()}-${parentSpan}-01`, `00-${traceId}-${parentSpan}`, 'basura', `ff-${traceId}-${parentSpan}-01`, `00-${traceId}-${'0'.repeat(16)}-01`];
    for (const header of bad) {
        const r = await api(app.base, 'GET', '/health', { ip: testIp(), headers: { traceparent: header } });
        assert.match(r.headers.get('x-request-id'), /^[0-9a-f]{32}$/, header);
        assert.notStrictEqual(r.headers.get('x-request-id'), traceId, header);
    }
    const a = await api(app.base, 'GET', '/health', { ip: testIp() });
    const b = await api(app.base, 'GET', '/health', { ip: testIp() });
    assert.notStrictEqual(a.headers.get('x-request-id'), b.headers.get('x-request-id'));
});

itDb('OTLP: con colector configurado se exportan la petición y sus consultas SQL, sin datos personales', async () => {
    const collector = await receiver();
    try {
        await withEnv({ OTEL_EXPORTER_OTLP_ENDPOINT: collector.url, OTEL_TRACES_SAMPLER_ARG: '1', OTEL_BSP_SCHEDULE_DELAY: '50', OTEL_EXPORTER_OTLP_HEADERS: 'x-api-key=clave-colector' }, async () => {
            const ip = testIp();
            const user = await registerAndLogin(app.base, { ip });
            collector.received.length = 0;

            const traceId = crypto.randomBytes(16).toString('hex');
            const parentSpan = crypto.randomBytes(8).toString('hex');
            const res = await api(app.base, 'GET', '/api/notes?page=1&secreto=NO-DEBE-SALIR', { token: user.token, ip, headers: { traceparent: `00-${traceId}-${parentSpan}-01` } });
            assert.strictEqual(res.status, 200);

            for (let i = 0; i < 40 && collector.received.length === 0; i++) await wait(50);
            assert.ok(collector.received.length >= 1, 'el colector recibió un lote');
            const request = collector.received[0];
            assert.strictEqual(request.url, '/v1/traces');
            assert.strictEqual(request.headers['x-api-key'], 'clave-colector');

            const payload = JSON.parse(request.body);
            const spans = payload.resourceSpans[0].scopeSpans[0].spans.filter(s => s.traceId === traceId);
            assert.strictEqual(payload.resourceSpans[0].resource.attributes[0].value.stringValue, 'secure-server');
            const root = spans.find(s => s.name === 'GET /api/notes');
            assert.ok(root, `span raíz; nombres: ${spans.map(s => s.name)}`);
            assert.strictEqual(root.parentSpanId, parentSpan, 'continúa la traza entrante');
            assert.strictEqual(root.kind, 2);
            assert.ok(BigInt(root.endTimeUnixNano) >= BigInt(root.startTimeUnixNano));
            const status = root.attributes.find(a => a.key === 'http.response.status_code');
            assert.strictEqual(status.value.intValue, '200');
            const sql = spans.filter(s => s.name === 'db.query');
            assert.ok(sql.length >= 2, 'consultas SQL como spans hijos');
            assert.ok(sql.every(s => s.parentSpanId === root.spanId && s.kind === 3));
            assert.ok(sql.every(s => ['select', 'insert', 'update'].includes(s.attributes.find(a => a.key === 'db.operation').value.stringValue)));

            // Nada de datos personales ni de la URL real en el lote
            for (const secret of ['NO-DEBE-SALIR', user.token, user.username, ip, 'SELECT ', 'FROM user']) {
                assert.ok(!request.body.includes(secret), `el lote contiene "${secret}"`);
            }
        });
    } finally { await collector.close(); }
});

itDb('muestreo: con razón 0 no se exporta nada, salvo que la traza entrante ya esté muestreada; sin colector no hay coste', async () => {
    const collector = await receiver();
    try {
        await withEnv({ OTEL_EXPORTER_OTLP_ENDPOINT: collector.url, OTEL_TRACES_SAMPLER_ARG: '0', OTEL_BSP_SCHEDULE_DELAY: '50' }, async () => {
            const ip = testIp();
            for (let i = 0; i < 5; i++) await api(app.base, 'GET', '/health', { ip });
            await wait(300);
            assert.strictEqual(collector.received.length, 0, 'ratio 0: nada');

            const traceId = crypto.randomBytes(16).toString('hex');
            await api(app.base, 'GET', '/health', { ip, headers: { traceparent: `00-${traceId}-${crypto.randomBytes(8).toString('hex')}-01` } });
            for (let i = 0; i < 40 && collector.received.length === 0; i++) await wait(50);
            assert.ok(collector.received.length >= 1, 'una traza ya muestreada se respeta');
        });
    } finally { await collector.close(); }

    // sin colector configurado: ningún span se guarda, pero el traceId sigue
    const res = await api(app.base, 'GET', '/health', { ip: testIp(), headers: { traceparent: `00-${crypto.randomBytes(16).toString('hex')}-${crypto.randomBytes(8).toString('hex')}-01` } });
    assert.match(res.headers.get('traceparent'), /-00$/, 'sin exportador no se marca como muestreada');
});

itDb('colector caído o que responde 500: la petición no se ve afectada y se cuenta el fallo', async () => {
    const before = sample(await metricsText(), 'secure_server_otel_export_failures_total');
    await withEnv({ OTEL_EXPORTER_OTLP_ENDPOINT: 'http://127.0.0.1:9', OTEL_TRACES_SAMPLER_ARG: '1', OTEL_BSP_SCHEDULE_DELAY: '30' }, async () => {
        const res = await api(app.base, 'GET', '/health', { ip: testIp() });
        assert.strictEqual(res.status, 200);
        await wait(400);
    });
    const failing = await receiver(500);
    try {
        await withEnv({ OTEL_EXPORTER_OTLP_ENDPOINT: failing.url, OTEL_TRACES_SAMPLER_ARG: '1', OTEL_BSP_SCHEDULE_DELAY: '30' }, async () => {
            assert.strictEqual((await api(app.base, 'GET', '/health', { ip: testIp() })).status, 200);
            await wait(400);
        });
    } finally { await failing.close(); }
    assert.ok(sample(await metricsText(), 'secure_server_otel_export_failures_total') >= before + 2);
});

// ============================================================================ alertas

const fakeFailures = async (n, ips, extra = {}) => {
    for (let i = 0; i < n; i++) {
        await db.query("INSERT INTO security_events (event_type, rule, severity, ip_address, username_hash, user_id) VALUES (?, ?, 'medium', ?, ?, ?)",
            [extra.type || 'LOGIN_FAILED', extra.rule ?? 'BAD_CREDENTIALS', `198.51.100.${(i % ips) + 1}`, extra.hash ?? null, extra.userId ?? null]);
    }
};
const cleanEvents = () => db.query('DELETE FROM security_events');
const cleanAlerts = () => db.query('DELETE FROM security_alerts');
const activeAlerts = async (rule) => (await db.query("SELECT * FROM security_alerts WHERE rule = ? AND status <> 'resolved'", [rule]))[0];

itDb('alerta de fallos de login masivos desde muchas IP: se crea, no se duplica y respeta la ventana y los umbrales', async () => {
    await cleanEvents(); await cleanAlerts();
    await fakeFailures(40, 20);                                   // 40 fallos < 50: no salta
    assert.strictEqual((await alertsService().evaluate()).created, 0);
    await fakeFailures(15, 3);                                    // 55 fallos pero solo 20 IP: sí (>= 10 IP)
    const first = await alertsService().evaluate();
    assert.strictEqual(first.created, 1, JSON.stringify(first));
    const [alert] = await activeAlerts('LOGIN_FAILURES_DISTRIBUTED');
    assert.deepStrictEqual([alert.severity, alert.status, alert.event_count], ['high', 'open', 55]);

    await fakeFailures(5, 5);
    const second = await alertsService().evaluate();
    assert.deepStrictEqual([second.created, second.updated], [0, 1], 'se actualiza, no se duplica');
    const [again] = await activeAlerts('LOGIN_FAILURES_DISTRIBUTED');
    assert.strictEqual(again.id, alert.id);
    assert.strictEqual(again.event_count, 60);

    // fuera de la ventana no cuenta
    await cleanEvents(); await cleanAlerts();
    await fakeFailures(60, 20);
    await db.query("UPDATE security_events SET created_at = DATE_SUB(NOW(), INTERVAL 2 HOUR)");
    assert.strictEqual((await alertsService().evaluate()).created, 0, 'eventos de hace 2 h no cuentan');
});

itDb('alertas por cuenta atacada, códigos MFA, evento crítico, antivirus caído y actividad administrativa sensible', async () => {
    await cleanEvents(); await cleanAlerts();
    const hash = 'a'.repeat(64);
    await fakeFailures(16, 4, { type: 'LOGIN_FAILED', hash });
    await fakeFailures(11, 2, { type: 'LOGIN_FAILED', rule: 'BAD_MFA_CODE', userId: 7 });
    await db.query("INSERT INTO security_events (event_type, rule, severity, ip_address) VALUES ('REFRESH_TOKEN_REUSE', 'REFRESH_REUSE', 'critical', '203.0.113.5')");
    await db.query("INSERT INTO security_events (event_type, rule, severity) VALUES ('FILE_REJECTED', 'SCANNER_UNAVAILABLE', 'low')");
    await db.query("INSERT INTO security_events (event_type, severity) VALUES ('MFA_RESET_BY_ADMIN', 'high')");
    await db.query("INSERT INTO security_events (event_type, severity) VALUES ('SERVER_INTEGRITY_BREACH', 'high')");

    const result = await alertsService().evaluate();
    assert.deepStrictEqual(result.errors, []);
    const rules = (await db.query("SELECT rule, severity, subject FROM security_alerts ORDER BY rule"))[0];
    const byRule = Object.fromEntries(rules.map(r => [r.rule, r]));
    assert.strictEqual(byRule.ACCOUNT_UNDER_ATTACK.severity, 'medium');
    assert.strictEqual(byRule.ACCOUNT_UNDER_ATTACK.subject, `account:${hash.slice(0, 16)}`);
    assert.deepStrictEqual([byRule.MFA_CODE_GUESSING.severity, byRule.MFA_CODE_GUESSING.subject], ['high', 'user:7']);
    assert.strictEqual(byRule.EVENT_CRITICAL.severity, 'critical');
    assert.strictEqual(byRule.ANTIVIRUS_UNAVAILABLE.severity, 'high');
    assert.strictEqual(byRule.SENSITIVE_ADMIN_ACTIVITY.subject, 'MFA_RESET_BY_ADMIN');
    assert.strictEqual(byRule.SERVER_INTEGRITY.severity, 'critical');
    assert.ok(!byRule.LOGIN_FAILURES_DISTRIBUTED, 'los umbrales de otras reglas no se cruzaron');
});

itDb('gestión por API (solo admin): listar, reconocer, resolver, estados inválidos y re-alerta si la condición persiste', async () => {
    await cleanEvents(); await cleanAlerts();
    await db.query("INSERT INTO security_events (event_type, rule, severity, ip_address) VALUES ('MALWARE_X', 'MALWARE_Eicar', 'critical', '203.0.113.9')");
    assert.strictEqual((await call(admin, 'POST', '/api/system/alerts/evaluate')).body.result.created, 1);

    for (const role of ['user', 'auditor', 'operator']) {
        const who = await roleUser(role);
        for (const [method, route] of [['GET', '/api/system/alerts'], ['POST', '/api/system/alerts/evaluate'], ['POST', '/api/system/alerts/1/ack'], ['POST', '/api/system/alerts/1/resolve'], ['GET', '/api/system/dashboard']]) {
            assert.strictEqual((await call(who, method, route)).status, 403, `${role} ${method} ${route}`);
        }
    }

    const open = await call(admin, 'GET', '/api/system/alerts?status=open&severity=critical');
    assert.strictEqual(open.status, 200);
    assert.strictEqual(open.body.alerts.length, 1);
    const id = open.body.alerts[0].id;
    assert.strictEqual((await call(admin, 'GET', '/api/system/alerts?status=raro')).status, 400);

    assert.strictEqual((await call(admin, 'POST', `/api/system/alerts/${id}/ack`)).status, 200);
    assert.strictEqual((await call(admin, 'POST', `/api/system/alerts/${id}/ack`)).status, 409, 'ya reconocida');
    assert.strictEqual((await call(admin, 'POST', '/api/system/alerts/99999999/ack')).status, 404);
    assert.strictEqual((await call(admin, 'POST', '/api/system/alerts/abc/ack')).status, 400);
    const [[ack]] = await db.query('SELECT acknowledged_by, status FROM security_alerts WHERE id = ?', [id]);
    assert.deepStrictEqual([ack.status, ack.acknowledged_by], ['acknowledged', admin.userId]);

    assert.strictEqual((await call(admin, 'POST', `/api/system/alerts/${id}/resolve`)).status, 200);
    assert.strictEqual((await call(admin, 'POST', `/api/system/alerts/${id}/resolve`)).status, 409);

    // la condición sigue ahí: al resolverla se levanta una alerta NUEVA (la anterior queda en el historial)
    assert.strictEqual((await call(admin, 'POST', '/api/system/alerts/evaluate')).body.result.created, 1);
    const all = (await call(admin, 'GET', '/api/system/alerts')).body.alerts;
    assert.deepStrictEqual(all.map(a => a.status).sort(), ['open', 'resolved']);
});

itDb('solo se auto-resuelven las alertas RECONOCIDAS sin recurrencia; las abiertas nadie las ha visto y se quedan', async () => {
    await cleanEvents(); await cleanAlerts();
    for (const [subject, status] of [['a', 'open'], ['b', 'acknowledged']]) {
        await db.query("INSERT INTO security_alerts (rule, subject, dedupe_key, severity, title, status, last_seen) VALUES ('TEST', ?, ?, 'high', 't', ?, DATE_SUB(NOW(), INTERVAL 5 HOUR))", [subject, `TEST|${subject}`, status]);
    }
    const result = await alertsService().evaluate();
    assert.strictEqual(result.autoResolved, 1);
    const statuses = Object.fromEntries((await db.query('SELECT subject, status FROM security_alerts'))[0].map(r => [r.subject, r.status]));
    assert.deepStrictEqual(statuses, { a: 'open', b: 'resolved' });
});

itDb('una sola alerta ACTIVA por clave (índice único), también con evaluaciones simultáneas; las resueltas no estorban', async () => {
    await cleanEvents(); await cleanAlerts();
    const insert = () => db.query("INSERT INTO security_alerts (rule, subject, dedupe_key, severity, title) VALUES ('X', 'g', 'X|g', 'low', 't')");
    await insert();
    await assert.rejects(insert, (e) => e.code === 'ER_DUP_ENTRY');
    await db.query("UPDATE security_alerts SET status = 'resolved'");
    await insert();                                               // la anterior está resuelta: ya cabe otra activa
    await insert().then(() => assert.fail('debía fallar')).catch(e => assert.strictEqual(e.code, 'ER_DUP_ENTRY'));

    await cleanAlerts();
    await db.query("INSERT INTO security_events (event_type, rule, severity) VALUES ('REFRESH_TOKEN_REUSE', 'R', 'critical')");
    const results = await Promise.all([alertsService().evaluate(), alertsService().evaluate(), alertsService().evaluate()]);
    assert.strictEqual((await activeAlerts('EVENT_CRITICAL')).length, 1, JSON.stringify(results));
});

itDb('webhook: firma HMAC, respeta la severidad mínima, un destino caído no impide la alerta y no sigue redirecciones', async () => {
    await cleanEvents(); await cleanAlerts();
    const hook = await receiver();
    try {
        await withEnv({ ALERT_WEBHOOK_URL: `${hook.url}/aviso`, ALERT_WEBHOOK_SECRET: 'secreto-del-webhook', ALERT_NOTIFY_MIN_SEVERITY: 'high' }, async () => {
            await db.query("INSERT INTO security_events (event_type, rule, severity) VALUES ('REFRESH_TOKEN_REUSE', 'R', 'critical')");   // critical: avisa
            await db.query("INSERT INTO security_events (event_type, severity) VALUES ('PRIVACY_EXPORT', 'medium')");                    // medium: no avisa
            await alertsService().evaluate();

            assert.strictEqual(hook.received.length, 1, 'solo la crítica sale por el webhook');
            const [req] = hook.received;
            assert.strictEqual(req.url, '/aviso');
            const expected = `sha256=${crypto.createHmac('sha256', 'secreto-del-webhook').update(req.body).digest('hex')}`;
            assert.strictEqual(req.headers['x-signature-256'], expected);
            const body = JSON.parse(req.body);
            assert.match(body.text, /^\[CRITICAL\] /);
            assert.strictEqual(body.alert.rule, 'EVENT_CRITICAL');
            assert.ok(!req.body.includes('203.0.113'), 'sin IPs ni datos de usuarios en el aviso');
            assert.ok((await activeAlerts('EVENT_CRITICAL'))[0].notified_at);
        });
    } finally { await hook.close(); }

    await cleanAlerts();
    const failing = await receiver(500);
    try {
        await withEnv({ ALERT_WEBHOOK_URL: failing.url }, async () => {
            await alertsService().evaluate();
            const [alert] = await activeAlerts('EVENT_CRITICAL');
            assert.ok(alert, 'la alerta existe aunque el aviso fallara');
            assert.strictEqual(alert.notified_at, null);
            assert.match(alert.notify_error, /500/);
        });
    } finally { await failing.close(); }

    // en producción el webhook exige https
    const result = await withEnv({ NODE_ENV: 'production', ALERT_WEBHOOK_URL: 'http://127.0.0.1:1/x' }, () => alertsService().notify({ id: 1, rule: 'R', subject: 's', severity: 'critical', title: 't', count: 1, details: {} }));
    assert.match(result.error, /https/);
    const redirecting = http.createServer((req, res) => res.writeHead(302, { Location: 'http://127.0.0.1:1/otro' }).end());
    await new Promise(resolve => redirecting.listen(0, '127.0.0.1', resolve));
    try {
        const r = await withEnv({ ALERT_WEBHOOK_URL: `http://127.0.0.1:${redirecting.address().port}/` }, () => alertsService().notify({ id: 1, rule: 'R', subject: 's', severity: 'critical', title: 't', count: 1, details: {} }));
        assert.ok(r.error, 'una redirección se trata como error');
    } finally { await new Promise(resolve => redirecting.close(resolve)); }
});

itDb('panel: solo admin, con alertas, eventos, sesiones, archivos y estado del sistema, sin secretos', async () => {
    await cleanAlerts();
    await db.query("INSERT INTO security_events (event_type, rule, severity) VALUES ('MALWARE_X', 'M', 'critical')");
    await alertsService().evaluate();
    const res = await call(admin, 'GET', '/api/system/dashboard?hours=24');
    assert.strictEqual(res.status, 200, res.text);
    const d = res.body.dashboard;
    assert.strictEqual(res.headers.get('cache-control'), 'no-store');
    assert.strictEqual(d.windowHours, 24);
    assert.ok(d.alerts.open.critical >= 1 && d.alerts.latest.length >= 1);
    assert.ok(d.events.total >= 1 && Array.isArray(d.events.timeline));
    assert.ok(d.auth.activeSessions >= 2);
    assert.strictEqual(d.system.database, 'ok');
    assert.strictEqual(typeof d.system.config.mfaRequiredForPrivilegedRoles, 'boolean');
    assert.strictEqual((await call(admin, 'GET', '/api/system/dashboard?hours=0')).status, 400);
    assert.ok(!JSON.stringify(res.body).match(/password|secret|seed|token/i) || !/"(?:password|secret|token)"/i.test(JSON.stringify(res.body)), 'sin secretos');
});

// ============================================================================ datos personales

async function userWithData() {
    const ip = testIp();
    const user = await registerAndLogin(app.base, { ip });
    const note = await api(app.base, 'POST', '/api/notes', { token: user.token, ip, json: { title: 'Mi receta secreta', content: 'La clave es la mantequilla' } });
    const form = new FormData();
    form.append('file', new Blob([Buffer.from('hola mundo, esto es un texto')]), 'apuntes.txt');
    const file = await api(app.base, 'POST', '/api/files', { token: user.token, ip, form });
    assert.strictEqual(note.status, 201); assert.strictEqual(file.status, 201, file.text);
    return { ...user, ip, fileId: file.body.file.id };
}
const REASON = 'Solicitud de supresión de datos del titular (RGPD art. 17)';

itDb('exportar datos de un usuario (solo admin): descifrado y completo, sin hashes ni secretos, y queda auditado', async () => {
    const victim = await userWithData();
    for (const role of ['user', 'auditor', 'operator']) {
        assert.strictEqual((await call(await roleUser(role), 'GET', `/api/system/users/${victim.userId}/export`)).status, 403, role);
    }
    const res = await call(admin, 'GET', `/api/system/users/${victim.userId}/export`);
    assert.strictEqual(res.status, 200, res.text);
    assert.strictEqual(res.headers.get('cache-control'), 'no-store');
    assert.match(res.headers.get('content-disposition'), /^attachment; filename="user-\d+-export\.json"$/);

    const data = res.body.export;
    assert.strictEqual(data.user.username, victim.username);
    assert.strictEqual(data.user.email, 'usuario@example.com');
    assert.deepStrictEqual(data.notes.map(n => [n.title, n.content]), [['Mi receta secreta', 'La clave es la mantequilla']]);
    assert.strictEqual(data.files[0].name, 'apuntes.txt');
    assert.ok(data.sessions.length >= 1 && data.securityEvents !== undefined);

    const raw = JSON.stringify(res.body);
    const [[row]] = await db.query('SELECT password_hash FROM users WHERE id = ?', [victim.userId]);
    for (const secret of [row.password_hash, 'mfa_secret', 'key_encrypted', 'jwt_token_hash', 'refresh_hash', victim.refreshToken, victim.token]) assert.ok(!raw.includes(secret), `el export contiene ${secret.slice(0, 20)}`);

    assert.strictEqual((await call(admin, 'GET', '/api/system/users/99999999/export')).status, 404);
    assert.strictEqual((await call(admin, 'GET', '/api/system/users/abc/export')).status, 400);
    const [audit] = await db.query("SELECT COUNT(*) AS n FROM security_events WHERE event_type = 'PRIVACY_EXPORT' AND user_id = ?", [victim.userId]);
    assert.strictEqual(Number(audit[0].n), 1);
});

itDb('borrar los datos de un usuario: confirmación de nombre, aprobación de OTRO admin, todo desaparece y los eventos quedan anonimizados', async () => {
    const victim = await userWithData();
    await api(app.base, 'POST', '/api/auth/login', { ip: victim.ip, json: { username: victim.username, password: 'mal-mal-mal-mal' } });
    const filePath = (await db.query('SELECT storage_name FROM user_files WHERE user_id = ?', [victim.userId]))[0][0].storage_name;
    const onDisk = () => { let found = false; (function walk(d) { if (!fs.existsSync(d)) return; for (const e of fs.readdirSync(d, { withFileTypes: true })) e.isDirectory() ? walk(`${d}/${e.name}`) : (found ||= e.name.startsWith(filePath)); })(`${filesDir}/files`); return found; };
    assert.ok(onDisk());

    const erase = (body, who = admin) => call(who, 'POST', `/api/system/users/${victim.userId}/erase`, body);
    assert.strictEqual((await erase({ reason: REASON, confirmUsername: 'otro-usuario' })).status, 400, 'confirmación equivocada');
    assert.strictEqual((await erase({ reason: 'corto', confirmUsername: victim.username })).status, 400);
    assert.strictEqual((await erase({ reason: REASON, confirmUsername: victim.username }, await roleUser('operator'))).status, 403);

    const requested = await erase({ reason: REASON, confirmUsername: victim.username });
    assert.strictEqual(requested.status, 202, requested.text);
    assert.ok(await db.query('SELECT 1 FROM users WHERE id = ?', [victim.userId]).then(r => r[0].length === 1), 'todavía existe');

    assert.strictEqual((await call(admin, 'POST', `/api/system/approvals/${requested.body.approvalId}/approve`)).status, 403, 'no se auto-aprueba');
    const done = await call(adminB, 'POST', `/api/system/approvals/${requested.body.approvalId}/approve`);
    assert.strictEqual(done.status, 200, done.text);
    assert.deepStrictEqual([done.body.result.erased, done.body.result.notes, done.body.result.files, done.body.result.filesRemovedFromDisk, done.body.result.filesLeftOnDisk], [true, 1, 1, 1, 0]);

    for (const table of ['users', 'user_notes', 'user_files', 'user_sessions']) {
        const column = table === 'users' ? 'id' : 'user_id';
        assert.strictEqual((await db.query(`SELECT 1 FROM ${table === 'users' ? 'users' : table} WHERE ${column} = ?`, [victim.userId]))[0].length, 0, table);
    }
    assert.ok(!onDisk(), 'los bytes cifrados también se borraron del disco');
    assert.strictEqual((await api(app.base, 'GET', '/api/notes', { token: victim.token, ip: victim.ip })).status, 401);
    assert.strictEqual((await api(app.base, 'POST', '/api/auth/login', { ip: victim.ip, json: { username: victim.username, password: victim.password } })).status, 401);

    // los eventos se conservan para investigar, pero sin vínculo con la persona
    const [left] = await db.query('SELECT COUNT(*) AS n FROM security_events WHERE user_id = ?', [victim.userId]);
    assert.strictEqual(Number(left[0].n), 0);
    const [anon] = await db.query("SELECT COUNT(*) AS n FROM security_events WHERE event_type = 'USER_ERASED'");
    assert.ok(Number(anon[0].n) >= 1);
});

itDb('no se borra una cuenta con privilegios (hay que quitarle el rol antes)', async () => {
    const target = await roleUser('operator');
    const res = await call(admin, 'POST', `/api/system/users/${target.userId}/erase`, { reason: REASON, confirmUsername: target.username });
    assert.strictEqual(res.status, 409);
    assert.strictEqual(res.body.code, 'ROLE_PROTECTED');
    assert.strictEqual((await call(admin, 'POST', '/api/system/users/99999999/erase', { reason: REASON, confirmUsername: 'x' })).status, 404);
});

itDb('ADMIN_APPROVALS_REQUIRED=1: el borrado se ejecuta al momento y queda registrado', async () => {
    await withEnv({ ADMIN_APPROVALS_REQUIRED: '1' }, async () => {
        const victim = await userWithData();
        const res = await call(admin, 'POST', `/api/system/users/${victim.userId}/erase`, { reason: REASON, confirmUsername: victim.username });
        assert.strictEqual(res.status, 200, res.text);
        assert.strictEqual(res.body.result.erased, true);
        assert.strictEqual((await db.query('SELECT 1 FROM users WHERE id = ?', [victim.userId]))[0].length, 0);
    });
});

// ============================================================================ revocar sesiones (incidentes)

itDb('revocar las sesiones de un usuario (admin): sus tokens y refresh dejan de valer al instante', async () => {
    const victim = await roleUser('user');
    const second = (await api(app.base, 'POST', '/api/auth/login', { ip: victim.ip, json: { username: victim.username, password: helpers.PASSWORD } })).body;
    for (const role of ['user', 'auditor', 'operator']) {
        assert.strictEqual((await call(await roleUser(role), 'POST', `/api/system/users/${victim.userId}/revoke-sessions`, { reason: REASON })).status, 403, role);
    }
    assert.strictEqual((await call(admin, 'POST', `/api/system/users/${victim.userId}/revoke-sessions`, {})).status, 400, 'motivo obligatorio');
    const res = await call(admin, 'POST', `/api/system/users/${victim.userId}/revoke-sessions`, { reason: REASON });
    assert.deepStrictEqual([res.status, res.body.closed], [200, 2]);
    for (const tokens of [victim, second]) {
        assert.strictEqual((await api(app.base, 'GET', '/api/notes', { token: tokens.token, ip: victim.ip })).status, 401);
        assert.strictEqual((await api(app.base, 'POST', '/api/auth/refresh', { ip: victim.ip, json: { refreshToken: tokens.refreshToken } })).status, 401);
    }
    assert.strictEqual((await call(admin, 'GET', '/api/notes')).status, 200, 'las del admin no se tocan');
});

itDb('interruptor de emergencia: cerrar TODAS las sesiones exige la frase de confirmación y deja un evento crítico', async () => {
    const bystander = await roleUser('user');
    const operator = await roleUser('operator');
    assert.strictEqual((await call(operator, 'POST', '/api/system/sessions/revoke-all', { reason: REASON, confirm: 'REVOKE-ALL-SESSIONS' })).status, 403);
    assert.strictEqual((await call(admin, 'POST', '/api/system/sessions/revoke-all', { reason: REASON })).status, 400);
    assert.strictEqual((await call(admin, 'POST', '/api/system/sessions/revoke-all', { reason: REASON, confirm: 'si' })).status, 400);
    assert.strictEqual((await call(bystander, 'GET', '/api/notes')).status, 200, 'sin la frase no se tocó nada');

    const res = await call(admin, 'POST', '/api/system/sessions/revoke-all', { reason: REASON, confirm: 'REVOKE-ALL-SESSIONS' });
    assert.strictEqual(res.status, 200, res.text);
    assert.ok(res.body.closed >= 3);
    assert.strictEqual((await call(bystander, 'GET', '/api/notes')).status, 401);
    assert.strictEqual((await call(admin, 'GET', '/api/notes')).status, 401, 'incluidas las del propio admin');
    const [[event]] = await db.query("SELECT severity FROM security_events WHERE event_type = 'SESSIONS_REVOKED_ALL' ORDER BY id DESC LIMIT 1");
    assert.strictEqual(event.severity, 'critical');
});
