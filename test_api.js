// Tests de integración de la capa de APIs (cargador de rutas, auth, roles, validación y /api/notes).
// No necesita MySQL ni .env: la base de datos y los servicios pesados se sustituyen por dobles en memoria.
//
//   npm run test:api

const test = require('node:test');
const assert = require('node:assert');
const path = require('path');

// ---------- Dobles de prueba ----------
function stub(relPath, exports) {
    const resolved = require.resolve(path.join(__dirname, relPath));
    require.cache[resolved] = { id: resolved, filename: resolved, loaded: true, exports };
}

const state = { notes: [], nextNoteId: 1, securityLogs: [], blockedIPs: ['203.0.113.9'], counters: new Map(), securityEvents: [] };
const users = { 1: { role: 'user' }, 2: { role: 'admin' } };

const fakeDb = {
    async query(sql, params = []) {
        const q = sql.replace(/\s+/g, ' ').trim();

        if (q.startsWith('SELECT role FROM users')) {
            return [users[params[0]] ? [users[params[0]]] : []];
        }
        if (q.startsWith('INSERT INTO security_logs')) {
            state.securityLogs.push({ event_type: params[0] });
            return [{ insertId: state.securityLogs.length }];
        }
        if (q.startsWith('INSERT INTO user_notes')) {
            const note = {
                id: state.nextNoteId++, user_id: params[0], title_encrypted: params[1],
                content_encrypted: params[2], created_at: new Date(), updated_at: new Date()
            };
            state.notes.push(note);
            return [{ insertId: note.id }];
        }
        if (q.startsWith('SELECT COUNT(*) AS total FROM user_notes')) {
            return [[{ total: state.notes.filter(n => n.user_id === params[0]).length }]];
        }
        if (q.startsWith('SELECT') && q.includes('FROM user_notes WHERE user_id = ?')) {
            return [state.notes.filter(n => n.user_id === params[0]).reverse()];
        }
        if (q.startsWith('SELECT') && q.includes('FROM user_notes WHERE id = ? AND user_id = ?')) {
            return [state.notes.filter(n => n.id === Number(params[0]) && n.user_id === params[1])];
        }
        if (q.startsWith('UPDATE user_notes')) {
            // SQL fijo con COALESCE: null = "conservar el valor actual"
            const [title, content, id, userId] = params;
            const note = state.notes.find(n => n.id === Number(id) && n.user_id === userId);
            if (note) {
                if (title !== null) note.title_encrypted = title;
                if (content !== null) note.content_encrypted = content;
            }
            return [{ affectedRows: note ? 1 : 0 }];
        }
        // Contadores del limitador de peticiones (tabla rate_limit_counters)
        if (q.startsWith('INSERT INTO rate_limit_counters')) {
            const key = params.join('|');
            state.counters.set(key, (state.counters.get(key) || 0) + 1);
            return [{ affectedRows: 1 }];
        }
        if (q.startsWith('SELECT window_start, hits FROM rate_limit_counters')) {
            const [scope, subject, ...windows] = params;
            return [windows.filter(w => state.counters.has(`${scope}|${subject}|${w}`))
                .map(w => ({ window_start: w, hits: state.counters.get(`${scope}|${subject}|${w}`) }))];
        }
        if (q.includes('FROM rate_limit_counters')) {
            return [[{ tracked: state.counters.size, active: state.counters.size }]];
        }
        if (q.startsWith('INSERT INTO security_events')) {
            state.securityEvents.push({ event_type: params[0] });
            return [{ insertId: state.securityEvents.length }];
        }
        if (q.startsWith('DELETE FROM user_notes')) {
            const before = state.notes.length;
            state.notes = state.notes.filter(n => !(n.id === Number(params[0]) && n.user_id === params[1]));
            return [{ affectedRows: before - state.notes.length }];
        }
        if (q.startsWith('SELECT COUNT(*) as total FROM security_logs')) {
            return [[{ total: state.securityLogs.length }]];
        }
        if (q.includes('FROM security_logs')) {
            return [state.securityLogs.map((l, i) => ({ id: i + 1, ...l }))];
        }
        if (q.includes('FROM blocked_ips')) {
            return [state.blockedIPs.map(ip => ({ ip_address: ip }))];
        }
        throw new Error(`Consulta no soportada por el doble de prueba: ${q}`);
    },
    // Varias sentencias sobre "una conexión" (la usa el limitador de peticiones)
    async withConnection(fn) { return fn({ query: (sql, params) => fakeDb.query(sql, params) }); }
};

// Cifrado reversible trivial: lo que importa aquí es que el controlador cifre/descifre
const fakeEncryptor = {
    encrypt: (text) => `enc:${Buffer.from(String(text)).toString('base64')}`,
    decrypt: (text) => Buffer.from(text.slice(4), 'base64').toString(),
    getMetrics: () => ({ totalEncryptions: 0 })
};

const tokens = { 'token-user': 1, 'token-admin': 2 };

stub('src/config/database.js', fakeDb);
stub('src/crypto/tripleEncryptor.js', fakeEncryptor);
stub('src/security/secure-auth.service.js', {
    async validateToken(token) {
        const userId = tokens[token];
        return userId
            ? { valid: true, userId, username: `user${userId}`, sessionId: 1, riskLevel: 'low' }
            : { valid: false, error: 'Sesión inválida o expirada' };
    },
    hashToken: (t) => t
});
stub('src/security/anomaly-detection.service.js', {
    async isIPBlocked() { return false; },
    analyzeRequest() { return []; },
    getStats: () => ({ activeIPs: 0, blockedIPs: state.blockedIPs.length }),
    async unblockIP(ip) { state.blockedIPs = state.blockedIPs.filter(i => i !== ip); return true; }
});
stub('src/middleware/serverCheck.middleware.js', { getStatus: () => ({ status: 'secure' }), async performAsyncCheck() { return { ok: true }; } });
stub('src/services/secure-communications.service.js', { getStats: () => ({ availableChannels: 0 }), async testChannels() { return []; } });
stub('src/tasks/scheduleKeyRotation.js', { getScheduleStatus: () => ({ isEnabled: false }) });
// auth.routes depende del controlador de auth (que usa bcrypt, geoip...): no se prueba aquí
stub('src/api/controllers/auth.controller.js', {
    register: (req, res) => res.json({ success: true }),
    login: (req, res) => res.json({ success: true }),
    logout: (req, res) => res.json({ success: true }),
    getProfile: (req, res) => res.json({ success: true })
});

const express = require('express');
const { registerRoutes } = require('./src/api/routes');
const { createErrorHandler } = require('./src/middleware/error.middleware');
const loggedErrors = [];

let server;
let base;
let mounted;

test.before(async () => {
    const app = express();
    app.use(express.json());
    mounted = registerRoutes(app);
    app.get('/__boom', () => { throw new Error('detalle interno que no debe filtrarse'); });
    app.use((req, res) => res.status(404).json({ success: false, message: 'Ruta no encontrada' }));
    app.use(createErrorHandler({ logError: (error) => loggedErrors.push(error.message) }));
    await new Promise(resolve => { server = app.listen(0, resolve); });
    base = `http://127.0.0.1:${server.address().port}`;
});

test.after(() => server.close());

async function call(method, url, { token, body, raw } = {}) {
    const res = await fetch(base + url, {
        method,
        headers: {
            ...(token && { Authorization: `Bearer ${token}` }),
            ...((body || raw) && { 'Content-Type': 'application/json' })
        },
        body: raw ?? (body ? JSON.stringify(body) : undefined)
    });
    return { status: res.status, json: await res.json() };
}

// ---------- Cargador de rutas ----------
test('el cargador monta cada *.routes.js en /api/<nombre>', () => {
    const byPath = Object.fromEntries(mounted.map(m => [m.path, m.access]));
    assert.deepStrictEqual(byPath, {
        '/api/auth': 'custom',
        '/api/files': 'protected',
        '/api/notes': 'protected',
        '/api/system': 'protected'
    });
});

test('rutas protegidas rechazan peticiones sin token o con token inválido (401)', async () => {
    assert.strictEqual((await call('GET', '/api/notes')).status, 401);
    const bad = await call('GET', '/api/notes', { token: 'basura' });
    assert.strictEqual(bad.status, 401);
    assert.strictEqual(bad.json.code, 'INVALID_TOKEN');
});

// ---------- /api/notes ----------
test('notes: crear, listar, leer, actualizar y borrar', async () => {
    const created = await call('POST', '/api/notes', { token: 'token-user', body: { title: ' Mi nota ', content: 'secreto' } });
    assert.strictEqual(created.status, 201);
    const id = created.json.note.id;
    assert.strictEqual(created.json.note.title, 'Mi nota');

    // En base de datos NO debe quedar texto plano
    assert.ok(state.notes[0].title_encrypted.startsWith('enc:'));
    assert.ok(!JSON.stringify(state.notes).includes('secreto'));

    const list = await call('GET', '/api/notes?limit=5', { token: 'token-user' });
    assert.strictEqual(list.status, 200);
    assert.strictEqual(list.json.notes.length, 1);
    assert.strictEqual(list.json.notes[0].content, 'secreto');
    assert.deepStrictEqual(list.json.pagination, { page: 1, limit: 5, total: 1, pages: 1 });

    const one = await call('GET', `/api/notes/${id}`, { token: 'token-user' });
    assert.strictEqual(one.json.note.title, 'Mi nota');

    const updated = await call('PUT', `/api/notes/${id}`, { token: 'token-user', body: { content: 'nuevo' } });
    assert.strictEqual(updated.json.note.content, 'nuevo');
    assert.strictEqual(updated.json.note.title, 'Mi nota');

    const deleted = await call('DELETE', `/api/notes/${id}`, { token: 'token-user' });
    assert.strictEqual(deleted.status, 200);
    assert.strictEqual((await call('GET', `/api/notes/${id}`, { token: 'token-user' })).status, 404);

    // Cada operación queda auditada
    const events = state.securityLogs.map(l => l.event_type).filter(e => e.startsWith('NOTE_'));
    assert.deepStrictEqual(events, ['NOTE_CREATED', 'NOTE_UPDATED', 'NOTE_DELETED']);
});

test('notes: un usuario no puede ver, editar ni borrar notas de otro', async () => {
    const created = await call('POST', '/api/notes', { token: 'token-user', body: { title: 'privada' } });
    const id = created.json.note.id;

    assert.strictEqual((await call('GET', `/api/notes/${id}`, { token: 'token-admin' })).status, 404);
    assert.strictEqual((await call('PUT', `/api/notes/${id}`, { token: 'token-admin', body: { title: 'x' } })).status, 404);
    assert.strictEqual((await call('DELETE', `/api/notes/${id}`, { token: 'token-admin' })).status, 404);
    assert.strictEqual((await call('GET', '/api/notes', { token: 'token-admin' })).json.notes.length, 0);
});

test('notes: validación de entrada', async () => {
    const noTitle = await call('POST', '/api/notes', { token: 'token-user', body: { content: 'x' } });
    assert.strictEqual(noTitle.status, 400);
    assert.strictEqual(noTitle.json.code, 'VALIDATION_ERROR');

    const longTitle = await call('POST', '/api/notes', { token: 'token-user', body: { title: 'a'.repeat(201) } });
    assert.strictEqual(longTitle.status, 400);

    assert.strictEqual((await call('GET', '/api/notes/abc', { token: 'token-user' })).status, 400);
    assert.strictEqual((await call('GET', '/api/notes?limit=9999', { token: 'token-user' })).status, 400);
    assert.strictEqual((await call('PUT', '/api/notes/1', { token: 'token-user', body: { title: '' } })).status, 400);
});

test('JSON malformado devuelve 400 y NO se registra como error del servidor', async () => {
    loggedErrors.length = 0;
    const originalError = console.error;
    console.error = () => {};
    try {
        for (let i = 0; i < 3; i++) {
            const res = await call('POST', '/api/notes', { token: 'token-user', raw: '{no es json' });
            assert.strictEqual(res.status, 400);
        }
    } finally {
        console.error = originalError;
    }
    assert.deepStrictEqual(loggedErrors, [], 'un error del cliente no debe llenar el log de auditoría');
});

test('un error real (5xx) sí se registra y no filtra detalles al cliente', async () => {
    loggedErrors.length = 0;
    const originalError = console.error;
    console.error = () => {};
    let res;
    try { res = await call('GET', '/__boom'); } finally { console.error = originalError; }
    assert.strictEqual(res.status, 500);
    assert.strictEqual(res.json.message, 'Error interno del servidor');
    assert.ok(!JSON.stringify(res.json).includes('detalle interno'));
    assert.deepStrictEqual(loggedErrors, ['detalle interno que no debe filtrarse']);
});

// ---------- /api/system ----------
test('system: usuarios sin rol admin reciben 403', async () => {
    const res = await call('GET', '/api/system/status', { token: 'token-user' });
    assert.strictEqual(res.status, 403);
    assert.strictEqual(res.json.code, 'FORBIDDEN');
});

test('system: un admin ve el estado y la respuesta incluye server y security', async () => {
    const res = await call('GET', '/api/system/status', { token: 'token-admin' });
    assert.strictEqual(res.status, 200);
    assert.ok(res.json.status.server.nodeVersion);
    assert.ok(res.json.status.security.integrityCheck);
    assert.ok('activeRateLimitWindows' in res.json.status.protection);
});

test('system: rotate-keys ya no se puede lanzar por HTTP (501) y apunta al CLI', async () => {
    const res = await call('POST', '/api/system/rotate-keys', { token: 'token-admin' });
    assert.strictEqual(res.status, 501);
    assert.strictEqual(res.json.code, 'USE_CLI');
    assert.match(res.json.message, /npm run rotate-keys/);
});

test('system: /rotation muestra el estado sin claves ni datos y solo a admins', async () => {
    assert.strictEqual((await call('GET', '/api/system/rotation', { token: 'token-user' })).status, 403);

    const res = await call('GET', '/api/system/rotation', { token: 'token-admin' });
    assert.strictEqual(res.status, 200);
    assert.ok(['stable', 'legacy'].includes(res.json.rotation.keys.mode));
    assert.ok(Array.isArray(res.json.rotation.backups));
    assert.strictEqual(typeof res.json.rotation.guard.maintenance, 'boolean');
    // Solo la huella pública: nunca las claves
    assert.deepStrictEqual(Object.keys(res.json.rotation.keys).sort(), ['epoch', 'fingerprint', 'mode']);
});

test('system: logs paginados, IPs bloqueadas y desbloqueo', async () => {
    const logs = await call('GET', '/api/system/logs?limit=999999', { token: 'token-admin' });
    assert.strictEqual(logs.status, 200);
    assert.strictEqual(logs.json.pagination.limit, 200);

    assert.strictEqual((await call('GET', '/api/system/logs?severity=boom', { token: 'token-admin' })).status, 400);

    const blocked = await call('GET', '/api/system/blocked-ips', { token: 'token-admin' });
    assert.strictEqual(blocked.json.blockedIPs.length, 1);

    assert.strictEqual((await call('DELETE', '/api/system/blocked-ips/no-es-ip', { token: 'token-admin' })).status, 400);
    assert.strictEqual((await call('DELETE', '/api/system/blocked-ips/203.0.113.9', { token: 'token-admin' })).status, 200);
    assert.strictEqual(state.blockedIPs.length, 0);
});
