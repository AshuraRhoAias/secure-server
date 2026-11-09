// Pruebas de sesiones: JWT de acceso corto + refresh con rotación + cerrar sesiones. MariaDB real.
//
//   npm run test:sessions

const test = require('node:test');
const assert = require('node:assert');
const jwt = require('jsonwebtoken');

require('./test_helpers/env');
const helpers = require('./test_helpers/app');
const { api, registerAndLogin, testIp, PASSWORD } = helpers;

let app, db, enabled = false;
const wait = (ms) => new Promise(resolve => setTimeout(resolve, ms));

test.before(async () => {
    enabled = await helpers.prepareDatabase();
    if (!enabled) return;
    db = require('./src/config/database');
    app = await helpers.startApp();
});
test.after(async () => {
    if (!enabled) return;
    await app.close();
    await db.pool.end();
});

const login = (username, ip) => api(app.base, 'POST', '/api/auth/login', { ip, json: { username, password: PASSWORD } });
const refresh = (refreshToken, ip) => api(app.base, 'POST', '/api/auth/refresh', { ip, json: { refreshToken } });
const me = (token, ip) => api(app.base, 'GET', '/api/notes', { token, ip });
const sessionRow = async (userId) => (await db.query('SELECT * FROM user_sessions WHERE user_id = ? ORDER BY id DESC LIMIT 1', [userId]))[0][0];

test('login: JWT de acceso de 15 min y refresh opaco; en la BD solo el hash del refresh', async (t) => {
    if (!enabled) return t.skip('sin BD');
    const ip = testIp();
    const user = await registerAndLogin(app.base, { ip });

    const decoded = jwt.decode(user.token);
    assert.strictEqual(decoded.exp - decoded.iat, 15 * 60);
    assert.strictEqual(decoded.v, 2);
    assert.match(user.refreshToken, /^rt_[A-Za-z0-9_-]{43}$/);

    const row = await sessionRow(user.userId);
    assert.notStrictEqual(row.refresh_hash, user.refreshToken, 'el refresh no se guarda en claro');
    assert.strictEqual(row.refresh_hash.length, 64);
    assert.ok(!JSON.stringify(row).includes(user.refreshToken));
    assert.ok(new Date(row.absolute_expires_at) > new Date(row.expires_at) || +new Date(row.absolute_expires_at) === +new Date(row.expires_at));

    const res = await login(user.username, ip);
    assert.ok(res.body.expiresIn === 900 && res.body.refreshExpiresAt && res.body.sessionExpiresAt);
    assert.strictEqual((await me(user.token, ip)).status, 200);
});

test('refresh: da un token nuevo y rota el refresh; el cliente no tiene que volver a iniciar sesión', async (t) => {
    if (!enabled) return t.skip('sin BD');
    const ip = testIp();
    const user = await registerAndLogin(app.base, { ip });

    const r1 = await refresh(user.refreshToken, ip);
    assert.strictEqual(r1.status, 200, r1.text);
    assert.notStrictEqual(r1.body.refreshToken, user.refreshToken, 'el refresh rota');
    assert.strictEqual((await me(r1.body.token, ip)).status, 200, 'el token nuevo vale');
    assert.strictEqual(jwt.decode(r1.body.token).sessionId, jwt.decode(user.token).sessionId, 'misma sesión');

    // El token anterior sigue vivo hasta que caduque (15 min), pero la sesión es la misma
    assert.strictEqual((await me(user.token, ip)).status, 200);

    const r2 = await refresh(r1.body.refreshToken, ip);
    assert.strictEqual(r2.status, 200);
    assert.strictEqual((await api(app.base, 'GET', '/api/auth/profile', { token: r2.body.token, ip })).status, 200);
});

test('el JWT de acceso caduca solo y se recupera con el refresh', async (t) => {
    if (!enabled) return t.skip('sin BD');
    process.env.ACCESS_TOKEN_MINUTES = '0.02'; // 1,2 s ≈ 1 s
    try {
        const ip = testIp();
        const user = await registerAndLogin(app.base, { ip });
        assert.strictEqual((await me(user.token, ip)).status, 200);
        await wait(2500);
        assert.strictEqual((await me(user.token, ip)).status, 401, 'caducó');
        const r = await refresh(user.refreshToken, ip);
        assert.strictEqual(r.status, 200);
        assert.strictEqual((await me(r.body.token, ip)).status, 200);
    } finally { delete process.env.ACCESS_TOKEN_MINUTES; }
});

test('reutilizar un refresh ya rotado (fuera de la gracia) = robo: se revoca la sesión entera', async (t) => {
    if (!enabled) return t.skip('sin BD');
    const ip = testIp();
    const user = await registerAndLogin(app.base, { ip });
    const stolen = user.refreshToken;

    const legit = await refresh(stolen, ip);
    assert.strictEqual(legit.status, 200);
    // Pasada la gracia (se simula envejeciendo la rotación)
    await db.query('UPDATE user_sessions SET refreshed_at = DATE_SUB(NOW(), INTERVAL 1 HOUR) WHERE user_id = ?', [user.userId]);

    const attacker = await refresh(stolen, testIp());
    assert.strictEqual(attacker.status, 401);

    // La sesión murió para todos: el atacante y también quien tenía el token nuevo
    assert.strictEqual((await refresh(legit.body.refreshToken, ip)).status, 401);
    assert.strictEqual((await me(legit.body.token, ip)).status, 401, 'el JWT de acceso también deja de valer');

    const [events] = await db.query("SELECT severity FROM security_events WHERE event_type = 'REFRESH_TOKEN_REUSE' AND user_id = ?", [user.userId]);
    assert.strictEqual(events.length, 1);
    assert.strictEqual(events[0].severity, 'critical');
    assert.strictEqual((await sessionRow(user.userId)).revoked_reason, 'refresh_reuse');
});

test('dos renovaciones simultáneas con el mismo token: gana una, el resto recibe 409 y la sesión sigue viva', async (t) => {
    if (!enabled) return t.skip('sin BD');
    const ip = testIp();
    const user = await registerAndLogin(app.base, { ip });

    const results = await Promise.all(Array.from({ length: 6 }, () => refresh(user.refreshToken, ip)));
    const statuses = results.map(r => r.status).sort();
    assert.deepStrictEqual(statuses, [200, 409, 409, 409, 409, 409]);
    const winner = results.find(r => r.status === 200);
    assert.strictEqual((await me(winner.body.token, ip)).status, 200, 'la sesión no se revocó');
    assert.strictEqual((await refresh(winner.body.refreshToken, ip)).status, 200);
});

test('refresh: inválido, de otro formato, caducado por inactividad y por tope absoluto', async (t) => {
    if (!enabled) return t.skip('sin BD');
    const ip = testIp();

    for (const bad of ['', 'x', 'rt_corto', `rt_${'A'.repeat(43)}`, 'Bearer abc', `rt_${'A'.repeat(44)}`]) {
        const r = await refresh(bad, ip);
        assert.ok([400, 401].includes(r.status), `${bad} -> ${r.status}`);
    }
    assert.strictEqual((await api(app.base, 'POST', '/api/auth/refresh', { ip, json: {} })).status, 400);

    // Inactividad
    const idle = await registerAndLogin(app.base, { ip: testIp() });
    await db.query('UPDATE user_sessions SET expires_at = DATE_SUB(NOW(), INTERVAL 1 SECOND) WHERE user_id = ?', [idle.userId]);
    assert.strictEqual((await refresh(idle.refreshToken, ip)).status, 401);

    // Tope absoluto: aunque la renueve a diario, a los 30 días hay que iniciar sesión de nuevo
    const abs = await registerAndLogin(app.base, { ip: testIp() });
    await db.query('UPDATE user_sessions SET absolute_expires_at = DATE_SUB(NOW(), INTERVAL 1 SECOND) WHERE user_id = ?', [abs.userId]);
    assert.strictEqual((await refresh(abs.refreshToken, ip)).status, 401);
    assert.strictEqual((await me(abs.token, ip)).status, 401, 'el tope absoluto también corta el JWT aún vigente');
});

test('la renovación nunca supera el tope absoluto', async (t) => {
    if (!enabled) return t.skip('sin BD');
    const ip = testIp();
    const user = await registerAndLogin(app.base, { ip });
    await db.query('UPDATE user_sessions SET absolute_expires_at = DATE_ADD(NOW(), INTERVAL 1 HOUR) WHERE user_id = ?', [user.userId]);
    const r = await refresh(user.refreshToken, ip);
    assert.strictEqual(r.status, 200);
    const row = await sessionRow(user.userId);
    assert.ok(new Date(row.expires_at) <= new Date(row.absolute_expires_at), 'expires_at <= absolute_expires_at');
    assert.ok(new Date(r.body.refreshExpiresAt) <= new Date(r.body.sessionExpiresAt));
});

test('logout cierra SOLO esa sesión y su refresh deja de valer', async (t) => {
    if (!enabled) return t.skip('sin BD');
    const ip = testIp();
    const a = await registerAndLogin(app.base, { ip });
    const second = (await login(a.username, ip)).body;

    assert.strictEqual((await api(app.base, 'POST', '/api/auth/logout', { token: a.token, ip })).status, 200);
    assert.strictEqual((await me(a.token, ip)).status, 401);
    assert.strictEqual((await refresh(a.refreshToken, ip)).status, 401);
    assert.strictEqual((await me(second.token, ip)).status, 200, 'la otra sesión sigue');
});

test('cerrar TODAS las sesiones: tokens de acceso y refresh de todos los dispositivos dejan de valer', async (t) => {
    if (!enabled) return t.skip('sin BD');
    const ip = testIp();
    const phone = await registerAndLogin(app.base, { ip });
    const laptop = (await login(phone.username, ip)).body;
    const tablet = (await login(phone.username, ip)).body;
    const other = await registerAndLogin(app.base, { ip: testIp() });

    const res = await api(app.base, 'POST', '/api/auth/logout-all', { token: laptop.token, ip, json: {} });
    assert.strictEqual(res.status, 200, res.text);
    assert.strictEqual(res.body.closed, 3);

    for (const tokens of [phone, laptop, tablet]) {
        assert.strictEqual((await me(tokens.token, ip)).status, 401);
        assert.strictEqual((await refresh(tokens.refreshToken, ip)).status, 401);
    }
    assert.strictEqual((await me(other.token, ip)).status, 200, 'las sesiones de otro usuario no se tocan');
});

test('cerrar todas menos la actual (keepCurrent) y listado de sesiones', async (t) => {
    if (!enabled) return t.skip('sin BD');
    const ip = testIp();
    const phone = await registerAndLogin(app.base, { ip });
    const laptop = (await login(phone.username, ip)).body;

    const list = await api(app.base, 'GET', '/api/auth/sessions', { token: laptop.token, ip });
    assert.strictEqual(list.status, 200);
    assert.strictEqual(list.body.sessions.length, 2);
    assert.strictEqual(list.body.sessions.filter(s => s.current).length, 1);
    assert.ok(list.body.sessions.every(s => s.createdAt && s.authMethods.includes('pwd')));
    assert.ok(!JSON.stringify(list.body).match(/refresh|hash/i), 'el listado no expone hashes ni tokens');

    const res = await api(app.base, 'POST', '/api/auth/logout-all', { token: laptop.token, ip, json: { keepCurrent: true } });
    assert.strictEqual(res.body.closed, 1);
    assert.strictEqual((await me(laptop.token, ip)).status, 200);
    assert.strictEqual((await me(phone.token, ip)).status, 401);
});

test('cerrar una sesión concreta; no se puede cerrar la de otro usuario (404, sin distinguir)', async (t) => {
    if (!enabled) return t.skip('sin BD');
    const ip = testIp();
    const owner = await registerAndLogin(app.base, { ip });
    const second = (await login(owner.username, ip)).body;
    const intruder = await registerAndLogin(app.base, { ip: testIp() });

    const list = await api(app.base, 'GET', '/api/auth/sessions', { token: owner.token, ip });
    const target = list.body.sessions.find(s => !s.current);

    const cross = await api(app.base, 'DELETE', `/api/auth/sessions/${target.id}`, { token: intruder.token, ip });
    assert.strictEqual(cross.status, 404);
    assert.strictEqual((await me(second.token, ip)).status, 200, 'sigue viva');
    assert.strictEqual((await api(app.base, 'DELETE', '/api/auth/sessions/abc', { token: owner.token, ip })).status, 400);
    assert.strictEqual((await api(app.base, 'DELETE', '/api/auth/sessions/999999999', { token: owner.token, ip })).status, 404);
    // Hallazgo del fuzzing: un id fuera del rango de la columna daba 500
    assert.strictEqual((await api(app.base, 'DELETE', '/api/auth/sessions/2147483648', { token: owner.token, ip })).status, 404);
    assert.strictEqual((await api(app.base, 'DELETE', '/api/auth/sessions/99999999999999999999', { token: owner.token, ip })).status, 400);

    assert.strictEqual((await api(app.base, 'DELETE', `/api/auth/sessions/${target.id}`, { token: owner.token, ip })).status, 200);
    assert.strictEqual((await me(second.token, ip)).status, 401);
    assert.strictEqual((await api(app.base, 'DELETE', `/api/auth/sessions/${target.id}`, { token: owner.token, ip })).status, 404, 'ya cerrada');
});

test('sin token no se pueden listar ni cerrar sesiones', async (t) => {
    if (!enabled) return t.skip('sin BD');
    const ip = testIp();
    assert.strictEqual((await api(app.base, 'GET', '/api/auth/sessions', { ip })).status, 401);
    assert.strictEqual((await api(app.base, 'POST', '/api/auth/logout-all', { ip, json: {} })).status, 401);
    assert.strictEqual((await api(app.base, 'DELETE', '/api/auth/sessions/1', { ip })).status, 401);
});

test('un JWT de reto de MFA, o firmado con otro secreto/algoritmo, no vale como sesión ni se renueva', async (t) => {
    if (!enabled) return t.skip('sin BD');
    const ip = testIp();
    const user = await registerAndLogin(app.base, { ip });
    const claims = jwt.decode(user.token);

    const { exp, iat, ...payload } = claims;
    const forged = jwt.sign(payload, 'otro-secreto', { algorithm: 'HS256', expiresIn: 600 });
    assert.strictEqual((await me(forged, ip)).status, 401);
    const none = `${Buffer.from('{"alg":"none","typ":"JWT"}').toString('base64url')}.${Buffer.from(JSON.stringify(claims)).toString('base64url')}.`;
    assert.strictEqual((await me(none, ip)).status, 401);
    // El access token no sirve como refresh
    assert.ok([400, 401].includes((await refresh(user.token, ip)).status));
});

test('tokens largos anteriores (sin v:2, buscados por hash) siguen valiendo hasta que caduquen', async (t) => {
    if (!enabled) return t.skip('sin BD');
    const ip = testIp();
    const user = await registerAndLogin(app.base, { ip });
    const credentialBuilder = require('./src/config/credential-builder');
    const secureAuth = require('./src/security/secure-auth.service');

    const legacy = jwt.sign({ userId: user.userId, username: user.username, sessionId: 'x', riskLevel: 'low', amr: ['pwd'] },
        credentialBuilder.generateJWTSecret(), { algorithm: 'HS256', expiresIn: '5d' });
    await db.query(
        `INSERT INTO user_sessions (user_id, jwt_token_hash, ip_address, user_agent, risk_level, expires_at)
         VALUES (?, ?, '127.0.0.1', 'legacy', 'low', DATE_ADD(NOW(), INTERVAL 5 DAY))`, [user.userId, secureAuth.hashToken(legacy)]);

    assert.strictEqual((await me(legacy, ip)).status, 200);
    assert.strictEqual((await api(app.base, 'POST', '/api/auth/logout-all', { token: legacy, ip, json: {} })).status, 200);
    assert.strictEqual((await me(legacy, ip)).status, 401, 'logout-all cierra también las sesiones antiguas');
});

test('la fila de sesión no se reactiva por efecto colateral (expires_at sin ON UPDATE)', async (t) => {
    if (!enabled) return t.skip('sin BD');
    const user = await registerAndLogin(app.base, { ip: testIp() });
    await db.query('UPDATE user_sessions SET expires_at = DATE_SUB(NOW(), INTERVAL 1 HOUR) WHERE user_id = ?', [user.userId]);
    const before = (await sessionRow(user.userId)).expires_at;
    await db.query('UPDATE user_sessions SET risk_level = ? WHERE user_id = ?', ['high', user.userId]);
    const after = (await sessionRow(user.userId)).expires_at;
    assert.strictEqual(+new Date(after), +new Date(before), 'un UPDATE ajeno no toca expires_at');
});
