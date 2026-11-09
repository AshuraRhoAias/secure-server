// Pruebas de roles finos (RBAC) y de la aprobación de dos administradores. MariaDB real.
//
//   npm run test:rbac

const test = require('node:test');
const assert = require('node:assert');

require('./test_helpers/env');
const helpers = require('./test_helpers/app');
const { api, registerAndLogin, testIp } = helpers;
const totp = require('./src/security/totp');

let app, db, enabled = false;

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

const itDb = (name, fn) => test(name, async (t) => { if (!enabled) return t.skip('sin BD'); await fn(t); });

async function userWithRole(role) {
    const ip = testIp();
    const user = await registerAndLogin(app.base, { ip });
    if (role !== 'user') await db.query('UPDATE users SET role = ? WHERE id = ?', [role, user.userId]);
    return { ...user, ip, role };
}
const call = (user, method, route, json) => api(app.base, method, route, { token: user.token, ip: user.ip, json });

async function userWithMfa() {
    const user = await userWithRole('user');
    const setup = await call(user, 'POST', '/api/auth/mfa/setup');
    const enable = await call(user, 'POST', '/api/auth/mfa/enable', { otp: totp.totp(setup.body.secret) });
    assert.strictEqual(enable.status, 200, enable.text);
    return { ...user, secret: setup.body.secret };
}
const withEnv = async (vars, fn) => {
    const saved = Object.fromEntries(Object.keys(vars).map(k => [k, process.env[k]]));
    Object.assign(process.env, vars);
    try { await fn(); } finally {
        for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
    }
};
const REASON = 'Dispositivo perdido, verificado por videollamada con el titular';

// ============================================================================ permisos (puro)

test('permisos: un permiso desconocido falla al definir la ruta, no deja la ruta abierta', () => {
    const roleMiddleware = require('./src/middleware/role.middleware');
    assert.throws(() => roleMiddleware.requirePermission('system:redd'), /Permiso desconocido/);
    const { can, ROLES } = require('./src/security/permissions');
    assert.deepStrictEqual(ROLES, ['user', 'auditor', 'operator', 'admin']);
    assert.strictEqual(can('user', 'system:read'), false);
    assert.strictEqual(can('rol-inventado', 'system:read'), false);
    assert.throws(() => can('admin', 'nope'));
});

test('permisos: la operación y observabilidad nuevas son SOLO admin', () => {
    const { PERMISSIONS } = require('./src/security/permissions');
    for (const name of ['alerts:read', 'alerts:manage', 'dashboard:read', 'metrics:read', 'privacy:export', 'privacy:erase',
        'sessions:revoke-any', 'approvals:read', 'approvals:decide', 'accounts:mfa-reset', 'system:operate']) {
        assert.deepStrictEqual(PERMISSIONS[name], ['admin'], name);
    }
});

// ============================================================================ matriz de roles contra el servidor real

const MATRIX = [
    // [método, ruta, permiso, roles que SÍ pasan]
    ['GET', '/api/system/status', ['auditor', 'operator', 'admin']],
    ['GET', '/api/system/logs', ['auditor', 'operator', 'admin']],
    ['GET', '/api/system/rotation', ['auditor', 'operator', 'admin']],
    ['GET', '/api/system/blocked-ips', ['auditor', 'operator', 'admin']],
    ['GET', '/api/system/security-events', ['auditor', 'operator', 'admin']],
    ['GET', '/api/system/security-summary', ['auditor', 'operator', 'admin']],
    ['DELETE', '/api/system/blocked-ips/203.0.113.250', ['operator', 'admin']],
    ['POST', '/api/system/accounts/unlock', ['operator', 'admin'], { username: 'nadie-existe' }],
    ['POST', '/api/system/accounts/mfa-reset', ['admin'], { username: 'nadie-existe', reason: REASON }],
    ['GET', '/api/system/approvals', ['admin']],
    ['POST', '/api/system/approvals/999999/approve', ['admin']],
    ['POST', '/api/system/approvals/999999/reject', ['admin']],
    ['POST', '/api/system/integrity-check', ['admin']],
    ['POST', '/api/system/rotate-keys', ['admin']],
    ['POST', '/api/system/test-communications', ['admin']]
];

itDb('matriz: cada rol solo llega a lo suyo (403 para el resto)', async () => {
    const users = {};
    for (const role of ['user', 'auditor', 'operator', 'admin']) users[role] = await userWithRole(role);

    for (const [method, route, allowed, body] of MATRIX) {
        for (const [role, user] of Object.entries(users)) {
            const res = await call(user, method, route, body);
            if (allowed.includes(role)) assert.notStrictEqual(res.status, 403, `${role} ${method} ${route} -> ${res.status} ${res.text.slice(0, 100)}`);
            else assert.strictEqual(res.status, 403, `${role} ${method} ${route} debía ser 403 y fue ${res.status}`);
        }
    }
});

itDb('default-deny: TODA ruta de /api/system rechaza al usuario normal (nadie se dejó una ruta sin permiso)', async () => {
    const router = require('./src/api/routes/system.routes');
    const user = await userWithRole('user');
    const routes = router.stack.filter(layer => layer.route);
    assert.ok(routes.length >= 15);
    for (const layer of routes) {
        for (const method of Object.keys(layer.route.methods)) {
            const route = '/api/system' + layer.route.path.replace(':id', '1').replace(':ip', '203.0.113.9');
            const hasBody = ['POST', 'PUT', 'PATCH'].includes(method.toUpperCase());
            const res = await call(user, method.toUpperCase(), route, hasBody ? { username: 'x', reason: REASON } : undefined);
            assert.strictEqual(res.status, 403, `${method} ${route} -> ${res.status}`);
        }
    }
});

itDb('el rol se lee de la BD en cada petición: quitarlo surte efecto al instante', async () => {
    const op = await userWithRole('operator');
    assert.strictEqual((await call(op, 'GET', '/api/system/status')).status, 200);
    await db.query("UPDATE users SET role = 'user' WHERE id = ?", [op.userId]);
    assert.strictEqual((await call(op, 'GET', '/api/system/status')).status, 403, 'mismo token, rol retirado');
});

itDb('un rol desconocido que llegara de la BD no concede acceso aunque el permiso lo "permitiera"', async () => {
    const roleMiddleware = require('./src/middleware/role.middleware');
    const original = db.query;
    db.query = async () => [[{ role: 'superadmin' }]];
    try {
        for (const guard of [roleMiddleware.requireRole('superadmin'), roleMiddleware.requirePermission('system:read')]) {
            let status = null, nextCalled = false;
            const res = { status(code) { status = code; return this; }, json() { return this; } };
            await guard({ user: { id: 1 } }, res, () => { nextCalled = true; });
            assert.strictEqual(status, 403);
            assert.strictEqual(nextCalled, false);
        }
    } finally { db.query = original; }
});

itDb('MFA_REQUIRED_FOR_ADMINS alcanza a TODOS los roles con privilegios, no solo a admin', async () => {
    await withEnv({ MFA_REQUIRED_FOR_ADMINS: 'true' }, async () => {
        for (const role of ['auditor', 'operator', 'admin']) {
            const user = await userWithRole(role);
            const res = await call(user, 'GET', '/api/system/status');
            assert.strictEqual(res.status, 403, role);
            assert.strictEqual(res.body.code, 'MFA_REQUIRED', role);
        }
        const plain = await userWithRole('user');
        assert.strictEqual((await call(plain, 'GET', '/api/notes')).status, 200, 'un usuario normal no se ve afectado');
    });
});

itDb('auditor y operator no pueden escribir donde solo lee/opera el admin; el operator sí desbloquea cuentas', async () => {
    const auditor = await userWithRole('auditor');
    const operator = await userWithRole('operator');
    const victim = await userWithRole('user');
    assert.strictEqual((await call(auditor, 'POST', '/api/system/accounts/unlock', { username: victim.username })).status, 403);
    assert.strictEqual((await call(operator, 'POST', '/api/system/accounts/unlock', { username: victim.username })).status, 200);
    assert.strictEqual((await call(operator, 'POST', '/api/system/accounts/mfa-reset', { username: victim.username, reason: REASON })).status, 403);
});

// ============================================================================ aprobación de dos administradores

itDb('reiniciar el MFA exige a un SEGUNDO administrador: el solicitante no puede aprobarse a sí mismo', async () => {
    const adminA = await userWithRole('admin');
    const adminB = await userWithRole('admin');
    const victim = await userWithMfa();
    await call(victim, 'POST', '/api/auth/login', null).catch(() => {});

    const request = await call(adminA, 'POST', '/api/system/accounts/mfa-reset', { username: victim.username, reason: REASON });
    assert.strictEqual(request.status, 202, request.text);
    assert.strictEqual(request.body.status, 'pending');
    const id = request.body.approvalId;

    // Nada cambió todavía
    const [[still]] = await db.query('SELECT mfa_enabled FROM users WHERE id = ?', [victim.userId]);
    assert.strictEqual(still.mfa_enabled, 1);

    const self = await call(adminA, 'POST', `/api/system/approvals/${id}/approve`);
    assert.strictEqual(self.status, 403);
    assert.strictEqual(self.body.code, 'SELF_APPROVAL');
    assert.strictEqual((await db.query('SELECT mfa_enabled FROM users WHERE id = ?', [victim.userId]))[0][0].mfa_enabled, 1);

    const listing = await call(adminB, 'GET', '/api/system/approvals?status=pending');
    const item = listing.body.approvals.find(a => a.id === id);
    assert.ok(item && item.target.username === victim.username && item.reason === REASON);

    const approved = await call(adminB, 'POST', `/api/system/approvals/${id}/approve`);
    assert.strictEqual(approved.status, 200, approved.text);
    assert.strictEqual(approved.body.status, 'executed');
    assert.strictEqual(approved.body.result.mfaDisabled, true);
    assert.strictEqual((await db.query('SELECT mfa_enabled FROM users WHERE id = ?', [victim.userId]))[0][0].mfa_enabled, 0);

    // Las sesiones de la víctima se cerraron (si alguien ya estaba dentro con una robada, también se queda fuera)
    assert.strictEqual((await call(victim, 'GET', '/api/notes')).status, 401);

    // Una solicitud ejecutada no se vuelve a ejecutar
    assert.strictEqual((await call(adminB, 'POST', `/api/system/approvals/${id}/approve`)).status, 409);

    const [rows] = await db.query('SELECT status, requested_by, approved_by, executed_at FROM admin_approvals WHERE id = ?', [id]);
    assert.deepStrictEqual([rows[0].status, rows[0].requested_by, rows[0].approved_by], ['executed', adminA.userId, adminB.userId]);
    assert.ok(rows[0].executed_at);

    const [events] = await db.query("SELECT event_type FROM security_events WHERE user_id = ? AND event_type IN ('ADMIN_APPROVAL_REQUESTED','ADMIN_APPROVAL_EXECUTED','MFA_RESET_BY_ADMIN')", [victim.userId]);
    assert.deepStrictEqual(events.map(e => e.event_type).sort(), ['ADMIN_APPROVAL_EXECUTED', 'ADMIN_APPROVAL_REQUESTED', 'MFA_RESET_BY_ADMIN']);
});

itDb('dos administradores aprobando a la vez: se ejecuta UNA sola vez', async () => {
    const adminA = await userWithRole('admin');
    const [adminB, adminC] = [await userWithRole('admin'), await userWithRole('admin')];
    const victim = await userWithMfa();

    const id = (await call(adminA, 'POST', '/api/system/accounts/mfa-reset', { username: victim.username, reason: REASON })).body.approvalId;
    const results = await Promise.all([adminB, adminC, adminB, adminC].map(a => call(a, 'POST', `/api/system/approvals/${id}/approve`)));
    assert.strictEqual(results.filter(r => r.status === 200).length, 1, results.map(r => r.status).join(','));
    assert.ok(results.filter(r => r.status !== 200).every(r => r.status === 409));
    const [events] = await db.query("SELECT COUNT(*) AS n FROM security_events WHERE event_type = 'MFA_RESET_BY_ADMIN' AND user_id = ?", [victim.userId]);
    assert.strictEqual(Number(events[0].n), 1);
});

itDb('solicitud: motivo obligatorio, usuario inexistente, caducada, rechazada y cancelada', async () => {
    const adminA = await userWithRole('admin');
    const adminB = await userWithRole('admin');
    const victim = await userWithMfa();

    assert.strictEqual((await call(adminA, 'POST', '/api/system/accounts/mfa-reset', { username: victim.username })).status, 400, 'sin motivo');
    assert.strictEqual((await call(adminA, 'POST', '/api/system/accounts/mfa-reset', { username: victim.username, reason: 'corto' })).status, 400);
    assert.strictEqual((await call(adminA, 'POST', '/api/system/accounts/mfa-reset', { username: 'no-existe-' + Date.now(), reason: REASON })).status, 404);

    // caducada
    const expired = (await call(adminA, 'POST', '/api/system/accounts/mfa-reset', { username: victim.username, reason: REASON })).body.approvalId;
    await db.query('UPDATE admin_approvals SET expires_at = DATE_SUB(NOW(), INTERVAL 1 MINUTE) WHERE id = ?', [expired]);
    assert.strictEqual((await call(adminB, 'POST', `/api/system/approvals/${expired}/approve`)).status, 410);
    const shown = (await call(adminB, 'GET', '/api/system/approvals')).body.approvals.find(a => a.id === expired);
    assert.strictEqual(shown.status, 'expired');

    // rechazada por otro admin / cancelada por quien la pidió
    const rejected = (await call(adminA, 'POST', '/api/system/accounts/mfa-reset', { username: victim.username, reason: REASON })).body.approvalId;
    assert.strictEqual((await call(adminB, 'POST', `/api/system/approvals/${rejected}/reject`)).body.status, 'rejected');
    assert.strictEqual((await call(adminB, 'POST', `/api/system/approvals/${rejected}/approve`)).status, 409);
    const cancelled = (await call(adminA, 'POST', '/api/system/accounts/mfa-reset', { username: victim.username, reason: REASON })).body.approvalId;
    assert.strictEqual((await call(adminA, 'POST', `/api/system/approvals/${cancelled}/reject`)).body.status, 'cancelled');

    assert.strictEqual((await call(adminB, 'POST', '/api/system/approvals/99999999/approve')).status, 404);
    assert.strictEqual((await call(adminB, 'POST', '/api/system/approvals/abc/approve')).status, 400);
    assert.strictEqual((await db.query('SELECT mfa_enabled FROM users WHERE id = ?', [victim.userId]))[0][0].mfa_enabled, 1, 'nada de esto desactivó el MFA');
});

itDb('ADMIN_APPROVALS_REQUIRED=1 (un solo administrador): se ejecuta al momento y queda registrado', async () => {
    await withEnv({ ADMIN_APPROVALS_REQUIRED: '1' }, async () => {
        const admin = await userWithRole('admin');
        const victim = await userWithMfa();
        const res = await call(admin, 'POST', '/api/system/accounts/mfa-reset', { username: victim.username, reason: REASON });
        assert.strictEqual(res.status, 200, res.text);
        assert.strictEqual(res.body.status, 'executed');
        assert.strictEqual((await db.query('SELECT mfa_enabled FROM users WHERE id = ?', [victim.userId]))[0][0].mfa_enabled, 0);
        const [[row]] = await db.query('SELECT status, requested_by, approved_by, reason FROM admin_approvals WHERE id = ?', [res.body.approvalId]);
        assert.deepStrictEqual([row.status, row.requested_by, row.approved_by, row.reason], ['executed', admin.userId, admin.userId, REASON]);
    });
});

// ============================================================================ SSO no degrada roles intermedios

itDb('roles: el esquema acepta los cuatro roles y rechaza otros', async () => {
    const user = await userWithRole('user');
    for (const role of ['auditor', 'operator', 'admin', 'user']) {
        await db.query('UPDATE users SET role = ? WHERE id = ?', [role, user.userId]);
    }
    await assert.rejects(() => db.query("UPDATE users SET role = 'root' WHERE id = ?", [user.userId]));
});
