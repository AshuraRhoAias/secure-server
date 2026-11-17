// Gestión de usuarios desde la web (FASE 1): crear cuentas, doble firma para el rol admin, cambio de rol,
// contraseña temporal con cambio obligatorio y cambio de contraseña. MariaDB real.
//
//   node --test test/test_users_admin.js

const test = require('node:test');
const assert = require('node:assert');

require('./helpers/env');
const helpers = require('./helpers/app');
const { api, registerAndLogin, testIp, uniqueName } = helpers;
const userAdmin = require('../src/security/user-admin.service');

let app, db, enabled = false;

test.before(async () => {
    enabled = await helpers.prepareDatabase();
    if (!enabled) return;
    db = require('../src/config/database');
    app = await helpers.startApp();
});
test.after(async () => {
    if (!enabled) return;
    await app.close();
    await db.pool.end();
});

const itDb = (name, fn) => test(name, async (t) => { if (!enabled) return t.skip('sin BD'); await fn(t); });
const REASON = 'Alta de personal nuevo, verificada con RRHH';

async function userWithRole(role) {
    const ip = testIp();
    const user = await registerAndLogin(app.base, { ip });
    if (role !== 'user') await db.query('UPDATE users SET role = ? WHERE id = ?', [role, user.userId]);
    return { ...user, ip, role };
}
const call = (user, method, route, json) => api(app.base, method, route, { token: user.token, ip: user.ip, json });
const login = (username, password, ip = testIp()) => api(app.base, 'POST', '/api/auth/login', { ip, json: { username, password } });

// ============================================================================ puro

test('contraseña temporal: 24 caracteres, cumple la política y no se repite', () => {
    const seen = new Set();
    for (let i = 0; i < 50; i++) {
        const pw = userAdmin.generateTemporaryPassword();
        assert.ok(pw.length >= 20);
        assert.strictEqual(userAdmin.passwordPolicyError(pw), null);
        assert.match(pw, /[A-Z]/); assert.match(pw, /[a-z]/); assert.match(pw, /\d/); assert.match(pw, /[-_.!#$%*+=]/);
        seen.add(pw);
    }
    assert.strictEqual(seen.size, 50);
    assert.ok(userAdmin.passwordPolicyError('corta'));
    assert.ok(userAdmin.passwordPolicyError('é'.repeat(40))); // 80 bytes > 72
});

// ============================================================================ crear usuarios

for (const role of ['user', 'auditor', 'operator']) {
    itDb(`crear ${role}: 201, contraseña temporal, login con cambio obligatorio hasta cambiarla`, async () => {
        const admin = await userWithRole('admin');
        const username = uniqueName('nuevo');
        const created = await call(admin, 'POST', '/api/system/users', { username, role, reason: REASON });
        assert.strictEqual(created.status, 201, created.text);
        const temp = created.body.temporaryPassword;
        assert.strictEqual(userAdmin.passwordPolicyError(temp), null);
        assert.ok(temp.length >= 20);
        assert.strictEqual(created.body.user.role, role);

        const [rows] = await db.query('SELECT role, must_change_password, created_by FROM users WHERE id = ?', [created.body.user.id]);
        assert.strictEqual(rows[0].role, role);
        assert.strictEqual(Number(rows[0].must_change_password), 1);
        assert.strictEqual(Number(rows[0].created_by), admin.userId);

        const ip = testIp();
        const session = await login(username, temp, ip);
        assert.strictEqual(session.status, 200, session.text);
        assert.strictEqual(session.body.passwordChangeRequired, true);
        const me = { token: session.body.token, ip };

        const blocked = await api(app.base, 'GET', '/api/notes', me);
        assert.strictEqual(blocked.status, 403, blocked.text);
        assert.strictEqual(blocked.body.code, 'PASSWORD_CHANGE_REQUIRED');
        assert.strictEqual((await api(app.base, 'GET', '/api/auth/profile', me)).status, 200);

        const nueva = 'Otra-Contraseña-Larga-456';
        const changed = await api(app.base, 'POST', '/api/auth/password', { ...me, json: { currentPassword: temp, newPassword: nueva } });
        assert.strictEqual(changed.status, 200, changed.text);
        assert.strictEqual((await api(app.base, 'GET', '/api/notes', me)).status, 200); // misma sesión, ya sin bloqueo

        assert.strictEqual((await login(username, temp)).status, 401);
        const again = await login(username, nueva);
        assert.strictEqual(again.status, 200);
        assert.strictEqual(again.body.passwordChangeRequired, false);
    });
}

itDb('crear con contraseña propia: no se devuelve y debe cumplir la política', async () => {
    const admin = await userWithRole('admin');
    const username = uniqueName('propia');
    const weak = await call(admin, 'POST', '/api/system/users', { username, role: 'user', reason: REASON, password: 'corta' });
    assert.strictEqual(weak.status, 400);
    const ok = await call(admin, 'POST', '/api/system/users', { username, role: 'user', reason: REASON, password: 'Clave-Inicial-Larga-1' });
    assert.strictEqual(ok.status, 201, ok.text);
    assert.strictEqual(ok.body.temporaryPassword, null);
    assert.strictEqual((await login(username, 'Clave-Inicial-Larga-1')).body.passwordChangeRequired, true);
});

itDb('nombre duplicado: 409; motivo corto: 400; no-admin: 403', async () => {
    const admin = await userWithRole('admin');
    const username = uniqueName('dup');
    assert.strictEqual((await call(admin, 'POST', '/api/system/users', { username, role: 'user', reason: REASON })).status, 201);
    const dup = await call(admin, 'POST', '/api/system/users', { username, role: 'user', reason: REASON });
    assert.strictEqual(dup.status, 409);
    const short = await call(admin, 'POST', '/api/system/users', { username: uniqueName('corto'), role: 'user', reason: 'corto' });
    assert.strictEqual(short.status, 400);

    for (const role of ['user', 'auditor', 'operator']) {
        const other = await userWithRole(role);
        assert.strictEqual((await call(other, 'POST', '/api/system/users', { username: uniqueName('x'), role: 'user', reason: REASON })).status, 403, role);
        assert.strictEqual((await call(other, 'GET', '/api/system/users')).status, 403, role);
        assert.strictEqual((await call(other, 'POST', `/api/system/users/${admin.userId}/role`, { role: 'user', reason: REASON })).status, 403, role);
    }
});

// ============================================================================ rol admin con doble firma

itDb('crear admin: 202 con aprobación; el mismo admin no la aprueba; otro sí y se cierran las sesiones', async () => {
    const adminA = await userWithRole('admin');
    const adminB = await userWithRole('admin');
    const username = uniqueName('futuroadmin');
    const created = await call(adminA, 'POST', '/api/system/users', { username, role: 'admin', reason: REASON });
    assert.strictEqual(created.status, 202, created.text);
    assert.strictEqual(created.body.user.role, 'user');
    assert.ok(created.body.approvalId);
    assert.ok(created.body.temporaryPassword);
    const userId = created.body.user.id;

    const [pending] = await db.query('SELECT action, status, params FROM admin_approvals WHERE id = ?', [created.body.approvalId]);
    assert.strictEqual(pending[0].action, 'user_set_role');
    assert.strictEqual(pending[0].status, 'pending');
    assert.deepStrictEqual(JSON.parse(pending[0].params), { role: 'admin' }); // sin contraseñas en los params

    // El nuevo usuario entra y abre una sesión (con la temporal, antes de la aprobación)
    const ip = testIp();
    const session = await login(username, created.body.temporaryPassword, ip);
    assert.strictEqual(session.status, 200);

    const self = await call(adminA, 'POST', `/api/system/approvals/${created.body.approvalId}/approve`);
    assert.strictEqual(self.status, 403, self.text);

    // Con la contraseña temporal todavía (adminA la conoce), otro admin NO puede darle admin: 409 y sigue pendiente
    const early = await call(adminB, 'POST', `/api/system/approvals/${created.body.approvalId}/approve`);
    assert.strictEqual(early.status, 409, early.text);
    assert.strictEqual(early.body.code, 'TARGET_NOT_READY');
    const [stillPending] = await db.query('SELECT status FROM admin_approvals WHERE id = ?', [created.body.approvalId]);
    assert.strictEqual(stillPending[0].status, 'pending');

    // El titular cambia la contraseña (la sesión actual sigue); ya se puede aprobar
    const changed = await api(app.base, 'POST', '/api/auth/password', {
        token: session.body.token, ip, json: { currentPassword: created.body.temporaryPassword, newPassword: 'Titular-Nueva-Clave-2026' }
    });
    assert.strictEqual(changed.status, 200, changed.text);

    const approved = await call(adminB, 'POST', `/api/system/approvals/${created.body.approvalId}/approve`);
    assert.strictEqual(approved.status, 200, approved.text);
    const [rows] = await db.query('SELECT role FROM users WHERE id = ?', [userId]);
    assert.strictEqual(rows[0].role, 'admin');

    const dead = await api(app.base, 'GET', '/api/auth/profile', { token: session.body.token, ip });
    assert.strictEqual(dead.status, 401, 'las sesiones del usuario se revocan al cambiar el rol');
    const [live] = await db.query('SELECT COUNT(*) AS n FROM user_sessions WHERE user_id = ? AND revoked_at IS NULL', [userId]);
    assert.strictEqual(Number(live[0].n), 0);
});

// ============================================================================ cambio de rol

itDb('cambiar rol: directo (200) revoca sesiones; a admin pasa por aprobación (202)', async () => {
    const admin = await userWithRole('admin');
    const target = await userWithRole('user');

    const direct = await call(admin, 'POST', `/api/system/users/${target.userId}/role`, { role: 'auditor', reason: REASON });
    assert.strictEqual(direct.status, 200, direct.text);
    assert.strictEqual(direct.body.role, 'auditor');
    assert.strictEqual((await call(target, 'GET', '/api/auth/profile')).status, 401);
    const [rows] = await db.query('SELECT role FROM users WHERE id = ?', [target.userId]);
    assert.strictEqual(rows[0].role, 'auditor');

    const same = await call(admin, 'POST', `/api/system/users/${target.userId}/role`, { role: 'auditor', reason: REASON });
    assert.strictEqual(same.status, 409);

    const up = await call(admin, 'POST', `/api/system/users/${target.userId}/role`, { role: 'admin', reason: REASON });
    assert.strictEqual(up.status, 202, up.text);
    const [still] = await db.query('SELECT role FROM users WHERE id = ?', [target.userId]);
    assert.strictEqual(still[0].role, 'auditor');
    assert.strictEqual((await call(admin, 'POST', '/api/system/users/999999/role', { role: 'user', reason: REASON })).status, 404);
    assert.strictEqual((await call(admin, 'POST', `/api/system/users/${target.userId}/role`, { role: 'user', reason: 'corto' })).status, 400);
});

itDb('degradar a un admin también exige la firma de otro admin (202) y no cambia nada hasta entonces', async () => {
    const adminA = await userWithRole('admin');
    const adminB = await userWithRole('admin');
    const down = await call(adminA, 'POST', `/api/system/users/${adminB.userId}/role`, { role: 'user', reason: REASON });
    assert.strictEqual(down.status, 202, down.text);
    const [rows] = await db.query('SELECT role FROM users WHERE id = ?', [adminB.userId]);
    assert.strictEqual(rows[0].role, 'admin');
    assert.strictEqual((await call(adminB, 'GET', '/api/auth/profile')).status, 200, 'sus sesiones siguen hasta la aprobación');
});

itDb('aplicar admin a una cuenta con contraseña temporal se rechaza también en la capa de servicio', async () => {
    const admin = await userWithRole('admin');
    const created = await call(admin, 'POST', '/api/system/users', { username: uniqueName('temporal'), role: 'user', reason: REASON });
    assert.strictEqual(created.status, 201, created.text);
    await assert.rejects(userAdmin.applyRole(created.body.user.id, 'admin', { actor: admin.userId }), { code: 'TARGET_NOT_READY' });
});

itDb('no se cambia el propio rol (403) ni se deja el sistema sin administradores (409)', async () => {
    const admin = await userWithRole('admin');
    const self = await call(admin, 'POST', `/api/system/users/${admin.userId}/role`, { role: 'user', reason: REASON });
    assert.strictEqual(self.status, 403, self.text);

    // Solo queda un admin (admin) y se intenta degradarlo desde otro: el "otro" tendría que ser admin, así que
    // se prueba directamente la regla de la capa de servicio con un único administrador en la tabla.
    await db.query("UPDATE users SET role = 'user' WHERE role = 'admin' AND id <> ?", [admin.userId]);
    await assert.rejects(userAdmin.applyRole(admin.userId, 'user', { actor: 0 }), { code: 'LAST_ADMIN' });
    const [rows] = await db.query('SELECT role FROM users WHERE id = ?', [admin.userId]);
    assert.strictEqual(rows[0].role, 'admin');
});

// ============================================================================ listado

itDb('listado: paginado, filtra por rol y busca por nombre exacto; sin hashes ni secretos', async () => {
    const admin = await userWithRole('admin');
    const username = uniqueName('buscado');
    const created = await call(admin, 'POST', '/api/system/users', { username, role: 'operator', reason: REASON });
    assert.strictEqual(created.status, 201);

    const found = await call(admin, 'GET', `/api/system/users?q=${encodeURIComponent(username)}`);
    assert.strictEqual(found.status, 200, found.text);
    assert.strictEqual(found.body.users.length, 1);
    const row = found.body.users[0];
    assert.strictEqual(row.username, username);
    assert.strictEqual(row.role, 'operator');
    assert.strictEqual(row.mustChangePassword, true);
    assert.strictEqual(row.mfaEnabled, false);
    assert.strictEqual(row.activeSessions, 0);
    assert.strictEqual(row.createdBy, admin.userId);

    const operators = await call(admin, 'GET', '/api/system/users?role=operator');
    assert.ok(operators.body.users.every(u => u.role === 'operator'));

    const page = await call(admin, 'GET', '/api/system/users?limit=2');
    assert.strictEqual(page.body.users.length, 2);
    assert.ok(page.body.nextBefore);
    const next = await call(admin, 'GET', `/api/system/users?limit=2&before=${page.body.nextBefore}`);
    assert.ok(next.body.users.every(u => u.id < page.body.nextBefore));
    assert.strictEqual((await call(admin, 'GET', '/api/system/users?limit=201')).status, 400);

    const text = (await call(admin, 'GET', '/api/system/users?limit=200')).text.toLowerCase();
    for (const secret of ['password_hash', 'passwordhash', 'hash', 'secret', 'encrypted', created.body.temporaryPassword.toLowerCase()]) {
        assert.ok(!text.includes(secret), `la respuesta no debe contener "${secret}"`);
    }
});

// ============================================================================ cambio de contraseña

itDb('cambio de contraseña: actual incorrecta rechazada, igual rechazada, revoca las demás sesiones', async () => {
    const ip = testIp();
    const user = await registerAndLogin(app.base, { ip });
    const second = await login(user.username, user.password, ip);
    assert.strictEqual(second.status, 200);
    const me = { token: user.token, ip };

    const wrong = await api(app.base, 'POST', '/api/auth/password', { ...me, json: { currentPassword: 'incorrecta-123', newPassword: 'Nueva-Contraseña-789' } });
    assert.strictEqual(wrong.status, 401);
    const same = await api(app.base, 'POST', '/api/auth/password', { ...me, json: { currentPassword: user.password, newPassword: user.password } });
    assert.strictEqual(same.status, 400);
    assert.strictEqual(same.body.code, 'SAME_PASSWORD');
    const weak = await api(app.base, 'POST', '/api/auth/password', { ...me, json: { currentPassword: user.password, newPassword: 'corta' } });
    assert.strictEqual(weak.status, 400);
    assert.strictEqual((await api(app.base, 'GET', '/api/auth/profile', { token: second.body.token, ip })).status, 200);

    const ok = await api(app.base, 'POST', '/api/auth/password', { ...me, json: { currentPassword: user.password, newPassword: 'Nueva-Contraseña-789' } });
    assert.strictEqual(ok.status, 200, ok.text);
    assert.strictEqual(ok.body.sessionsClosed, 1);
    assert.strictEqual((await api(app.base, 'GET', '/api/auth/profile', me)).status, 200, 'la sesión actual sigue');
    assert.strictEqual((await api(app.base, 'GET', '/api/auth/profile', { token: second.body.token, ip })).status, 401, 'la otra se cerró');
    assert.strictEqual((await login(user.username, user.password)).status, 401);
    assert.strictEqual((await login(user.username, 'Nueva-Contraseña-789')).status, 200);
});
