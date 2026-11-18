// Configuración en caliente (FASE 2): catálogo cerrado sin secretos, validación, cambios directos, cambios que reducen la
// seguridad (doble firma), restablecer al entorno, permisos y caché. MariaDB real.
//
//   node --test test/test_settings.js

const test = require('node:test');
const assert = require('node:assert');

require('./helpers/env');
const helpers = require('./helpers/app');
const { api, registerAndLogin, testIp } = helpers;
const runtimeSettings = require('../src/config/runtime-settings');

let app, db, enabled = false;

test.before(async () => {
    enabled = await helpers.prepareDatabase();
    if (!enabled) return;
    db = require('../src/config/database');
    app = await helpers.startApp();
});
test.after(async () => {
    if (!enabled) return;
    runtimeSettings.stop();
    await app.close();
    await db.pool.end();
});

const itDb = (name, fn) => test(name, async (t) => { if (!enabled) return t.skip('sin BD'); await fn(t); });
const REASON = 'Ajuste operativo acordado en el comité';

async function userWithRole(role) {
    const ip = testIp();
    const user = await registerAndLogin(app.base, { ip });
    if (role !== 'user') await db.query('UPDATE users SET role = ? WHERE id = ?', [role, user.userId]);
    return { ...user, ip, role };
}
const call = (user, method, route, json) => api(app.base, method, route, { token: user.token, ip: user.ip, json });
const put = (user, key, value, reason = REASON) => call(user, 'PUT', `/api/system/settings/${key}`, { value, reason });
const del = (user, key, reason = REASON) => call(user, 'DELETE', `/api/system/settings/${key}?reason=${encodeURIComponent(reason)}`);
const cleanup = async () => { for (const def of runtimeSettings.DEFINITIONS) await runtimeSettings.reset(def.key); };

// ============================================================================ puro

test('catálogo: 6-12 ajustes, claves únicas, sin secretos, claves ni opciones prohibidas', () => {
    const defs = runtimeSettings.DEFINITIONS;
    assert.ok(defs.length >= 6 && defs.length <= 12);
    assert.strictEqual(new Set(defs.map(d => d.key)).size, defs.length);
    const forbidden = /SECRET|PASSWORD|TOKEN|KEY|PEPPER|TLS|SSL|CORS|DISABLE_IP_BLOCKING|JWT|KMS|DB_/i;
    for (const def of defs) {
        assert.ok(!forbidden.test(def.envVar), `${def.envVar} no puede estar en el catálogo`);
        assert.ok(['int', 'bool', 'enum'].includes(def.type));
        assert.strictEqual(typeof def.weakens, 'function');
        assert.ok(def.label && def.group);
        assert.strictEqual(runtimeSettings.validate(def.key, def.default), def.default);
    }
});

test('validate: tipo estricto, rango y claves desconocidas', () => {
    assert.throws(() => runtimeSettings.validate('no.existe', 1), { code: 'UNKNOWN_SETTING' });
    assert.throws(() => runtimeSettings.validate('JWT_SECRET', 'x'), { code: 'UNKNOWN_SETTING' });
    assert.throws(() => runtimeSettings.validate('files.upload_max_image_mb', 0), { code: 'OUT_OF_RANGE' });
    assert.throws(() => runtimeSettings.validate('files.upload_max_image_mb', 9999), { code: 'OUT_OF_RANGE' });
    assert.throws(() => runtimeSettings.validate('files.upload_max_image_mb', '10'), { code: 'INVALID_VALUE' });
    assert.throws(() => runtimeSettings.validate('files.upload_max_image_mb', 1.5), { code: 'INVALID_VALUE' });
    assert.throws(() => runtimeSettings.validate('auth.mfa_required_privileged', 'true'), { code: 'INVALID_VALUE' });
    assert.throws(() => runtimeSettings.validate('files.image_sanitize', 'maybe'), { code: 'INVALID_VALUE' });
    assert.strictEqual(runtimeSettings.validate('files.image_sanitize', 'off'), 'off');
});

test('weakens: dirección de cada tipo de ajuste', () => {
    assert.strictEqual(runtimeSettings.isWeakening('auth.mfa_required_privileged', true, false), true);
    assert.strictEqual(runtimeSettings.isWeakening('auth.mfa_required_privileged', false, true), false);
    assert.strictEqual(runtimeSettings.isWeakening('files.upload_rate_per_min', 20, 50), true);
    assert.strictEqual(runtimeSettings.isWeakening('files.upload_rate_per_min', 20, 5), false);
    assert.strictEqual(runtimeSettings.isWeakening('security.events_max_per_minute', 30, 10), true);
    assert.strictEqual(runtimeSettings.isWeakening('alerts.notify_min_severity', 'high', 'critical'), true);
    assert.strictEqual(runtimeSettings.isWeakening('alerts.notify_min_severity', 'high', 'low'), false);
});

test('sin filas el valor es el del entorno o el defecto de siempre', () => {
    runtimeSettings.stop();
    const saved = process.env.UPLOAD_MAX_IMAGE_MB;
    try {
        delete process.env.UPLOAD_MAX_IMAGE_MB;
        assert.deepStrictEqual(runtimeSettings.envValue('files.upload_max_image_mb'), { value: 25, source: 'default' });
        process.env.UPLOAD_MAX_IMAGE_MB = '7';
        assert.deepStrictEqual(runtimeSettings.envValue('files.upload_max_image_mb'), { value: 7, source: 'env' });
        assert.strictEqual(runtimeSettings.get('files.upload_max_image_mb'), 7);
        assert.strictEqual(require('../src/files/storage').limits().perCategory.image, 7 * 1024 * 1024);
        process.env.UPLOAD_MAX_IMAGE_MB = 'basura';
        assert.strictEqual(runtimeSettings.get('files.upload_max_image_mb'), 25);
    } finally {
        if (saved === undefined) delete process.env.UPLOAD_MAX_IMAGE_MB; else process.env.UPLOAD_MAX_IMAGE_MB = saved;
    }
});

// ============================================================================ API

itDb('GET /settings: catálogo agrupado, sin secretos, con origen y límites', async () => {
    const admin = await userWithRole('admin');
    const res = await call(admin, 'GET', '/api/system/settings');
    assert.strictEqual(res.status, 200, res.text);
    const all = res.body.groups.flatMap(g => g.settings);
    assert.strictEqual(all.length, runtimeSettings.DEFINITIONS.length);
    for (const s of all) {
        assert.ok(['db', 'env', 'default'].includes(s.source));
        assert.ok(s.label && s.group);
        if (s.type === 'int') assert.ok(s.min < s.max);
        if (s.type === 'enum') assert.ok(Array.isArray(s.values));
    }
    assert.doesNotMatch(res.text, /JWT_SECRET|PASSWORD|DB_PASS|PEPPER|MASTER_KEY/i);
});

itDb('clave desconocida y valor inválido o fuera de rango: 400', async () => {
    const admin = await userWithRole('admin');
    assert.strictEqual((await put(admin, 'jwt_secret', 'x')).status, 400);
    assert.strictEqual((await put(admin, 'no.existe', 1)).status, 400);
    assert.strictEqual((await del(admin, 'no.existe')).status, 400);
    assert.strictEqual((await put(admin, 'files.upload_max_image_mb', 100000)).status, 400);
    assert.strictEqual((await put(admin, 'files.upload_max_image_mb', '5')).status, 400);
    assert.strictEqual((await put(admin, 'files.upload_max_image_mb', 5, 'corto')).status, 400);
    const noValue = await call(admin, 'PUT', '/api/system/settings/files.upload_max_image_mb', { reason: REASON });
    assert.strictEqual(noValue.status, 400);
    const [rows] = await db.query('SELECT COUNT(*) AS n FROM runtime_settings');
    assert.strictEqual(Number(rows[0].n), 0);
});

itDb('cambio que no debilita: 200, auditado, y el consumidor real lo usa de inmediato', async () => {
    const admin = await userWithRole('admin');
    const storage = require('../src/files/storage');
    const before = storage.limits().perCategory.image;

    const res = await put(admin, 'files.upload_max_image_mb', 3);
    assert.strictEqual(res.status, 200, res.text);
    assert.strictEqual(res.body.weakens, false);
    assert.strictEqual(res.body.value, 3);
    assert.strictEqual(storage.limits().perCategory.image, 3 * 1024 * 1024);
    assert.notStrictEqual(before, 3 * 1024 * 1024);

    const [rows] = await db.query('SELECT value_json, updated_by FROM runtime_settings WHERE setting_key = ?', ['files.upload_max_image_mb']);
    assert.strictEqual(JSON.parse(rows[0].value_json), 3);
    assert.strictEqual(Number(rows[0].updated_by), admin.userId);

    const [events] = await db.query("SELECT details FROM security_events WHERE event_type = 'SETTING_CHANGED' ORDER BY id DESC LIMIT 1");
    const details = typeof events[0].details === 'string' ? JSON.parse(events[0].details) : events[0].details;
    assert.strictEqual(details.key, 'files.upload_max_image_mb');
    assert.strictEqual(details.to, 3);
    assert.strictEqual(details.from, before / 1024 / 1024);

    const list = await call(admin, 'GET', '/api/system/settings');
    const item = list.body.groups.flatMap(g => g.settings).find(s => s.key === 'files.upload_max_image_mb');
    assert.strictEqual(item.value, 3);
    assert.strictEqual(item.source, 'db');
    assert.strictEqual(item.updatedBy.id, admin.userId);
    await cleanup();
});

itDb('límite de subidas por minuto: bajarlo (200) surte efecto en la ruta real al instante', async () => {
    const admin = await userWithRole('admin');
    const user = await userWithRole('user');
    assert.strictEqual((await put(admin, 'files.upload_rate_per_min', 1)).status, 200);
    const first = await call(user, 'POST', '/api/files', undefined);
    assert.notStrictEqual(first.status, 429);
    const second = await call(user, 'POST', '/api/files', undefined);
    assert.strictEqual(second.status, 429, second.text);
    assert.strictEqual(second.body.code, 'UPLOAD_RATE_LIMITED');
    await cleanup();
});

itDb('MFA obligatorio: activarlo (no debilita, 200) lo exige el middleware de roles de inmediato', async () => {
    const admin = await userWithRole('admin');
    const res = await put(admin, 'auth.mfa_required_privileged', true);
    assert.strictEqual(res.status, 200, res.text);
    const blocked = await call(admin, 'GET', '/api/system/settings');
    assert.strictEqual(blocked.status, 403);
    assert.strictEqual(blocked.body.code, 'MFA_REQUIRED');
    await runtimeSettings.reset('auth.mfa_required_privileged'); // restablecer es cosa del operador de la BD: él mismo ya no entra
    assert.strictEqual((await call(admin, 'GET', '/api/system/settings')).status, 200);
});

itDb('cambio que debilita: 202 pendiente, el mismo admin no aprueba, otro sí y se aplica', async () => {
    const a = await userWithRole('admin');
    const b = await userWithRole('admin');
    assert.strictEqual(runtimeSettings.get('files.image_sanitize'), 'on');

    const req = await put(a, 'files.image_sanitize', 'off');
    assert.strictEqual(req.status, 202, req.text);
    assert.strictEqual(req.body.status, 'pending');
    assert.strictEqual(req.body.weakens, true);
    assert.strictEqual(runtimeSettings.get('files.image_sanitize'), 'on'); // todavía no
    const [pending] = await db.query("SELECT action, params FROM admin_approvals WHERE id = ?", [req.body.approvalId]);
    assert.strictEqual(pending[0].action, 'settings_change');
    assert.deepStrictEqual(JSON.parse(pending[0].params), { key: 'files.image_sanitize', value: 'off', from: 'on' });

    const own = await call(a, 'POST', `/api/system/approvals/${req.body.approvalId}/approve`);
    assert.strictEqual(own.status, 403, own.text);
    assert.strictEqual(own.body.code, 'SELF_APPROVAL');
    assert.strictEqual(runtimeSettings.get('files.image_sanitize'), 'on');

    const ok = await call(b, 'POST', `/api/system/approvals/${req.body.approvalId}/approve`);
    assert.strictEqual(ok.status, 200, ok.text);
    assert.strictEqual(runtimeSettings.get('files.image_sanitize'), 'off');
    assert.strictEqual(runtimeSettings.source('files.image_sanitize'), 'db');

    // restablecer: volver a "on" (entorno) NO debilita: se aplica ya
    const reset = await del(a, 'files.image_sanitize');
    assert.strictEqual(reset.status, 200, reset.text);
    assert.strictEqual(runtimeSettings.get('files.image_sanitize'), 'on');
    assert.strictEqual(runtimeSettings.source('files.image_sanitize'), 'default');
    const again = await del(a, 'files.image_sanitize');
    assert.strictEqual(again.status, 409);
    await cleanup();
});

itDb('«¿debilita?» se decide con el valor REAL de la BD, no con la caché de esta réplica', async () => {
    const a = await userWithRole('admin');
    const key = 'files.upload_rate_per_min';
    await runtimeSettings.set(key, 100);                   // base conocida (el entorno de pruebas puede traer otro valor)
    const cached = runtimeSettings.get(key);
    // Otra réplica lo endurece directamente en la BD; la caché de este proceso aún no lo sabe
    const hardened = 20;
    await db.query('INSERT INTO runtime_settings (setting_key, value_json, updated_by) VALUES (?, ?, NULL) ON DUPLICATE KEY UPDATE value_json = VALUES(value_json)', [key, JSON.stringify(hardened)]);
    assert.strictEqual(runtimeSettings.get(key), cached, 'la caché sigue con el valor viejo');
    // Frente a la caché, cached - 1 «endurece»; frente al valor real (hardened) es SUBIRLO: debe pedir la segunda firma
    const res = await put(a, key, cached - 1);
    assert.strictEqual(res.status, 202, res.text);
    assert.strictEqual(res.body.weakens, true);
    await cleanup();
});

itDb('una aprobación obsoleta no revierte un endurecimiento posterior: falla con STALE_REQUEST', async () => {
    const a = await userWithRole('admin');
    const b = await userWithRole('admin');
    const key = 'files.upload_rate_per_min';
    await runtimeSettings.set(key, 100);                   // base conocida
    const start = runtimeSettings.get(key);
    const up = await put(a, key, start + 10);              // debilita: pendiente
    assert.strictEqual(up.status, 202, up.text);
    const down = await put(a, key, start - 2);             // mientras tanto se endurece (directo)
    assert.strictEqual(down.status, 200, down.text);
    const approve = await call(b, 'POST', `/api/system/approvals/${up.body.approvalId}/approve`);
    assert.strictEqual(approve.status, 409, approve.text);
    assert.strictEqual(approve.body.code, 'STALE_REQUEST');
    assert.strictEqual(runtimeSettings.get(key), start - 2, 'se mantiene el valor endurecido');
    const [row] = await db.query('SELECT status FROM admin_approvals WHERE id = ?', [up.body.approvalId]);
    assert.strictEqual(row[0].status, 'failed');
    await cleanup();
});

itDb('restablecer al entorno que debilita: también exige aprobación', async () => {
    const a = await userWithRole('admin');
    const b = await userWithRole('admin');
    assert.strictEqual((await put(a, 'files.upload_rate_per_min', 2)).status, 200); // el entorno de pruebas vale 100000
    const reset = await del(a, 'files.upload_rate_per_min');
    assert.strictEqual(reset.status, 202, reset.text);
    assert.strictEqual(runtimeSettings.get('files.upload_rate_per_min'), 2);
    const [pending] = await db.query('SELECT params FROM admin_approvals WHERE id = ?', [reset.body.approvalId]);
    assert.deepStrictEqual(JSON.parse(pending[0].params), { key: 'files.upload_rate_per_min', reset: true, from: 2 });
    assert.strictEqual((await call(b, 'POST', `/api/system/approvals/${reset.body.approvalId}/approve`)).status, 200);
    assert.strictEqual(runtimeSettings.get('files.upload_rate_per_min'), Number(process.env.UPLOAD_RATE_PER_MIN));
    assert.strictEqual(runtimeSettings.source('files.upload_rate_per_min'), 'env');
    await cleanup();
});

itDb('mismo valor: 409; no-admin (user, auditor, operator): 403', async () => {
    const admin = await userWithRole('admin');
    assert.strictEqual((await put(admin, 'files.image_sanitize', 'on')).status, 409);
    for (const role of ['user', 'auditor', 'operator']) {
        const u = await userWithRole(role);
        assert.strictEqual((await call(u, 'GET', '/api/system/settings')).status, 403, role);
        assert.strictEqual((await put(u, 'files.upload_max_image_mb', 5)).status, 403, role);
        assert.strictEqual((await del(u, 'files.upload_max_image_mb')).status, 403, role);
    }
    const anon = await api(app.base, 'GET', '/api/system/settings', { ip: testIp() });
    assert.strictEqual(anon.status, 401);
    const [rows] = await db.query('SELECT COUNT(*) AS n FROM runtime_settings');
    assert.strictEqual(Number(rows[0].n), 0);
});

// ============================================================================ caché

itDb('caché: tras escribir, get devuelve el nuevo valor en el mismo proceso', async () => {
    await runtimeSettings.set('files.download_rate_per_min', 77);
    assert.strictEqual(runtimeSettings.get('files.download_rate_per_min'), 77);
    await runtimeSettings.reset('files.download_rate_per_min');
    assert.strictEqual(runtimeSettings.get('files.download_rate_per_min'), runtimeSettings.envValue('files.download_rate_per_min').value);
});

itDb('caché: otra réplica escribe en la BD y este proceso converge tras el TTL, sin reiniciar', async () => {
    const savedTtl = process.env.SETTINGS_CACHE_TTL_MS;
    process.env.SETTINGS_CACHE_TTL_MS = '50';
    try {
        await runtimeSettings.start();
        const before = runtimeSettings.get('security.events_max_per_minute');
        await db.query("INSERT INTO runtime_settings (setting_key, value_json) VALUES ('security.events_max_per_minute', '41')");
        assert.strictEqual(runtimeSettings.get('security.events_max_per_minute'), before); // aún cacheado
        await new Promise(resolve => setTimeout(resolve, 120));
        runtimeSettings.get('security.events_max_per_minute'); // dispara el refresco en segundo plano
        await new Promise(resolve => setTimeout(resolve, 200));
        assert.strictEqual(runtimeSettings.get('security.events_max_per_minute'), 41);

        // fila corrupta o fuera de rango: se ignora
        await db.query("UPDATE runtime_settings SET value_json = '999999' WHERE setting_key = 'security.events_max_per_minute'");
        await runtimeSettings.refresh();
        assert.strictEqual(runtimeSettings.get('security.events_max_per_minute'), before);
    } finally {
        if (savedTtl === undefined) delete process.env.SETTINGS_CACHE_TTL_MS; else process.env.SETTINGS_CACHE_TTL_MS = savedTtl;
        runtimeSettings.stop();
        await cleanup();
    }
});
