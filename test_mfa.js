// Pruebas de MFA (TOTP + códigos de recuperación), contra MySQL/MariaDB real.
//
//   npm run test:mfa

const test = require('node:test');
const assert = require('node:assert');
const jwt = require('jsonwebtoken');

require('./test_helpers/env');
const helpers = require('./test_helpers/app');
const { api, registerAndLogin, testIp, PASSWORD } = helpers;
const totp = require('./src/security/totp');

const nextStepCode = (secret) => totp.totp(secret, { timeMs: Date.now() + 30_000 }); // el paso siguiente (> último aceptado)

// ============================================================================ TOTP (puro): vectores del RFC 6238

test('TOTP: coincide con los vectores de prueba del RFC 6238 (SHA-1)', () => {
    const secret = totp.base32Encode(Buffer.from('12345678901234567890'));
    const vectors = { 59: '94287082', 1111111109: '07081804', 1111111111: '14050471', 1234567890: '89005924', 2000000000: '69279037', 20000000000: '65353130' };
    for (const [seconds, expected] of Object.entries(vectors)) {
        assert.strictEqual(totp.totp(secret, { timeMs: seconds * 1000, digits: 8 }), expected, `t=${seconds}`);
    }
});

test('HOTP: vectores del RFC 4226', () => {
    const secret = totp.base32Encode(Buffer.from('12345678901234567890'));
    ['755224', '287082', '359152', '969429', '338314', '254676', '287922', '162583', '399871', '520489']
        .forEach((expected, counter) => assert.strictEqual(totp.hotp(secret, counter), expected));
});

test('base32: ida y vuelta y rechazo de caracteres inválidos', () => {
    for (const text of ['', 'f', 'fo', 'foo', 'foob', 'fooba', 'foobar']) {
        assert.strictEqual(totp.base32Decode(totp.base32Encode(Buffer.from(text))).toString(), text);
    }
    assert.strictEqual(totp.base32Encode(Buffer.from('foobar')), 'MZXW6YTBOI');
    assert.throws(() => totp.base32Decode('AB1!'));
});

test('TOTP: ventana de ±1 paso, anti-reutilización y formato estricto', () => {
    const secret = totp.generateSecret();
    const now = 1_700_000_000_000;
    const at = (delta) => totp.totp(secret, { timeMs: now + delta * 30_000 });

    assert.ok(totp.verifyTotp(secret, at(0), { timeMs: now }).ok);
    assert.ok(totp.verifyTotp(secret, at(-1), { timeMs: now }).ok, 'desfase de -30 s');
    assert.ok(totp.verifyTotp(secret, at(1), { timeMs: now }).ok, 'desfase de +30 s');
    assert.ok(!totp.verifyTotp(secret, at(2), { timeMs: now }).ok, 'fuera de la ventana');
    assert.ok(!totp.verifyTotp(secret, at(-2), { timeMs: now }).ok);

    const first = totp.verifyTotp(secret, at(0), { timeMs: now });
    const replay = totp.verifyTotp(secret, at(0), { timeMs: now, lastStep: first.step });
    assert.deepStrictEqual([replay.ok, replay.replay], [false, true], 'el mismo paso no se acepta dos veces');
    assert.ok(!totp.verifyTotp(secret, at(-1), { timeMs: now, lastStep: first.step }).ok, 'ni uno anterior');

    for (const bad of ['', '12345', '1234567', 'abcdef', '12 456', null, undefined, 123456]) {
        assert.ok(!totp.verifyTotp(secret, bad, { timeMs: now }).ok, String(bad));
    }
});

test('códigos de recuperación: formato, entropía y normalización', () => {
    const codes = new Set(Array.from({ length: 200 }, () => totp.generateRecoveryCode()));
    assert.strictEqual(codes.size, 200);
    for (const code of codes) assert.match(code, /^[A-Z2-7]{4}(-[A-Z2-7]{4}){3}$/);
    const code = [...codes][0];
    assert.strictEqual(totp.hashRecoveryCode(code), totp.hashRecoveryCode(code.toLowerCase().replace(/-/g, ' ')));
    assert.notStrictEqual(totp.hashRecoveryCode(code), totp.hashRecoveryCode([...codes][1]));
});

// ============================================================================ INTEGRACIÓN

let dbAvailable = false;
let app;
let db;

test.before(async () => {
    dbAvailable = await helpers.prepareDatabase();
    if (!dbAvailable) return;
    db = require('./src/config/database');
    app = await helpers.startApp();
});
test.after(async () => {
    if (app) await app.close();
    if (db?.pool) await db.pool.end();
});

const itDb = (name, fn) => test(name, async (t) => {
    if (!dbAvailable) return t.skip('sin base de datos');
    await fn(t);
});

// Crea un usuario con MFA ya activado. Devuelve su secreto y sus códigos de recuperación.
async function userWithMfa() {
    const ip = testIp();
    const user = await registerAndLogin(app.base, { ip });
    const setup = await api(app.base, 'POST', '/api/auth/mfa/setup', { ip, token: user.token });
    assert.strictEqual(setup.status, 200);
    const enable = await api(app.base, 'POST', '/api/auth/mfa/enable', { ip, token: user.token, json: { otp: totp.totp(setup.body.secret) } });
    assert.strictEqual(enable.status, 200, enable.text);
    return { ...user, ip, secret: setup.body.secret, recoveryCodes: enable.body.recoveryCodes };
}

const loginStep1 = (user, ip = user.ip) => api(app.base, 'POST', '/api/auth/login', { ip, json: { username: user.username, password: user.password } });
const loginStep2 = (mfaToken, body, ip) => api(app.base, 'POST', '/api/auth/login/mfa', { ip, json: { mfaToken, ...body } });

itDb('alta: setup devuelve secreto, otpauth y QR; enable exige un código válido y entrega 10 códigos de recuperación', async () => {
    const ip = testIp();
    const user = await registerAndLogin(app.base, { ip });
    assert.deepStrictEqual((await api(app.base, 'GET', '/api/auth/mfa', { ip, token: user.token })).body.mfa, { enabled: false, totp: false, passkeys: 0, pendingSetup: false, recoveryCodesRemaining: 0 });

    const setup = await api(app.base, 'POST', '/api/auth/mfa/setup', { ip, token: user.token });
    assert.strictEqual(setup.status, 200);
    assert.match(setup.body.secret, /^[A-Z2-7]{32}$/);
    assert.match(setup.body.otpauthUrl, /^otpauth:\/\/totp\/.+secret=[A-Z2-7]{32}&issuer=/);
    assert.match(setup.body.qrDataUrl, /^data:image\/png;base64,/);
    assert.strictEqual((await api(app.base, 'GET', '/api/auth/mfa', { ip, token: user.token })).body.mfa.pendingSetup, true);

    // sin activar todavía: el login no pide MFA
    assert.strictEqual((await loginStep1({ ...user, ip })).body.mfaRequired, undefined);

    const wrong = await api(app.base, 'POST', '/api/auth/mfa/enable', { ip, token: user.token, json: { otp: '000000' } });
    assert.strictEqual(wrong.status, 401);
    assert.strictEqual(wrong.body.code, 'INVALID_OTP');
    assert.strictEqual((await api(app.base, 'POST', '/api/auth/mfa/enable', { ip, token: user.token, json: { otp: 'abc' } })).status, 400);

    const ok = await api(app.base, 'POST', '/api/auth/mfa/enable', { ip, token: user.token, json: { otp: totp.totp(setup.body.secret) } });
    assert.strictEqual(ok.status, 200);
    assert.strictEqual(ok.body.recoveryCodes.length, 10);
    assert.strictEqual(new Set(ok.body.recoveryCodes).size, 10);

    assert.deepStrictEqual((await api(app.base, 'GET', '/api/auth/mfa', { ip, token: user.token })).body.mfa, { enabled: true, totp: true, passkeys: 0, pendingSetup: false, recoveryCodesRemaining: 10 });
    assert.strictEqual((await api(app.base, 'POST', '/api/auth/mfa/setup', { ip, token: user.token })).status, 409, 'no se puede re-iniciar con MFA activo');
    assert.strictEqual((await api(app.base, 'POST', '/api/auth/mfa/enable', { ip, token: user.token, json: { otp: totp.totp(setup.body.secret) } })).status, 409);

    // En BD: secreto cifrado v4 (nunca en claro) y códigos solo como hash
    const [[row]] = await db.query('SELECT mfa_secret_encrypted, mfa_enabled, mfa_last_step FROM users WHERE id = ?', [user.userId]);
    assert.ok(row.mfa_secret_encrypted.startsWith('v4:') && !row.mfa_secret_encrypted.includes(setup.body.secret));
    assert.strictEqual(row.mfa_enabled, 1);
    assert.ok(row.mfa_last_step > 0);
    const [hashes] = await db.query('SELECT code_hash FROM user_recovery_codes WHERE user_id = ?', [user.userId]);
    assert.ok(hashes.every(h => /^[0-9a-f]{64}$/.test(h.code_hash) && !ok.body.recoveryCodes.some(c => h.code_hash.includes(c))));
});

itDb('login con MFA: la contraseña sola NO da sesión; con el código sí; y el reto no sirve como sesión', async () => {
    const user = await userWithMfa();

    const step1 = await loginStep1(user);
    assert.strictEqual(step1.status, 200);
    assert.strictEqual(step1.body.mfaRequired, true);
    assert.ok(step1.body.mfaToken && !step1.body.token, 'no hay token de sesión todavía');

    // el reto no vale como Bearer
    assert.strictEqual((await api(app.base, 'GET', '/api/notes', { ip: user.ip, token: step1.body.mfaToken })).status, 401);
    // ni una sesión válida vale como reto
    assert.strictEqual((await loginStep2(user.token, { otp: nextStepCode(user.secret) }, user.ip)).body.code, 'INVALID_MFA_TOKEN');

    const step2 = await loginStep2(step1.body.mfaToken, { otp: nextStepCode(user.secret) }, user.ip);
    assert.strictEqual(step2.status, 200, step2.text);
    assert.deepStrictEqual(step2.body.authMethods, ['pwd', 'otp']);
    assert.strictEqual((await api(app.base, 'GET', '/api/notes', { ip: user.ip, token: step2.body.token })).status, 200);
});

itDb('un código no se puede reutilizar, ni siquiera 5 peticiones simultáneas con el mismo código', async () => {
    const user = await userWithMfa();
    const code = nextStepCode(user.secret);

    const tokens = await Promise.all(Array.from({ length: 5 }, async () => (await loginStep1(user)).body.mfaToken));
    const results = await Promise.all(tokens.map(token => loginStep2(token, { otp: code }, user.ip)));
    assert.strictEqual(results.filter(r => r.status === 200).length, 1, 'solo una gana la carrera (UPDATE atómico del paso)');
    assert.strictEqual(results.filter(r => r.status === 401).length, 4);

    const again = await loginStep2((await loginStep1(user)).body.mfaToken, { otp: code }, user.ip);
    assert.strictEqual(again.status, 401);
    // el código usado al ACTIVAR tampoco vale
    assert.strictEqual((await loginStep2((await loginStep1(user)).body.mfaToken, { otp: totp.totp(user.secret) }, user.ip)).status, 401);
});

itDb('los códigos TOTP incorrectos cuentan para el bloqueo y acertar la contraseña NO reinicia el contador', async () => {
    const user = await userWithMfa();
    const attacker = testIp();

    // El atacante conoce la contraseña y prueba códigos. Cada vuelta por el paso 1 NO reinicia los fallos.
    for (let i = 0; i < 5; i++) {
        const challenge = await loginStep1(user, attacker);
        assert.strictEqual(challenge.status, 200, `paso 1 (vuelta ${i})`);
        const bad = await loginStep2(challenge.body.mfaToken, { otp: '000000' }, attacker);
        assert.strictEqual(bad.status, 401, `vuelta ${i}`);
    }
    const locked = await loginStep1(user, attacker);
    assert.strictEqual(locked.status, 429);
    assert.strictEqual(locked.body.code, 'ACCOUNT_LOCKED');

    // El dueño, desde su IP, sigue entrando
    const challenge = await loginStep1(user);
    assert.strictEqual((await loginStep2(challenge.body.mfaToken, { otp: nextStepCode(user.secret) }, user.ip)).status, 200);

    const [rules] = await db.query("SELECT COUNT(*) AS n FROM security_events WHERE event_type = 'LOGIN_FAILED' AND rule = 'BAD_MFA_CODE' AND ip_address = ?", [attacker]);
    assert.strictEqual(rules[0].n, 5);
});

itDb('códigos de recuperación: valen una vez, se descuentan y quedan registrados', async () => {
    const user = await userWithMfa();
    const [first, second] = user.recoveryCodes;

    const a = await loginStep2((await loginStep1(user)).body.mfaToken, { recoveryCode: first.toLowerCase() }, user.ip);
    assert.strictEqual(a.status, 200, 'minúsculas también');
    assert.deepStrictEqual(a.body.authMethods, ['pwd', 'recovery']);

    assert.strictEqual((await loginStep2((await loginStep1(user)).body.mfaToken, { recoveryCode: first }, user.ip)).status, 401, 'ya usado');
    assert.strictEqual((await loginStep2((await loginStep1(user)).body.mfaToken, { recoveryCode: second }, user.ip)).status, 200);
    assert.strictEqual((await api(app.base, 'GET', '/api/auth/mfa', { ip: user.ip, token: a.body.token })).body.mfa.recoveryCodesRemaining, 8);

    const [trail] = await db.query("SELECT COUNT(*) AS n FROM security_events WHERE event_type = 'MFA_RECOVERY_CODE_USED' AND user_id = ?", [user.userId]);
    assert.strictEqual(trail[0].n, 2);
});

itDb('retos manipulados, de otra clave o caducados → 401 INVALID_MFA_TOKEN', async () => {
    const user = await userWithMfa();
    const credentialBuilder = require('./src/config/credential-builder');
    const secret = credentialBuilder.generateJWTSecret();
    const payload = { typ: 'mfa', userId: user.userId, username: user.username, uh: 'x'.repeat(64) };

    const real = (await loginStep1(user)).body.mfaToken;
    const [h, p, s] = real.split('.');
    const forged = {
        'firma ajena': jwt.sign(payload, 'otra-clave', { algorithm: 'HS256', expiresIn: 300 }),
        'caducado': jwt.sign(payload, secret, { algorithm: 'HS256', expiresIn: -5 }),
        'alg none': `${Buffer.from('{"alg":"none"}').toString('base64url')}.${p}.`,
        'payload alterado': `${h}.${Buffer.from(JSON.stringify({ ...JSON.parse(Buffer.from(p, 'base64url')), userId: 1 })).toString('base64url')}.${s}`,
        'sin typ=mfa': jwt.sign({ userId: user.userId }, secret, { algorithm: 'HS256', expiresIn: 300 }),
        'basura': 'no-es-un-jwt'
    };
    for (const [name, token] of Object.entries(forged)) {
        const r = await loginStep2(token, { otp: nextStepCode(user.secret) }, testIp());
        assert.strictEqual(r.status, 401, name);
        assert.strictEqual(r.body.code, 'INVALID_MFA_TOKEN', name);
    }
});

itDb('formato: otp y recoveryCode se validan antes de tocar nada', async () => {
    const ip = testIp();
    for (const body of [{}, { otp: '12345' }, { otp: '1234567' }, { otp: 'abcdef' }, { recoveryCode: '!!' }, { otp: 123456 }]) {
        const r = await loginStep2('x', body, ip);
        assert.ok([400].includes(r.status), `${JSON.stringify(body)} → ${r.status}`);
    }
});

itDb('desactivar y regenerar códigos exigen contraseña Y segundo factor (una sesión robada no basta)', async () => {
    const user = await userWithMfa();
    const session = (await loginStep2((await loginStep1(user)).body.mfaToken, { otp: nextStepCode(user.secret) }, user.ip)).body.token;
    const call = (route, body) => api(app.base, 'POST', route, { ip: user.ip, token: session, json: body });

    assert.strictEqual((await call('/api/auth/mfa/disable', { password: 'incorrecta', recoveryCode: user.recoveryCodes[0] })).status, 401);
    assert.strictEqual((await call('/api/auth/mfa/disable', { password: user.password, otp: '000000' })).status, 401);
    assert.strictEqual((await call('/api/auth/mfa/disable', { password: user.password })).status, 401, 'sin segundo factor');
    assert.strictEqual((await api(app.base, 'GET', '/api/auth/mfa', { ip: user.ip, token: session })).body.mfa.enabled, true);

    // regenerar: los códigos anteriores dejan de valer
    const regenerated = await call('/api/auth/mfa/recovery-codes', { password: user.password, recoveryCode: user.recoveryCodes[1] });
    assert.strictEqual(regenerated.status, 200);
    assert.strictEqual(regenerated.body.recoveryCodes.length, 10);
    assert.strictEqual((await loginStep2((await loginStep1(user)).body.mfaToken, { recoveryCode: user.recoveryCodes[2] }, user.ip)).status, 401, 'código antiguo');
    assert.strictEqual((await loginStep2((await loginStep1(user)).body.mfaToken, { recoveryCode: regenerated.body.recoveryCodes[0] }, user.ip)).status, 200);

    const off = await call('/api/auth/mfa/disable', { password: user.password, recoveryCode: regenerated.body.recoveryCodes[1] });
    assert.strictEqual(off.status, 200);
    assert.strictEqual((await loginStep1(user)).body.mfaRequired, undefined, 'sin MFA el login vuelve a ser directo');
    const [[row]] = await db.query('SELECT mfa_secret_encrypted, mfa_enabled FROM users WHERE id = ?', [user.userId]);
    assert.deepStrictEqual([row.mfa_secret_encrypted, row.mfa_enabled], [null, 0]);
    assert.strictEqual((await db.query('SELECT 1 FROM user_recovery_codes WHERE user_id = ?', [user.userId]))[0].length, 0);
});

itDb('admins: con MFA_REQUIRED_FOR_ADMINS solo operan con segundo factor; y un admin puede reiniciar el MFA de otro', async () => {
    const saved = process.env.MFA_REQUIRED_FOR_ADMINS;
    const savedApprovals = process.env.ADMIN_APPROVALS_REQUIRED;
    process.env.MFA_REQUIRED_FOR_ADMINS = 'true';
    process.env.ADMIN_APPROVALS_REQUIRED = '1'; // la aprobación de dos admins se prueba en test_rbac.js
    try {
        const ip = testIp();
        const adminPwdOnly = await registerAndLogin(app.base, { ip });
        await db.query("UPDATE users SET role = 'admin' WHERE id = ?", [adminPwdOnly.userId]);
        const denied = await api(app.base, 'GET', '/api/system/blocked-ips', { ip, token: adminPwdOnly.token });
        assert.strictEqual(denied.status, 403);
        assert.strictEqual(denied.body.code, 'MFA_REQUIRED');

        const admin = await userWithMfa();
        await db.query("UPDATE users SET role = 'admin' WHERE id = ?", [admin.userId]);
        const session = (await loginStep2((await loginStep1(admin)).body.mfaToken, { otp: nextStepCode(admin.secret) }, admin.ip)).body.token;
        assert.strictEqual((await api(app.base, 'GET', '/api/system/blocked-ips', { ip: admin.ip, token: session })).status, 200);

        // dispositivo perdido y sin códigos: el admin reinicia el MFA de otro usuario
        const lost = await userWithMfa();
        const reset = await api(app.base, 'POST', '/api/system/accounts/mfa-reset', { ip: admin.ip, token: session, json: { username: lost.username, reason: 'Dispositivo perdido y sin códigos de recuperación' } });
        assert.strictEqual(reset.status, 200);
        assert.strictEqual((await loginStep1(lost)).body.mfaRequired, undefined);
        assert.strictEqual((await api(app.base, 'POST', '/api/system/accounts/mfa-reset', { ip: admin.ip, token: session, json: { username: 'no-existe-' + Date.now(), reason: 'Dispositivo perdido y sin códigos de recuperación' } })).status, 404);
        assert.strictEqual((await api(app.base, 'POST', '/api/system/accounts/mfa-reset', { ip: lost.ip, token: (await loginStep1(lost).then(r => registerAndLogin(app.base, { ip: lost.ip }))).token, json: { username: lost.username } })).status, 403);
    } finally {
        if (saved === undefined) delete process.env.MFA_REQUIRED_FOR_ADMINS; else process.env.MFA_REQUIRED_FOR_ADMINS = saved;
        if (savedApprovals === undefined) delete process.env.ADMIN_APPROVALS_REQUIRED; else process.env.ADMIN_APPROVALS_REQUIRED = savedApprovals;
    }
});

itDb('la rotación de claves re-cifra el secreto TOTP y el usuario sigue entrando', async () => {
    const enc = require('./src/crypto/tripleEncryptor');
    const secureEnv = require('./src/config/secure-env');
    const user = await userWithMfa();
    const [[before]] = await db.query('SELECT mfa_secret_encrypted FROM users WHERE id = ?', [user.userId]);

    const oldKey = secureEnv.getSecret('encryption');
    const newKey = require('crypto').randomBytes(32).toString('hex');
    const rewrapped = enc.withKey(newKey, () => enc.encrypt(enc.withKey(oldKey, () => enc.decrypt(before.mfa_secret_encrypted))));
    await db.query('UPDATE users SET mfa_secret_encrypted = ? WHERE id = ?', [rewrapped, user.userId]);

    // El paso 1 lee otros campos (cifrados con la clave antigua en esta simulación parcial): se hace antes del cambio
    const challenge = (await loginStep1(user)).body.mfaToken;
    const original = enc.getKey;
    enc.getKey = () => newKey;
    try {
        const step2 = await loginStep2(challenge, { otp: nextStepCode(user.secret) }, user.ip);
        assert.strictEqual(step2.status, 200, step2.text);
    } finally { enc.getKey = original; }
});
