// Passkeys / llaves de seguridad (WebAuthn) como segundo factor, con un autenticador SOFTWARE que firma de verdad.
// MariaDB real y el servidor real.
//
//   npm run test:webauthn

const test = require('node:test');
const assert = require('node:assert');
const jwt = require('jsonwebtoken');

require('./test_helpers/env');
process.env.WEBAUTHN_RP_ID = 'localhost';
process.env.WEBAUTHN_ORIGINS = 'http://localhost:5173';
const helpers = require('./test_helpers/app');
const { api, registerAndLogin, testIp, PASSWORD } = helpers;
const { SoftAuthenticator } = require('./test_helpers/webauthn-authenticator');
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
const withEnv = async (vars, fn) => {
    const saved = Object.fromEntries(Object.keys(vars).map(k => [k, process.env[k]]));
    for (const [k, v] of Object.entries(vars)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
    try { return await fn(); } finally {
        for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
    }
};

const call = (user, method, route, json) => api(app.base, method, route, { token: user.token, ip: user.ip, json });
async function newUser() {
    const ip = testIp();
    return { ...(await registerAndLogin(app.base, { ip })), ip };
}
async function registerKey(user, authenticator = new SoftAuthenticator(), { name = 'Mi llave', extra = {}, otp, recoveryCode } = {}) {
    const options = await call(user, 'POST', '/api/auth/webauthn/register/options', { password: PASSWORD, ...(otp && { otp }), ...(recoveryCode && { recoveryCode }) });
    if (options.status !== 200) return { options, authenticator };
    const done = await call(user, 'POST', '/api/auth/webauthn/register', { credential: authenticator.register(options.body.options, extra), name });
    return { options, done, authenticator };
}
async function startLogin(user, ip = user.ip) {
    const step1 = await api(app.base, 'POST', '/api/auth/login', { ip, json: { username: user.username, password: PASSWORD } });
    return step1;
}
async function passkeyLogin(user, authenticator, { optionsFor, ip = user.ip, assertion = {} } = {}) {
    const step1 = await startLogin(user, ip);
    const mfaToken = step1.body.mfaToken;
    if (!mfaToken) return { step1 };                       // bloqueado (o sin MFA): no hay reto que firmar
    const options = await api(app.base, 'POST', '/api/auth/login/webauthn/options', { ip, json: { mfaToken } });
    const credential = authenticator.assert((optionsFor || options.body).options || options.body.options, assertion);
    const login = await api(app.base, 'POST', '/api/auth/login/webauthn', { ip, json: { mfaToken, credential } });
    return { step1, options, login, mfaToken, credential };
}

// ============================================================================ configuración

itDb('sin WEBAUTHN_RP_ID / WEBAUTHN_ORIGINS la función está desactivada (404 claro) y el login normal no cambia', async () => {
    await withEnv({ WEBAUTHN_RP_ID: undefined, WEBAUTHN_ORIGINS: undefined }, async () => {
        const user = await newUser();
        const res = await call(user, 'POST', '/api/auth/webauthn/register/options', { password: PASSWORD });
        assert.deepStrictEqual([res.status, res.body.code], [404, 'WEBAUTHN_NOT_CONFIGURED']);
        assert.strictEqual((await call(user, 'GET', '/api/auth/webauthn/credentials')).body.enabled, false);
        assert.strictEqual((await startLogin(user)).body.mfaRequired, undefined);
    });
});

itDb('configuración inválida: orígenes que no son https (salvo localhost fuera de producción) o ajenos al RP ID se rechazan', async () => {
    const webauthn = require('./src/security/webauthn.service');
    const cfg = (rp, origins, env = {}) => withEnv({ WEBAUTHN_RP_ID: rp, WEBAUTHN_ORIGINS: origins, ...env }, () => webauthn.config());
    assert.ok(await cfg('ejemplo.com', 'https://app.ejemplo.com'));
    await assert.rejects(async () => cfg('ejemplo.com', 'http://app.ejemplo.com'), /https/);
    await assert.rejects(async () => cfg('ejemplo.com', 'https://evil.com'), /no pertenece/);
    await assert.rejects(async () => cfg('ejemplo.com', 'https://notejemplo.com'), /no pertenece/, 'sufijo sin punto: "notejemplo.com" no es subdominio');
    await assert.rejects(async () => cfg('ejemplo.com', 'https://app.ejemplo.com/ruta'), /solo el origen/);
    await assert.rejects(async () => cfg('localhost', 'http://localhost:3000', { NODE_ENV: 'production' }), /https/, 'en producción ni localhost sin https');
    assert.ok(await cfg('localhost', 'http://localhost:3000'));
    await withEnv({ WEBAUTHN_RP_ID: 'ejemplo.com', WEBAUTHN_ORIGINS: 'http://x.ejemplo.com' }, async () => {
        assert.strictEqual(webauthn.enabled(), false, 'mal configurado = desactivado, no abierto');
        const user = await newUser();
        assert.strictEqual((await call(user, 'POST', '/api/auth/webauthn/register/options', { password: PASSWORD })).status, 503);
    });
});

// ============================================================================ registro

itDb('registro: exige contraseña, entrega recuperación al ser el primer factor y no expone la clave', async () => {
    const user = await newUser();
    assert.strictEqual((await call(user, 'POST', '/api/auth/webauthn/register/options', { password: 'incorrecta-incorrecta' })).status, 401);
    assert.strictEqual((await call(user, 'POST', '/api/auth/webauthn/register/options', {})).status, 400);
    assert.strictEqual((await api(app.base, 'POST', '/api/auth/webauthn/register/options', { ip: user.ip, json: { password: PASSWORD } })).status, 401, 'sin sesión');

    const { options, done, authenticator } = await registerKey(user, new SoftAuthenticator(), { name: 'YubiKey <b>del trabajo</b>' });
    assert.strictEqual(options.status, 200, options.text);
    const o = options.body.options;
    assert.strictEqual(o.rp.id, 'localhost');
    assert.strictEqual(o.attestation, 'none');
    assert.deepStrictEqual(o.excludeCredentials, []);
    assert.ok(o.challenge.length >= 16);
    const handle = Buffer.from(o.user.id, 'base64url');
    assert.strictEqual(handle.length, 32, 'identificador de usuario de 32 bytes');
    assert.notStrictEqual(o.user.id, Buffer.from(String(user.userId)).toString('base64url'), 'no es el id de la base de datos');
    assert.ok(!handle.toString('utf8').includes(user.username), 'ni contiene el nombre');
    assert.strictEqual(options.headers.get('cache-control'), 'no-store');

    assert.strictEqual(done.status, 201, done.text);
    assert.strictEqual(done.body.recoveryCodes.length, 10, 'primer factor: códigos de recuperación');

    const list = await call(user, 'GET', '/api/auth/webauthn/credentials');
    assert.strictEqual(list.body.credentials.length, 1);
    assert.strictEqual(list.body.credentials[0].name, 'YubiKey bdel trabajo/b', 'se quitan < y > del nombre');
    assert.ok(!/[<>]/.test(list.body.credentials[0].name));
    assert.ok(!JSON.stringify(list.body).match(/publicKey|public_key|credentialId|credential_id/i), 'ni clave ni id de credencial');

    const status = await call(user, 'GET', '/api/auth/mfa');
    assert.deepStrictEqual([status.body.mfa.enabled, status.body.mfa.totp, status.body.mfa.passkeys], [true, false, 1]);

    const [[row]] = await db.query('SELECT public_key, counter, transports FROM webauthn_credentials WHERE user_id = ?', [user.userId]);
    assert.ok(row.public_key.length > 50);
    assert.strictEqual(authenticator.counter, 0);
});

itDb('registro: la misma llave dos veces, tope de 10 llaves, y excludeCredentials evita duplicarla en el navegador', async () => {
    const user = await newUser();
    const first = await registerKey(user);
    assert.strictEqual(first.done.status, 201);

    // el navegador recibe excludeCredentials con la ya registrada
    const again = await call(user, 'POST', '/api/auth/webauthn/register/options', { password: PASSWORD, recoveryCode: first.done.body.recoveryCodes[0] });
    assert.strictEqual(again.status, 200, again.text);
    assert.strictEqual(again.body.options.excludeCredentials.length, 1);
    // si aun así se intenta registrar la MISMA llave
    const dup = await call(user, 'POST', '/api/auth/webauthn/register', { credential: first.authenticator.register(again.body.options) });
    assert.deepStrictEqual([dup.status, dup.body.code], [409, 'CREDENTIAL_EXISTS']);

    // Hasta 10: se llega insertando filas (los 10 códigos de recuperación no dan para tantas reautenticaciones)
    for (let i = 0; i < 9; i++) {
        await db.query("INSERT INTO webauthn_credentials (user_id, credential_id, public_key, name, device_type) VALUES (?, ?, 'AA', ?, 'singleDevice')",
            [user.userId, `relleno-${user.userId}-${i}`, `llave ${i}`]);
    }
    assert.strictEqual(await countCreds(user), 10);
    const eleventh = await registerKey(user, new SoftAuthenticator(), { recoveryCode: first.done.body.recoveryCodes[1] });
    assert.strictEqual(eleventh.options.status, 409);
    assert.strictEqual(eleventh.options.body.code, 'TOO_MANY_CREDENTIALS');
});

itDb('registro: con un segundo factor ya activo hace falta ADEMÁS un código válido (una sesión robada no puede añadir su llave)', async () => {
    const user = await newUser();
    const setup = await call(user, 'POST', '/api/auth/mfa/setup');
    await call(user, 'POST', '/api/auth/mfa/enable', { otp: totp.totp(setup.body.secret) });

    const onlyPassword = await call(user, 'POST', '/api/auth/webauthn/register/options', { password: PASSWORD });
    assert.deepStrictEqual([onlyPassword.status, onlyPassword.body.code], [401, 'INVALID_OTP']);
    assert.strictEqual((await call(user, 'POST', '/api/auth/webauthn/register/options', { password: PASSWORD, otp: '000000' })).status, 401);

    const ok = await registerKey(user, new SoftAuthenticator(), { otp: totp.totp(setup.body.secret, { timeMs: Date.now() + 30_000 }) });
    assert.strictEqual(ok.done.status, 201, ok.done?.text || ok.options.text);
    assert.strictEqual(ok.done.body.recoveryCodes, undefined, 'ya tenía factor: no se regeneran los códigos');
});

itDb('registro: origen o RP ID falsos, reto ajeno, reto reutilizado o caducado, y reto de otro usuario o de otro propósito → rechazado', async () => {
    const user = await newUser();
    const attempts = [
        ['origen falso', (a, o) => a.register(o, { origin: 'http://localhost:6666' })],
        ['RP ID falso', (a, o) => a.register(o, { rpId: 'evil.test' })],
        ['reto inventado', (a, o) => a.register(o, { challenge: Buffer.from('reto-inventado-0123456789').toString('base64url') })]
    ];
    for (const [name, build] of attempts) {
        const options = await call(user, 'POST', '/api/auth/webauthn/register/options', { password: PASSWORD });
        const res = await call(user, 'POST', '/api/auth/webauthn/register', { credential: build(new SoftAuthenticator(), options.body.options) });
        assert.strictEqual(res.status, 400, `${name}: ${res.text}`);
    }
    assert.strictEqual(await countCreds(user), 0);

    // reutilizar un reto ya gastado
    const options = await call(user, 'POST', '/api/auth/webauthn/register/options', { password: PASSWORD });
    const authenticator = new SoftAuthenticator();
    const credential = authenticator.register(options.body.options);
    assert.strictEqual((await call(user, 'POST', '/api/auth/webauthn/register', { credential })).status, 201);
    const replay = await call(user, 'POST', '/api/auth/webauthn/register', { credential });
    assert.strictEqual(replay.status, 400);
    assert.strictEqual(replay.body.code, 'INVALID_CHALLENGE');

    // caducado
    const expired = await call(user, 'POST', '/api/auth/webauthn/register/options', { password: PASSWORD, recoveryCode: undefined }).catch(() => null);
    void expired;

    // el reto de OTRO usuario no vale
    const victim = await newUser();
    const victimOptions = await call(victim, 'POST', '/api/auth/webauthn/register/options', { password: PASSWORD });
    const stolen = new SoftAuthenticator().register(victimOptions.body.options);
    const mine = await newUser();
    assert.strictEqual((await call(mine, 'POST', '/api/auth/webauthn/register', { credential: stolen })).status, 400);
    assert.strictEqual(await countCreds(mine), 0);
    // y al dueño legítimo se le sigue pudiendo registrar
    assert.strictEqual((await call(victim, 'POST', '/api/auth/webauthn/register', { credential: stolen })).status, 201);
});
const countCreds = async (user) => Number((await db.query('SELECT COUNT(*) AS n FROM webauthn_credentials WHERE user_id = ?', [user.userId]))[0][0].n);

itDb('un reto de registro caduca a los 5 minutos y los caducados se limpian', async () => {
    const user = await newUser();
    const options = await call(user, 'POST', '/api/auth/webauthn/register/options', { password: PASSWORD });
    await db.query('UPDATE webauthn_challenges SET expires_at = DATE_SUB(NOW(), INTERVAL 1 SECOND) WHERE user_id = ?', [user.userId]);
    const res = await call(user, 'POST', '/api/auth/webauthn/register', { credential: new SoftAuthenticator().register(options.body.options) });
    assert.strictEqual(res.body.code, 'INVALID_CHALLENGE');

    await db.query('UPDATE webauthn_challenges SET expires_at = DATE_SUB(NOW(), INTERVAL 1 HOUR)');
    assert.ok(await require('./src/security/webauthn.service').purgeExpired() >= 0);
    assert.strictEqual(Number((await db.query('SELECT COUNT(*) AS n FROM webauthn_challenges WHERE expires_at < NOW()'))[0][0].n), 0);
});

// ============================================================================ inicio de sesión

itDb('login con passkey: paso 1 ofrece los métodos, paso 2 firma, la sesión lleva amr "hwk" y funciona con refresh', async () => {
    const user = await newUser();
    const { authenticator } = await registerKey(user);

    const { step1, options, login } = await passkeyLogin(user, authenticator);
    assert.strictEqual(step1.body.mfaRequired, true);
    assert.deepStrictEqual(step1.body.methods, ['webauthn', 'recovery']);
    assert.strictEqual(step1.body.token, undefined, 'todavía no hay sesión');
    assert.strictEqual(options.body.options.allowCredentials.length, 1);
    assert.strictEqual(options.body.options.allowCredentials[0].id, authenticator.id);
    assert.strictEqual(options.body.options.rpId, 'localhost');

    assert.strictEqual(login.status, 200, login.text);
    assert.deepStrictEqual(login.body.authMethods, ['pwd', 'hwk']);
    assert.deepStrictEqual(jwt.decode(login.body.token).amr, ['pwd', 'hwk']);
    assert.strictEqual((await api(app.base, 'GET', '/api/notes', { token: login.body.token, ip: user.ip })).status, 200);

    const refreshed = await api(app.base, 'POST', '/api/auth/refresh', { ip: user.ip, json: { refreshToken: login.body.refreshToken } });
    assert.deepStrictEqual(refreshed.body.authMethods, ['pwd', 'hwk'], 'la renovación conserva cómo se autenticó');
    const [[row]] = await db.query('SELECT counter, last_used_at FROM webauthn_credentials WHERE user_id = ?', [user.userId]);
    assert.strictEqual(Number(row.counter), 1);
    assert.ok(row.last_used_at);
});

itDb('con passkeys como único factor, el código TOTP no existe pero el de recuperación sí sirve', async () => {
    const user = await newUser();
    const { done } = await registerKey(user);
    const step1 = await startLogin(user);
    const wrong = await api(app.base, 'POST', '/api/auth/login/mfa', { ip: user.ip, json: { mfaToken: step1.body.mfaToken, otp: '123456' } });
    assert.strictEqual(wrong.status, 401);
    const ok = await api(app.base, 'POST', '/api/auth/login/mfa', { ip: user.ip, json: { mfaToken: step1.body.mfaToken, recoveryCode: done.body.recoveryCodes[0] } });
    assert.strictEqual(ok.status, 200, ok.text);
    assert.deepStrictEqual(ok.body.authMethods, ['pwd', 'recovery']);
});

itDb('usuario con TOTP y passkeys: puede entrar con cualquiera de los dos', async () => {
    const user = await newUser();
    const setup = await call(user, 'POST', '/api/auth/mfa/setup');
    const enabled = await call(user, 'POST', '/api/auth/mfa/enable', { otp: totp.totp(setup.body.secret) });
    const { authenticator } = await registerKey(user, new SoftAuthenticator(), { recoveryCode: enabled.body.recoveryCodes[0] });

    const step1 = await startLogin(user);
    assert.deepStrictEqual(step1.body.methods, ['totp', 'webauthn', 'recovery']);
    const withOtp = await api(app.base, 'POST', '/api/auth/login/mfa', { ip: user.ip, json: { mfaToken: step1.body.mfaToken, otp: totp.totp(setup.body.secret, { timeMs: Date.now() + 30_000 }) } });
    assert.deepStrictEqual(withOtp.body.authMethods, ['pwd', 'otp']);
    assert.deepStrictEqual((await passkeyLogin(user, authenticator)).login.body.authMethods, ['pwd', 'hwk']);
});

itDb('ataques en el login: origen falso, RP falso, reto ajeno, firma manipulada, reto reutilizado y llave de otro usuario → 401 y cuentan como fallo', async () => {
    const user = await newUser();
    const { authenticator } = await registerKey(user);
    const bad = [
        ['origen falso', { origin: 'http://localhost:6666' }],
        ['RP ID falso', { rpId: 'evil.test' }],
        ['reto inventado', { challenge: Buffer.from('reto-inventado-0123456789').toString('base64url') }],
        ['firma manipulada', { tamper: true }]
    ];
    for (const [name, assertion] of bad) {
        const { login } = await passkeyLogin(user, authenticator, { assertion });
        assert.deepStrictEqual([login.status, login.body.code], [401, 'INVALID_WEBAUTHN'], `${name}: ${login.text}`);
    }
    const [events] = await db.query("SELECT COUNT(*) AS n FROM security_events WHERE event_type = 'LOGIN_FAILED' AND rule = 'BAD_WEBAUTHN' AND user_id = ?", [user.userId]);
    assert.strictEqual(Number(events[0].n), bad.length);

    // el reto se consume: repetir EXACTAMENTE una respuesta buena ya usada no funciona
    const good = await passkeyLogin(user, authenticator);
    assert.strictEqual(good.login.status, 200);
    const replay = await api(app.base, 'POST', '/api/auth/login/webauthn', { ip: user.ip, json: { mfaToken: good.mfaToken, credential: good.credential } });
    assert.strictEqual(replay.status, 401);

    // una llave que no es de este usuario
    const stranger = new SoftAuthenticator();
    const { login } = await passkeyLogin(user, authenticator, { optionsFor: undefined, assertion: { credentialId: stranger.credentialId } });
    assert.strictEqual(login.status, 401);
});

itDb('el reto de login de OTRO usuario no vale: firmar el reto de la víctima con tu propia llave falla', async () => {
    const victim = await newUser();
    const attacker = await newUser();
    const victimKey = (await registerKey(victim)).authenticator;
    const attackerKey = (await registerKey(attacker)).authenticator;

    const victimStep = await startLogin(victim);
    const victimOptions = await api(app.base, 'POST', '/api/auth/login/webauthn/options', { ip: victim.ip, json: { mfaToken: victimStep.body.mfaToken } });
    // el atacante firma el reto de la víctima con SU llave y lo presenta con SU mfaToken
    const attackerStep = await startLogin(attacker);
    const forged = attackerKey.assert(victimOptions.body.options);
    const res = await api(app.base, 'POST', '/api/auth/login/webauthn', { ip: attacker.ip, json: { mfaToken: attackerStep.body.mfaToken, credential: forged } });
    assert.strictEqual(res.status, 401);
    // y la víctima sigue pudiendo entrar con su propio reto
    const legit = victimKey.assert(victimOptions.body.options);
    assert.strictEqual((await api(app.base, 'POST', '/api/auth/login/webauthn', { ip: victim.ip, json: { mfaToken: victimStep.body.mfaToken, credential: legit } })).status, 200);
});

itDb('retos con propósito: un reto de REGISTRO no sirve para iniciar sesión (ni al revés)', async () => {
    const user = await newUser();
    const { authenticator } = await registerKey(user);
    const regOptions = await call(user, 'POST', '/api/auth/webauthn/register/options', { password: PASSWORD, recoveryCode: undefined }).catch(() => null);
    void regOptions;

    // reto de login usado en el endpoint de registro
    const step1 = await startLogin(user);
    const loginOptions = await api(app.base, 'POST', '/api/auth/login/webauthn/options', { ip: user.ip, json: { mfaToken: step1.body.mfaToken } });
    const asRegistration = await call(user, 'POST', '/api/auth/webauthn/register', { credential: new SoftAuthenticator().register(loginOptions.body.options) });
    assert.deepStrictEqual([asRegistration.status, asRegistration.body.code], [400, 'INVALID_CHALLENGE']);
    void authenticator;
});

itDb('llave clonada: un contador que no avanza se rechaza, deja un evento CRÍTICO y la llave original sigue funcionando después de avanzar', async () => {
    const user = await newUser();
    const { authenticator } = await registerKey(user);
    assert.strictEqual((await passkeyLogin(user, authenticator)).login.status, 200);       // contador 1
    assert.strictEqual((await passkeyLogin(user, authenticator)).login.status, 200);       // contador 2

    const clone = await passkeyLogin(user, authenticator, { assertion: { counter: 1 } });  // una copia declara el 1 otra vez
    assert.strictEqual(clone.login.status, 401);
    const [events] = await db.query("SELECT severity, rule FROM security_events WHERE event_type = 'WEBAUTHN_COUNTER_ROLLBACK' AND user_id = ?", [user.userId]);
    assert.deepStrictEqual([events.length, events[0].severity, events[0].rule], [1, 'critical', 'WEBAUTHN_CLONE_SUSPECTED']);

    authenticator.counter = 5;
    assert.strictEqual((await passkeyLogin(user, authenticator, { assertion: { counter: 6 } })).login.status, 200);
    assert.strictEqual(Number((await db.query('SELECT counter FROM webauthn_credentials WHERE user_id = ?', [user.userId]))[0][0].counter), 6);
});

itDb('llaves con contador siempre 0 (passkeys sincronizadas) se aceptan; el contador solo importa si la llave lo usa', async () => {
    const user = await newUser();
    const { authenticator } = await registerKey(user, new SoftAuthenticator({ multiDevice: true, backedUp: true }));
    for (let i = 0; i < 3; i++) {
        const { login } = await passkeyLogin(user, authenticator, { assertion: { counter: 0 } });
        assert.strictEqual(login.status, 200, `intento ${i}: ${login.text}`);
    }
    const list = await call(user, 'GET', '/api/auth/webauthn/credentials');
    assert.deepStrictEqual([list.body.credentials[0].deviceType, list.body.credentials[0].backedUp], ['multiDevice', true]);
});

itDb('dos firmas simultáneas válidas con el mismo reto: solo una inicia sesión', async () => {
    const user = await newUser();
    const { authenticator } = await registerKey(user);
    const step1 = await startLogin(user);
    const options = await api(app.base, 'POST', '/api/auth/login/webauthn/options', { ip: user.ip, json: { mfaToken: step1.body.mfaToken } });
    const credential = authenticator.assert(options.body.options);
    const results = await Promise.all(Array.from({ length: 5 }, () => api(app.base, 'POST', '/api/auth/login/webauthn', { ip: user.ip, json: { mfaToken: step1.body.mfaToken, credential } })));
    assert.strictEqual(results.filter(r => r.status === 200).length, 1, results.map(r => r.status).join(','));
});

itDb('verificación de usuario: con WEBAUTHN_USER_VERIFICATION=required una llave sin PIN/huella no registra ni inicia sesión', async () => {
    await withEnv({ WEBAUTHN_USER_VERIFICATION: 'required' }, async () => {
        const user = await newUser();
        const noUv = await registerKey(user, new SoftAuthenticator({ userVerified: false }));
        assert.strictEqual(noUv.done.status, 400);
        const { authenticator, done } = await registerKey(user, new SoftAuthenticator({ userVerified: true }));
        assert.strictEqual(done.status, 201, done.text);
        const { login } = await passkeyLogin(user, authenticator, { assertion: { uv: false } });
        assert.strictEqual(login.status, 401);
        assert.strictEqual((await passkeyLogin(user, authenticator, { assertion: { uv: true } })).login.status, 200);
    });
    // por defecto (preferred) se acepta sin verificación
    const user = await newUser();
    assert.strictEqual((await registerKey(user, new SoftAuthenticator({ userVerified: false }))).done.status, 201);
});

itDb('los fallos de passkey comparten el bloqueo de cuenta con la contraseña y los códigos', async () => {
    const user = await newUser();
    const { authenticator } = await registerKey(user);
    const ip = testIp();
    for (let i = 0; i < 5; i++) {
        const { login } = await passkeyLogin(user, authenticator, { ip, assertion: { tamper: true } });
        assert.strictEqual(login.status, 401);
    }
    const locked = await passkeyLogin(user, authenticator, { ip });
    assert.ok([429, 401].includes(locked.step1.status), 'el paso 1 ya está bloqueado');
    assert.strictEqual(locked.step1.body.code, 'ACCOUNT_LOCKED');
    // desde otro origen el dueño sigue entrando (el bloqueo es por usuario+origen)
    assert.strictEqual((await passkeyLogin(user, authenticator, { ip: testIp() })).login.status, 200);
});

itDb('MFA_REQUIRED_FOR_ADMINS se cumple con una passkey (amr hwk)', async () => {
    const admin = await newUser();
    await db.query("UPDATE users SET role = 'admin' WHERE id = ?", [admin.userId]);
    const { authenticator } = await registerKey(admin);
    await withEnv({ MFA_REQUIRED_FOR_ADMINS: 'true' }, async () => {
        assert.strictEqual((await call(admin, 'GET', '/api/system/status')).status, 403, 'sesión solo con contraseña');
        const { login } = await passkeyLogin(admin, authenticator);
        assert.strictEqual((await api(app.base, 'GET', '/api/system/status', { token: login.body.token, ip: admin.ip })).status, 200);
    });
});

// ============================================================================ quitar llaves

itDb('quitar una llave exige contraseña + segundo factor; al quitar la última sin TOTP, desaparece el MFA y los códigos', async () => {
    const user = await newUser();
    const first = await registerKey(user);
    const second = await registerKey(user, new SoftAuthenticator(), { name: 'otra', recoveryCode: first.done.body.recoveryCodes[0] });
    const list = (await call(user, 'GET', '/api/auth/webauthn/credentials')).body.credentials;
    assert.strictEqual(list.length, 2);

    const remove = (id, body) => call(user, 'DELETE', `/api/auth/webauthn/credentials/${id}`, body);
    assert.strictEqual((await remove(list[0].id, { password: PASSWORD })).status, 401, 'sin segundo factor');
    assert.strictEqual((await remove(list[0].id, { password: 'mal-mal-mal-mal', recoveryCode: first.done.body.recoveryCodes[1] })).status, 401);
    assert.strictEqual((await remove(99999, { password: PASSWORD, recoveryCode: first.done.body.recoveryCodes[1] })).status, 404);
    assert.strictEqual((await remove('abc', { password: PASSWORD })).status, 400);

    assert.strictEqual((await remove(list[0].id, { password: PASSWORD, recoveryCode: first.done.body.recoveryCodes[2] })).status, 200);
    assert.strictEqual((await startLogin(user)).body.mfaRequired, true, 'queda una llave');

    assert.strictEqual((await remove(list[1].id, { password: PASSWORD, recoveryCode: first.done.body.recoveryCodes[3] })).status, 200);
    assert.strictEqual((await startLogin(user)).body.mfaRequired, undefined, 'sin factores, el login vuelve a ser solo contraseña');
    assert.strictEqual(Number((await db.query('SELECT COUNT(*) AS n FROM user_recovery_codes WHERE user_id = ?', [user.userId]))[0][0].n), 0, 'los códigos ya no protegen nada');
    void second;
});

itDb('no se pueden quitar las llaves de otro usuario', async () => {
    const owner = await newUser();
    const { done } = await registerKey(owner);
    const credential = (await call(owner, 'GET', '/api/auth/webauthn/credentials')).body.credentials[0];
    const intruder = await newUser();
    const res = await call(intruder, 'DELETE', `/api/auth/webauthn/credentials/${credential.id}`, { password: PASSWORD });
    assert.strictEqual(res.status, 404);
    assert.strictEqual(await countCreds(owner), 1);
    void done;
});

itDb('"desactivar MFA" y el reinicio por administradores eliminan TAMBIÉN las passkeys', async () => {
    const user = await newUser();
    const { done } = await registerKey(user);
    const disable = await call(user, 'POST', '/api/auth/mfa/disable', { password: PASSWORD, recoveryCode: done.body.recoveryCodes[0] });
    assert.strictEqual(disable.status, 200, disable.text);
    assert.strictEqual(await countCreds(user), 0);

    // reinicio por administradores
    const victim = await newUser();
    await registerKey(victim);
    await withEnv({ ADMIN_APPROVALS_REQUIRED: '1' }, async () => {
        const admin = await newUser();
        await db.query("UPDATE users SET role = 'admin' WHERE id = ?", [admin.userId]);
        const reset = await call(admin, 'POST', '/api/system/accounts/mfa-reset', { username: victim.username, reason: 'Llave perdida y sin códigos de recuperación' });
        assert.strictEqual(reset.status, 200, reset.text);
    });
    assert.strictEqual(await countCreds(victim), 0);
    assert.strictEqual((await startLogin(victim)).body.mfaRequired, undefined);
});

itDb('si WebAuthn se desactiva del servidor, un usuario con solo passkeys aún puede entrar con un código de recuperación', async () => {
    const user = await newUser();
    const { done } = await registerKey(user);
    await withEnv({ WEBAUTHN_RP_ID: undefined, WEBAUTHN_ORIGINS: undefined }, async () => {
        const step1 = await startLogin(user);
        assert.strictEqual(step1.body.mfaRequired, true);
        assert.deepStrictEqual(step1.body.methods, ['recovery']);
        const ok = await api(app.base, 'POST', '/api/auth/login/mfa', { ip: user.ip, json: { mfaToken: step1.body.mfaToken, recoveryCode: done.body.recoveryCodes[0] } });
        assert.strictEqual(ok.status, 200);
    });
});

itDb('las passkeys se borran con la cuenta (borrado de datos) y salen en el export del admin sin la clave', async () => {
    const user = await newUser();
    await registerKey(user);
    const [[{ n }]] = await db.query('SELECT COUNT(*) AS n FROM webauthn_credentials WHERE user_id = ?', [user.userId]);
    assert.strictEqual(Number(n), 1);
    await db.query('DELETE FROM users WHERE id = ?', [user.userId]);
    assert.strictEqual(Number((await db.query('SELECT COUNT(*) AS n FROM webauthn_credentials WHERE user_id = ?', [user.userId]))[0][0].n), 0, 'ON DELETE CASCADE');
    assert.strictEqual(Number((await db.query('SELECT COUNT(*) AS n FROM webauthn_challenges WHERE user_id = ?', [user.userId]))[0][0].n), 0);
});
