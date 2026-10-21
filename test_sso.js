// Pruebas del SSO por OpenID Connect contra un proveedor SIMULADO (test_helpers/mock-idp.js) y MariaDB real.
//
//   npm run test:sso

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');

require('./test_helpers/env');
const helpers = require('./test_helpers/app');
const { api, registerAndLogin, testIp } = helpers;
const { createMockIdp } = require('./test_helpers/mock-idp');

const CLIENT_ID = 'secure-server-test';
const CLIENT_SECRET = 'secreto-del-cliente-de-pruebas';

let dbAvailable = false;
let app, db, idp, oidc;
const ENV_KEYS = ['SSO_ISSUER', 'SSO_CLIENT_ID', 'SSO_CLIENT_SECRET', 'SSO_REDIRECT_URI', 'SSO_ALLOWED_EMAIL_DOMAINS', 'SSO_AUTO_PROVISION',
    'SSO_REQUIRE_EMAIL_VERIFIED', 'SSO_ADMIN_CLAIM', 'SSO_ADMIN_VALUE', 'SSO_POST_LOGIN_URL', 'MFA_REQUIRED_FOR_ADMINS'];

function configureSso() {
    Object.assign(process.env, {
        SSO_ISSUER: idp.issuer, SSO_CLIENT_ID: CLIENT_ID, SSO_CLIENT_SECRET: CLIENT_SECRET,
        SSO_REDIRECT_URI: `${app.base}/api/sso/callback`
    });
    for (const key of ['SSO_ALLOWED_EMAIL_DOMAINS', 'SSO_AUTO_PROVISION', 'SSO_REQUIRE_EMAIL_VERIFIED', 'SSO_ADMIN_CLAIM', 'SSO_ADMIN_VALUE', 'SSO_POST_LOGIN_URL', 'MFA_REQUIRED_FOR_ADMINS']) delete process.env[key];
    idp.behaviors.issuerOverride = null;
    idp.behaviors.jwksOverride = null;
    idp.behaviors.tokenStatus = null;
    oidc._resetCachesForTests();
}

test.before(async () => {
    dbAvailable = await helpers.prepareDatabase();
    if (!dbAvailable) return;
    db = require('./src/config/database');
    oidc = require('./src/sso/oidc.service');
    app = await helpers.startApp();
    idp = await createMockIdp({ clientId: CLIENT_ID, clientSecret: CLIENT_SECRET });
    configureSso();
});
test.after(async () => {
    for (const key of ENV_KEYS) delete process.env[key];
    if (idp) await idp.close();
    if (app) await app.close();
    if (db?.pool) await db.pool.end();
});

const itDb = (name, fn) => test(name, async (t) => {
    if (!dbAvailable) return t.skip('sin base de datos');
    configureSso();
    await fn(t);
});

const startLogin = async (ip) => {
    const res = await api(app.base, 'GET', '/api/sso/login', { ip, redirect: 'manual' });
    assert.strictEqual(res.status, 302, res.text);
    return res.headers.get('location');
};
const callback = (path, ip) => api(app.base, 'GET', path, { ip });
// Flujo completo: inicia, "el proveedor autentica", y llega el callback
async function fullLogin(options = {}, ip = testIp()) {
    const authUrl = await startLogin(ip);
    const { callbackPath } = idp.authorize(authUrl, options);
    return callback(callbackPath, ip);
}
const usersCount = async () => (await db.query('SELECT COUNT(*) AS n FROM users'))[0][0].n;
const failedRule = async (ip) => (await db.query("SELECT rule FROM security_events WHERE event_type = 'SSO_FAILED' AND ip_address = ? ORDER BY id DESC LIMIT 1", [ip]))[0][0]?.rule;

itDb('sin configurar: 404 SSO_NOT_CONFIGURED y /status lo dice', async () => {
    delete process.env.SSO_ISSUER;
    assert.deepStrictEqual((await api(app.base, 'GET', '/api/sso/status', { ip: testIp() })).body, { success: true, enabled: false, provider: 'oidc' });
    const res = await api(app.base, 'GET', '/api/sso/login', { ip: testIp(), redirect: 'manual' });
    assert.strictEqual(res.status, 404);
    assert.strictEqual(res.body.code, 'SSO_NOT_CONFIGURED');
    assert.strictEqual((await api(app.base, 'GET', '/api/sso/callback?code=x&state=y', { ip: testIp() })).status, 404);
});

itDb('inicio: redirige al proveedor con state, nonce y PKCE S256, y el estado vive en la BD (no en claro)', async () => {
    const ip = testIp();
    const authUrl = await startLogin(ip);
    const p = new URL(authUrl).searchParams;

    assert.strictEqual(new URL(authUrl).origin + new URL(authUrl).pathname, `${idp.issuer}/authorize`);
    assert.strictEqual(p.get('response_type'), 'code');
    assert.strictEqual(p.get('client_id'), CLIENT_ID);
    assert.strictEqual(p.get('redirect_uri'), `${app.base}/api/sso/callback`);
    assert.strictEqual(p.get('scope'), 'openid email profile');
    assert.strictEqual(p.get('code_challenge_method'), 'S256');
    assert.ok(p.get('state').length >= 40 && p.get('nonce').length >= 24 && p.get('code_challenge').length === 43);

    // Dos inicios nunca repiten state ni nonce
    const other = new URL(await startLogin(ip)).searchParams;
    assert.notStrictEqual(other.get('state'), p.get('state'));
    assert.notStrictEqual(other.get('nonce'), p.get('nonce'));

    // En la BD: solo el HASH del state, y el verificador PKCE cifrado y coherente con el desafío enviado
    const stateHash = crypto.createHash('sha256').update(p.get('state')).digest('hex');
    const [[row]] = await db.query('SELECT * FROM oidc_login_state WHERE state_hash = ?', [stateHash]);
    assert.ok(row && row.nonce === p.get('nonce'));
    assert.ok(row.code_verifier_encrypted.startsWith('v4:'));
    const verifier = require('./src/crypto/tripleEncryptor').decrypt(row.code_verifier_encrypted);
    assert.strictEqual(crypto.createHash('sha256').update(verifier).digest('base64url'), p.get('code_challenge'));
    assert.strictEqual((await db.query('SELECT 1 FROM oidc_login_state WHERE state_hash = ?', [p.get('state')]))[0].length, 0, 'el state en claro no se guarda');

    const json = await api(app.base, 'GET', '/api/sso/login?format=json', { ip });
    assert.strictEqual(json.status, 200);
    assert.ok(json.body.url.startsWith(`${idp.issuer}/authorize?`));
});

itDb('login completo: aprovisiona el usuario, da sesión con amr=sso y la sesión funciona; el segundo login es el mismo usuario', async () => {
    const sub = 'sub-' + crypto.randomUUID();
    const before = await usersCount();
    const first = await fullLogin({ sub, email: 'Ana@Acme.com' });
    assert.strictEqual(first.status, 200, first.text);
    assert.deepStrictEqual(first.body.authMethods, ['sso']);
    assert.ok(first.body.token);
    assert.strictEqual(first.headers.get('cache-control'), 'no-store');

    assert.strictEqual(await usersCount(), before + 1);
    assert.strictEqual((await api(app.base, 'GET', '/api/notes', { ip: testIp(), token: first.body.token })).status, 200);
    const profile = await api(app.base, 'GET', '/api/auth/profile', { ip: testIp(), token: first.body.token });
    assert.ok(profile.body.user.username.startsWith('sso_'));

    // Lo guardado: email cifrado (v4) y en minúsculas, rol user, y solo el HASH de la identidad
    const [[u]] = await db.query('SELECT id, email_encrypted, role, password_hash FROM users WHERE id = ?', [profile.body.user.id]);
    assert.strictEqual(require('./src/crypto/tripleEncryptor').decrypt(u.email_encrypted), 'ana@acme.com');
    assert.strictEqual(u.role, 'user');
    const [[identity]] = await db.query('SELECT issuer, identity_hash FROM user_identities WHERE user_id = ?', [u.id]);
    assert.strictEqual(identity.identity_hash, crypto.createHash('sha256').update(`${idp.issuer}|${sub}`).digest('hex'));
    assert.ok(!JSON.stringify(identity).includes(sub), 'el sujeto del proveedor no se guarda en claro');

    const second = await fullLogin({ sub, email: 'ana@acme.com' });
    assert.strictEqual(second.status, 200);
    assert.strictEqual(await usersCount(), before + 1, 'no se crea otro usuario');
    assert.strictEqual((await api(app.base, 'GET', '/api/auth/profile', { ip: testIp(), token: second.body.token })).body.user.id, u.id);

    // El cliente envió PKCE y secreto en el intercambio
    const exchange = idp.tokenRequests.at(-1).form;
    assert.ok(exchange.code_verifier.length >= 43 && exchange.grant_type === 'authorization_code' && exchange.client_secret === CLIENT_SECRET);
});

itDb('una cuenta SSO no puede entrar con contraseña', async () => {
    const res = await fullLogin({});
    const profile = await api(app.base, 'GET', '/api/auth/profile', { ip: testIp(), token: res.body.token });
    for (const password of ['', 'cualquiera-123456', 'sso', profile.body.user.username]) {
        const r = await api(app.base, 'POST', '/api/auth/login', { ip: testIp(), json: { username: profile.body.user.username, password: password || 'x' } });
        assert.strictEqual(r.status, 401);
    }
});

itDb('state: un solo uso, caduca, no se puede falsificar y faltan parámetros → error', async () => {
    const ip = testIp();
    const authUrl = await startLogin(ip);
    const { callbackPath } = idp.authorize(authUrl, {});
    assert.strictEqual((await callback(callbackPath, ip)).status, 200);

    const replay = await callback(callbackPath, ip);          // el mismo callback otra vez
    assert.strictEqual(replay.status, 401);
    assert.strictEqual(replay.body.code, 'SSO_STATE_INVALID');

    const forged = idp.authorize(await startLogin(ip), { stateOverride: crypto.randomBytes(32).toString('base64url') });
    assert.strictEqual((await callback(forged.callbackPath, ip)).body.code, 'SSO_STATE_INVALID');

    const stale = await startLogin(ip);
    await db.query('UPDATE oidc_login_state SET expires_at = DATE_SUB(NOW(), INTERVAL 1 MINUTE) WHERE state_hash = ?',
        [crypto.createHash('sha256').update(new URL(stale).searchParams.get('state')).digest('hex')]);
    assert.strictEqual((await callback(idp.authorize(stale, {}).callbackPath, ip)).body.code, 'SSO_STATE_INVALID');

    assert.strictEqual((await api(app.base, 'GET', '/api/sso/callback?code=abc', { ip })).status, 400);
    assert.strictEqual((await api(app.base, 'GET', '/api/sso/callback?state=abc', { ip })).status, 400);
    assert.strictEqual((await api(app.base, 'GET', '/api/sso/callback?error=access_denied&state=x', { ip })).body.code, 'SSO_PROVIDER_ERROR');
    assert.strictEqual((await api(app.base, 'GET', `/api/sso/callback?code[]=a&state=${'x'.repeat(10)}`, { ip })).status, 400, 'code como array');
});

itDb('el state se consume aunque el intercambio falle (no se puede reintentar con él)', async () => {
    const ip = testIp();
    const authUrl = await startLogin(ip);
    const { callbackPath } = idp.authorize(authUrl, {});
    idp.behaviors.tokenStatus = 500;
    assert.strictEqual((await callback(callbackPath, ip)).status, 401);
    idp.behaviors.tokenStatus = null;
    assert.strictEqual((await callback(callbackPath, ip)).body.code, 'SSO_STATE_INVALID');
});

const ID_TOKEN_ATTACKS = [
    ['nonce distinto (repetición de un token de otro login)', { claims: { nonce: 'otro-nonce' } }, /NONCE_MISMATCH/],
    ['audiencia de otra aplicación', { claims: { aud: 'otra-app' } }, /CLAIM_VALIDATION_FAILED/],
    ['emisor distinto', { claims: { iss: 'http://evil.example' } }, /CLAIM_VALIDATION_FAILED/],
    ['caducado', { claims: { exp: Math.floor(Date.now() / 1000) - 3600, iat: Math.floor(Date.now() / 1000) - 7200 } }, /JWT_EXPIRED/],
    ['sin sub', { claims: { sub: undefined }, sub: undefined }, /CLAIM_VALIDATION_FAILED|SUB/],
    ['firmado con HS256 usando el secreto del cliente (confusión de algoritmo)', { sign: 'hs256' }, /ALG|SIGNATURE|JOSE/],
    ['alg=none (sin firma)', { sign: 'none' }, /ALG|SIGNATURE|JWS|JOSE/],
    ['firmado con la clave del atacante (mismo kid)', { sign: 'evil-key' }, /SIGNATURE/],
    ['kid desconocido', { sign: 'unknown-kid' }, /NO_MATCHING_KEY|JWKS/],
    ['payload alterado tras firmar', { sign: 'tampered' }, /SIGNATURE/],
    ['varias audiencias sin azp', { claims: { aud: [CLIENT_ID, 'otra-app'] } }, /AZP_MISMATCH/]
];

for (const [name, options, rule] of ID_TOKEN_ATTACKS) {
    itDb(`id_token malicioso rechazado — ${name}`, async () => {
        const ip = testIp();
        const before = await usersCount();
        const res = await fullLogin(options, ip);
        assert.strictEqual(res.status, 401, res.text);
        assert.strictEqual(res.body.code, 'SSO_ID_TOKEN_INVALID');
        assert.ok(!res.body.token);
        assert.match(await failedRule(ip), rule);
        assert.strictEqual(await usersCount(), before, 'no se crea ningún usuario');
    });
}

itDb('email sin verificar → 403 (configurable); con SSO_REQUIRE_EMAIL_VERIFIED=false se acepta', async () => {
    const ip = testIp();
    const res = await fullLogin({ claims: { email_verified: false } }, ip);
    assert.strictEqual(res.status, 403);
    assert.strictEqual(res.body.code, 'SSO_EMAIL_UNVERIFIED');
    process.env.SSO_REQUIRE_EMAIL_VERIFIED = 'false';
    assert.strictEqual((await fullLogin({ claims: { email_verified: false } })).status, 200);
});

itDb('PKCE: si el proveedor recibe un verificador que no corresponde al desafío, no emite el token', async () => {
    const ip = testIp();
    const authUrl = await startLogin(ip);
    const { callbackPath } = idp.authorize(authUrl, { codeChallengeOverride: 'x'.repeat(43) }); // el code quedó ligado a OTRO desafío
    const res = await callback(callbackPath, ip);
    assert.strictEqual(res.status, 401);
    assert.strictEqual(res.body.code, 'SSO_TOKEN_EXCHANGE_FAILED');
});

itDb('secreto de cliente incorrecto → el intercambio falla', async () => {
    process.env.SSO_CLIENT_SECRET = 'incorrecto';
    const res = await fullLogin({});
    assert.strictEqual(res.status, 401);
    assert.strictEqual(res.body.code, 'SSO_TOKEN_EXCHANGE_FAILED');
});

itDb('mix-up: si el documento de descubrimiento declara OTRO issuer, se aborta', async () => {
    idp.behaviors.issuerOverride = 'https://evil.example';
    oidc._resetCachesForTests();
    const res = await api(app.base, 'GET', '/api/sso/login', { ip: testIp(), redirect: 'manual' });
    assert.strictEqual(res.status, 502);
    assert.strictEqual(res.body.code, 'SSO_ISSUER_MISMATCH');
});

itDb('en producción exige HTTPS en el issuer y los endpoints', async () => {
    const saved = process.env.NODE_ENV;
    process.env.NODE_ENV = 'production';
    try {
        oidc._resetCachesForTests();
        const res = await api(app.base, 'GET', '/api/sso/login', { ip: testIp(), redirect: 'manual' });
        assert.strictEqual(res.status, 502);
        assert.strictEqual(res.body.code, 'SSO_INSECURE_ENDPOINT');
    } finally { process.env.NODE_ENV = saved; oidc._resetCachesForTests(); }
});

itDb('NUNCA se enlaza por email con una cuenta local existente (toma de cuenta)', async () => {
    const local = await registerAndLogin(app.base, { ip: testIp() });
    const [[{ total_before }]] = await db.query('SELECT COUNT(*) AS total_before FROM users');
    // El "proveedor" afirma el mismo email que tiene (cifrado) la cuenta local
    const res = await fullLogin({ email: 'usuario@example.com' });
    assert.strictEqual(res.status, 200);
    const profile = await api(app.base, 'GET', '/api/auth/profile', { ip: testIp(), token: res.body.token });
    assert.notStrictEqual(profile.body.user.id, local.userId, 'es una cuenta distinta');
    const [[{ total_after }]] = await db.query('SELECT COUNT(*) AS total_after FROM users');
    assert.strictEqual(total_after, total_before + 1);
    assert.strictEqual((await api(app.base, 'GET', '/api/auth/profile', { ip: testIp(), token: local.token })).body.user.id, local.userId);
});

itDb('dominios permitidos y alta automática desactivable', async () => {
    process.env.SSO_ALLOWED_EMAIL_DOMAINS = 'acme.com, partner.org';
    const denied = await fullLogin({ email: 'intruso@evil.example' });
    assert.strictEqual(denied.status, 403);
    assert.strictEqual(denied.body.code, 'SSO_DOMAIN_NOT_ALLOWED');
    const sub = 'sub-' + crypto.randomUUID();
    assert.strictEqual((await fullLogin({ sub, email: 'ok@partner.org' })).status, 200);

    process.env.SSO_AUTO_PROVISION = 'false';
    const unknown = await fullLogin({ email: 'nuevo@acme.com' });
    assert.strictEqual(unknown.status, 403);
    assert.strictEqual(unknown.body.code, 'SSO_USER_NOT_PROVISIONED');
    assert.strictEqual((await fullLogin({ sub, email: 'ok@partner.org' })).status, 200, 'el ya dado de alta sí entra');
});

itDb('rol de administrador desde un claim del proveedor, y se retira al salir del grupo', async () => {
    process.env.SSO_ADMIN_CLAIM = 'groups';
    process.env.SSO_ADMIN_VALUE = 'secure-server-admins';
    process.env.MFA_REQUIRED_FOR_ADMINS = 'true';
    const sub = 'sub-' + crypto.randomUUID();

    const asAdmin = await fullLogin({ sub, claims: { groups: ['everyone', 'secure-server-admins'] } });
    assert.strictEqual(asAdmin.status, 200);
    // SSO cuenta como segundo factor para MFA_REQUIRED_FOR_ADMINS
    assert.strictEqual((await api(app.base, 'GET', '/api/system/blocked-ips', { ip: testIp(), token: asAdmin.body.token })).status, 200);

    const demoted = await fullLogin({ sub, claims: { groups: ['everyone'] } });
    assert.strictEqual((await api(app.base, 'GET', '/api/system/blocked-ips', { ip: testIp(), token: demoted.body.token })).status, 403);
});

itDb('dos primeros logins simultáneos de la misma identidad crean UN solo usuario', async () => {
    const sub = 'sub-' + crypto.randomUUID();
    const results = await Promise.all([fullLogin({ sub }), fullLogin({ sub }), fullLogin({ sub })]);
    assert.deepStrictEqual(results.map(r => r.status), [200, 200, 200]);
    const identityHash = crypto.createHash('sha256').update(`${idp.issuer}|${sub}`).digest('hex');
    assert.strictEqual((await db.query('SELECT 1 FROM user_identities WHERE identity_hash = ?', [identityHash]))[0].length, 1);
});

itDb('aplicación web: con SSO_POST_LOGIN_URL redirige a esa URL fija con el token en el fragmento (no en la query)', async () => {
    process.env.SSO_POST_LOGIN_URL = 'https://app.example.com/welcome';
    const ip = testIp();
    const { callbackPath } = idp.authorize(await startLogin(ip), {});
    const res = await api(app.base, 'GET', callbackPath, { ip, redirect: 'manual' });
    assert.strictEqual(res.status, 302);
    const target = new URL(res.headers.get('location'));
    assert.strictEqual(target.origin + target.pathname, 'https://app.example.com/welcome');
    assert.strictEqual(target.search, '');
    assert.ok(new URLSearchParams(target.hash.slice(1)).get('token'));
    assert.strictEqual(res.headers.get('cache-control'), 'no-store');
});

itDb('quien insiste con states o tokens falsos termina bloqueado', async () => {
    const ip = testIp();
    for (let i = 0; i < 10; i++) {
        await api(app.base, 'GET', `/api/sso/callback?code=x&state=${crypto.randomBytes(16).toString('hex')}`, { ip });
    }
    const anomaly = require('./src/security/anomaly-detection.service');
    assert.ok(await anomaly.isIPBlocked(ip));
});

itDb('limpieza: los estados caducados se borran', async () => {
    await db.query("INSERT INTO oidc_login_state (state_hash, nonce, code_verifier_encrypted, expires_at) VALUES (?, 'n', 'v4:x', DATE_SUB(NOW(), INTERVAL 3 DAY))", [crypto.randomBytes(32).toString('hex')]);
    assert.ok((await oidc.purgeExpired()) >= 1);
});
