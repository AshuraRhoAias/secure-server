// SSO por SAML 2.0 contra un IdP SIMULADO que firma de verdad (XML-DSig RSA-SHA256), con los ataques SAML clásicos.
// MariaDB real y el servidor real.
//
//   npm run test:saml

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

require('./test_helpers/env');
const helpers = require('./test_helpers/app');
const { api, registerAndLogin, testIp } = helpers;
const { MockSamlIdp } = require('./test_helpers/mock-saml-idp');

let app, db, idp, ACS, SP_ENTITY, enabled = false;

const SAML_VARS = ['SAML_IDP_SSO_URL', 'SAML_IDP_ENTITY_ID', 'SAML_IDP_CERT', 'SAML_CALLBACK_URL', 'SAML_SP_ENTITY_ID', 'SAML_REQUIRE_SIGNED', 'SAML_ADMIN_ATTRIBUTE',
    'SAML_ADMIN_VALUE', 'SAML_ALLOWED_EMAIL_DOMAINS', 'SAML_AUTO_PROVISION', 'SAML_POST_LOGIN_URL', 'SAML_CLOCK_SKEW_SECONDS', 'SAML_EMAIL_ATTRIBUTE'];
const configure = (extra = {}) => {
    SAML_VARS.forEach(k => delete process.env[k]);
    Object.assign(process.env, { SAML_IDP_SSO_URL: idp.ssoUrl, SAML_IDP_ENTITY_ID: idp.entityId, SAML_IDP_CERT: idp.cert, SAML_CALLBACK_URL: ACS }, extra);
};

test.before(async () => {
    enabled = await helpers.prepareDatabase();
    if (!enabled) return;
    db = require('./src/config/database');
    app = await helpers.startApp();
    idp = new MockSamlIdp();
    ACS = `${app.base}/api/saml/acs`;
    SP_ENTITY = `${app.base}/api/saml/metadata`;
});
test.after(async () => {
    SAML_VARS.forEach(k => delete process.env[k]);
    if (!enabled) return;
    await app.close();
    await db.pool.end();
});
const itDb = (name, fn) => test(name, async (t) => {
    if (!enabled) return t.skip('sin BD');
    configure();
    await fn(t);
});
const withEnv = async (vars, fn) => {
    const saved = Object.fromEntries(Object.keys(vars).map(k => [k, process.env[k]]));
    for (const [k, v] of Object.entries(vars)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
    try { return await fn(); } finally {
        for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
    }
};

// ---------------------------------------------------------------- ayudas del flujo
const begin = async (ip = testIp()) => {
    const res = await api(app.base, 'GET', '/api/saml/login?format=json', { ip });
    assert.strictEqual(res.status, 200, res.text);
    return { ...idp.parseAuthnRequest(res.body.url), ip };
};
const acsPost = (base64, ip = testIp(), extra = {}) => api(app.base, 'POST', '/api/saml/acs', {
    ip, raw: new URLSearchParams({ SAMLResponse: base64, ...extra }).toString(), headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
});
// Flujo completo: inicia, el IdP fabrica la respuesta (con las opciones dadas) y se entrega al ACS
async function samlLogin(opts = {}, ip = testIp()) {
    const request = await begin(ip);
    const built = idp.response(request, { audience: SP_ENTITY, ...opts });
    return { ...(await acsPost(built.base64, ip)), request, built, ip };
}
const failedEvents = async (ip) => (await db.query("SELECT rule FROM security_events WHERE event_type = 'SSO_FAILED' AND ip_address = ?", [ip]))[0].map(r => r.rule);

// ---------------------------------------------------------------- configuración

test('SAML desactivado por defecto: 404 claro en todas las rutas y el login normal no cambia', async (t) => {
    if (!enabled) return t.skip('sin BD');
    SAML_VARS.forEach(k => delete process.env[k]);
    assert.strictEqual((await api(app.base, 'GET', '/api/saml/status', { ip: testIp() })).body.enabled, false);
    for (const [method, route] of [['GET', '/api/saml/login'], ['GET', '/api/saml/metadata'], ['POST', '/api/saml/acs']]) {
        const res = await api(app.base, method, route, { ip: testIp() });
        assert.deepStrictEqual([res.status, res.body?.code], [404, 'SAML_NOT_CONFIGURED'], route);
    }
    assert.strictEqual((await registerAndLogin(app.base, { ip: testIp() })).token.length > 20, true);
});

itDb('metadatos del SP y AuthnRequest: entityID, URL ACS, ID guardado en BD y redirección al IdP', async () => {
    const meta = await api(app.base, 'GET', '/api/saml/metadata', { ip: testIp() });
    assert.strictEqual(meta.status, 200, meta.text);
    assert.match(meta.headers.get('content-type'), /samlmetadata\+xml/);
    assert.ok(meta.text.includes(`entityID="${SP_ENTITY}"`));
    assert.ok(meta.text.includes(`Location="${ACS}"`));

    const request = await begin();
    assert.strictEqual(request.url.origin + request.url.pathname, idp.ssoUrl);
    assert.strictEqual(request.acs, ACS);
    assert.strictEqual(request.issuer, SP_ENTITY);
    assert.match(request.id, /^_[0-9a-f-]+$/);
    const [rows] = await db.query('SELECT cache_key FROM saml_cache WHERE cache_key LIKE ?', [`%${request.id}`]);
    assert.strictEqual(rows.length, 1, 'el ID de la petición está guardado en la BD (vale en otra instancia)');

    const redirect = await api(app.base, 'GET', '/api/saml/login', { ip: testIp(), redirect: 'manual' });
    assert.strictEqual(redirect.status, 302);
    assert.ok(redirect.headers.get('location').startsWith(idp.ssoUrl));
    assert.strictEqual(redirect.headers.get('cache-control'), 'no-store');
});

itDb('en producción, URLs http:// del IdP o del ACS se rechazan (503)', async () => {
    await withEnv({ NODE_ENV: 'production' }, async () => {
        const res = await api(app.base, 'GET', '/api/saml/login?format=json', { ip: testIp() });
        assert.deepStrictEqual([res.status, res.body.code], [503, 'SAML_MISCONFIGURED']);
    });
});

// ---------------------------------------------------------------- camino feliz

itDb('login correcto: se crea el usuario, sesión con amr "saml", el email se guarda cifrado y el refresh conserva el método', async () => {
    const nameId = `u-${crypto.randomBytes(6).toString('hex')}`;
    const res = await samlLogin({ nameId, email: 'Persona@Ejemplo.com' });
    assert.strictEqual(res.status, 200, res.text);
    assert.deepStrictEqual(res.body.authMethods, ['saml']);
    assert.deepStrictEqual(jwt.decode(res.body.token).amr, ['saml']);
    assert.ok(res.body.refreshToken);
    assert.strictEqual(res.headers.get('cache-control'), 'no-store');
    assert.strictEqual((await api(app.base, 'GET', '/api/notes', { token: res.body.token, ip: res.ip })).status, 200);

    const [[user]] = await db.query("SELECT id, username_encrypted, email_encrypted, role, password_hash FROM users ORDER BY id DESC LIMIT 1");
    const enc = require('./src/crypto/tripleEncryptor');
    assert.match(enc.decrypt(user.username_encrypted), /^sso_[0-9a-f]{20}$/);
    assert.strictEqual(enc.decrypt(user.email_encrypted), 'persona@ejemplo.com');
    assert.ok(user.email_encrypted.startsWith('v4:') && !user.email_encrypted.includes('ejemplo'));
    assert.strictEqual(user.role, 'user');

    const refreshed = await api(app.base, 'POST', '/api/auth/refresh', { ip: res.ip, json: { refreshToken: res.body.refreshToken } });
    assert.deepStrictEqual(refreshed.body.authMethods, ['saml']);

    // el mismo NameID entra en la MISMA cuenta
    const again = await samlLogin({ nameId });
    assert.strictEqual(again.status, 200);
    assert.strictEqual(jwt.decode(again.body.token).userId, jwt.decode(res.body.token).userId);
    assert.strictEqual(Number((await db.query("SELECT COUNT(*) AS n FROM user_identities WHERE issuer = ?", [`saml:${idp.entityId}`]))[0][0].n) >= 1, true);

    // y esa cuenta no tiene contraseña conocida: no se puede entrar por el login normal
    const login = await api(app.base, 'POST', '/api/auth/login', { ip: testIp(), json: { username: enc.decrypt(user.username_encrypted), password: 'Contraseña-Segura-123' } });
    assert.strictEqual(login.status, 401);
});

itDb('NUNCA se enlaza por email con una cuenta local existente (toma de cuentas)', async () => {
    const victim = await registerAndLogin(app.base, { ip: testIp() });
    const res = await samlLogin({ nameId: `atacante-${crypto.randomBytes(4).toString('hex')}`, email: 'usuario@example.com' });   // el email de la víctima
    assert.strictEqual(res.status, 200);
    assert.notStrictEqual(jwt.decode(res.body.token).userId, victim.userId, 'cuenta NUEVA, no la de la víctima');
    assert.strictEqual((await api(app.base, 'GET', '/api/auth/profile', { token: res.body.token, ip: res.ip })).body.user.username.startsWith('sso_'), true);
});

itDb('rol admin por atributo: se concede, se retira al salir del grupo, y cumple MFA_REQUIRED_FOR_ADMINS (amr saml)', async () => {
    configure({ SAML_ADMIN_ATTRIBUTE: 'groups', SAML_ADMIN_VALUE: 'secure-admins' });
    const nameId = `adm-${crypto.randomBytes(5).toString('hex')}`;
    await withEnv({ MFA_REQUIRED_FOR_ADMINS: 'true' }, async () => {
        const admin = await samlLogin({ nameId, attributes: { groups: ['todos', 'secure-admins'] } });
        assert.strictEqual(admin.status, 200, admin.text);
        assert.strictEqual((await api(app.base, 'GET', '/api/system/status', { token: admin.body.token, ip: admin.ip })).status, 200);

        const demoted = await samlLogin({ nameId, attributes: { groups: ['todos'] } });
        assert.strictEqual((await api(app.base, 'GET', '/api/system/status', { token: demoted.body.token, ip: demoted.ip })).status, 403);
    });
    // un operador asignado con set-role no se degrada por SAML
    const opId = `op-${crypto.randomBytes(5).toString('hex')}`;
    const first = await samlLogin({ nameId: opId, attributes: { groups: ['todos'] } });
    await db.query("UPDATE users SET role = 'operator' WHERE id = ?", [jwt.decode(first.body.token).userId]);
    await samlLogin({ nameId: opId, attributes: { groups: ['todos'] } });
    assert.strictEqual((await db.query('SELECT role FROM users WHERE id = ?', [jwt.decode(first.body.token).userId]))[0][0].role, 'operator');
});

itDb('dominios permitidos y SAML_AUTO_PROVISION=false', async () => {
    configure({ SAML_ALLOWED_EMAIL_DOMAINS: 'ejemplo.com' });
    assert.strictEqual((await samlLogin({ nameId: `a-${crypto.randomBytes(4).toString('hex')}`, email: 'x@evil.com' })).body.code, 'SSO_DOMAIN_NOT_ALLOWED');
    assert.strictEqual((await samlLogin({ nameId: `b-${crypto.randomBytes(4).toString('hex')}`, email: 'x@ejemplo.com.evil.com' })).body.code, 'SSO_DOMAIN_NOT_ALLOWED', 'sufijo engañoso');
    assert.strictEqual((await samlLogin({ nameId: `c-${crypto.randomBytes(4).toString('hex')}`, email: 'ok@ejemplo.com' })).status, 200);

    configure({ SAML_AUTO_PROVISION: 'false' });
    const res = await samlLogin({ nameId: `d-${crypto.randomBytes(4).toString('hex')}` });
    assert.deepStrictEqual([res.status, res.body.code], [403, 'SSO_USER_NOT_PROVISIONED']);
});

itDb('SAML_POST_LOGIN_URL: 303 a una URL FIJA con el token en el fragmento; RelayState se ignora (sin open redirect)', async () => {
    configure({ SAML_POST_LOGIN_URL: 'https://app.ejemplo.com/auth/callback' });
    const request = await begin();
    const built = idp.response(request, { audience: SP_ENTITY, nameId: `r-${crypto.randomBytes(4).toString('hex')}` });
    const res = await api(app.base, 'POST', '/api/saml/acs', {
        ip: request.ip, redirect: 'manual', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        raw: new URLSearchParams({ SAMLResponse: built.base64, RelayState: 'https://evil.example/phish' }).toString()
    });
    assert.strictEqual(res.status, 303);
    const location = new URL(res.headers.get('location'));
    assert.strictEqual(location.origin + location.pathname, 'https://app.ejemplo.com/auth/callback');
    const fragment = new URLSearchParams(location.hash.slice(1));
    assert.ok(fragment.get('token') && fragment.get('refreshToken'));
    assert.ok(!res.headers.get('location').includes('evil.example'));
});

// ---------------------------------------------------------------- firmas

itDb('política de firmas: por defecto la ASERCIÓN firmada; la respuesta sola, o nada, se rechaza', async () => {
    const ok = await samlLogin({ sign: 'assertion', nameId: `s1-${crypto.randomBytes(4).toString('hex')}` });
    assert.strictEqual(ok.status, 200, ok.text);
    const both = await samlLogin({ sign: 'both', nameId: `s2-${crypto.randomBytes(4).toString('hex')}` });
    assert.strictEqual(both.status, 200, both.text);

    for (const sign of ['none', 'response']) {
        const res = await samlLogin({ sign });
        assert.deepStrictEqual([res.status, res.body.code], [401, 'SAML_RESPONSE_INVALID'], sign);
        assert.ok((await failedEvents(res.ip)).includes('SAML_BAD_SIGNATURE'), sign);
    }
});

itDb('SAML_REQUIRE_SIGNED=response exige la respuesta firmada; =both exige las dos', async () => {
    configure({ SAML_REQUIRE_SIGNED: 'response' });
    assert.strictEqual((await samlLogin({ sign: 'response', nameId: `p1-${crypto.randomBytes(4).toString('hex')}` })).status, 200);
    assert.strictEqual((await samlLogin({ sign: 'none' })).status, 401);

    configure({ SAML_REQUIRE_SIGNED: 'both' });
    assert.strictEqual((await samlLogin({ sign: 'both', nameId: `p2-${crypto.randomBytes(4).toString('hex')}` })).status, 200);
    assert.strictEqual((await samlLogin({ sign: 'assertion' })).status, 401);
    assert.strictEqual((await samlLogin({ sign: 'response' })).status, 401);
});

itDb('firmada con OTRA clave (un atacante que hace de IdP) → rechazada', async () => {
    for (const sign of ['assertion', 'response', 'both']) {
        const res = await samlLogin({ sign, signWith: 'rogue' });
        assert.strictEqual(res.status, 401, sign);
        assert.ok((await failedEvents(res.ip)).includes('SAML_BAD_SIGNATURE'), sign);
    }
});

itDb('aserción manipulada DESPUÉS de firmar (NameID a "admin", atributos, audiencia) → rechazada', async () => {
    const tampers = {
        nameId: (xml) => xml.replace('usuario-0001', 'admin-root'),
        atributo: (xml) => xml.replace('persona@ejemplo.com', 'ceo@ejemplo.com'),
        audiencia: (xml) => xml.replace(SP_ENTITY, 'https://otro.test'),
        caducidad: (xml) => xml.replace(/NotOnOrAfter="[^"]+"/g, 'NotOnOrAfter="2099-01-01T00:00:00.000Z"')
    };
    for (const [name, tamper] of Object.entries(tampers)) {
        const res = await samlLogin({ tamper });
        assert.strictEqual(res.status, 401, name);
    }
});

itDb('signature wrapping (XSW): una aserción maliciosa sin firmar junto a la firmada, o la firmada escondida → rechazada', async () => {
    const evil = (id) => `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${id}" Version="2.0" IssueInstant="${new Date().toISOString()}"><saml:Issuer>${idp.entityId}</saml:Issuer><saml:Subject><saml:NameID>admin-root</saml:NameID></saml:Subject></saml:Assertion>`;
    const attacks = {
        'segunda aserción antes': (xml) => xml.replace('</samlp:Status>', `</samlp:Status>${evil('_evil1')}`),
        'segunda aserción después': (xml) => xml.replace('</samlp:Response>', `${evil('_evil2')}</samlp:Response>`),
        'aserción firmada dentro de Extensions': (xml) => {
            const signed = /<saml:Assertion[\s\S]*<\/saml:Assertion>/.exec(xml)[0];
            return xml.replace(signed, `<samlp:Extensions>${signed}</samlp:Extensions>${evil('_evil3')}`);
        }
    };
    for (const [name, tamper] of Object.entries(attacks)) {
        const res = await samlLogin({ tamper, nameId: 'usuario-legitimo' });
        assert.strictEqual(res.status, 401, `${name}: ${res.text}`);
        // y NUNCA se crea la cuenta del NameID malicioso
        const hash = crypto.createHash('sha256').update(`saml:${idp.entityId}|admin-root`).digest('hex');
        assert.strictEqual((await db.query('SELECT 1 FROM user_identities WHERE identity_hash = ?', [hash]))[0].length, 0, name);
    }
});

itDb('rotación de certificados: con dos certificados configurados vale cualquiera de los dos y uno ajeno no', async () => {
    configure({ SAML_IDP_CERT: `${idp.rogue.cert}\n${idp.cert}` });   // el "viejo" primero y el vigente después
    assert.strictEqual((await samlLogin({ nameId: `rot-${crypto.randomBytes(4).toString('hex')}` })).status, 200);
    assert.strictEqual((await samlLogin({ signWith: 'rogue', nameId: `rot2-${crypto.randomBytes(4).toString('hex')}` })).status, 200, 'el segundo certificado de la lista también es de confianza');
    configure({ SAML_IDP_CERT: idp.cert });
    assert.strictEqual((await samlLogin({ signWith: 'rogue' })).status, 401);
});

// ---------------------------------------------------------------- contenido de la aserción

itDb('audiencia, destinatario, destino, emisor y estado erróneos → rechazados y registrados con su motivo', async () => {
    const cases = [
        ['audiencia ajena', { audience: 'https://otro-sp.test' }, 'SAML_BAD_AUDIENCE'],
        ['emisor desconocido', { issuer: 'https://evil-idp.test', assertionIssuer: 'https://evil-idp.test' }, 'SAML_BAD_ISSUER'],
        ['Recipient de otro ACS (Destination correcto)', { recipient: 'https://evil.test/acs', destination: ACS }, 'SAML_BAD_RECIPIENT'],
        ['Destination de otro ACS', { destination: 'https://evil.test/acs' }, 'SAML_BAD_DESTINATION'],
        ['estado de error del IdP', { statusCode: 'urn:oasis:names:tc:SAML:2.0:status:Responder' }, 'SAML_IDP_ERROR']
    ];
    for (const [name, opts, rule] of cases) {
        const res = await samlLogin(opts);
        assert.deepStrictEqual([res.status, res.body.code], [401, 'SAML_RESPONSE_INVALID'], name);
        assert.ok((await failedEvents(res.ip)).includes(rule), `${name}: reglas ${await failedEvents(res.ip)}`);
        assert.ok(!res.text.includes('audience') && !res.text.includes('Expected'), 'el motivo exacto no se cuenta al cliente');
    }
});

itDb('ventanas de validez: caducada y aún no válida se rechazan; la tolerancia de reloj está acotada y es configurable', async () => {
    const hour = 3600_000;
    const expired = await samlLogin({ notOnOrAfter: Date.now() - hour, confirmationNotOnOrAfter: Date.now() - hour });
    assert.strictEqual(expired.status, 401);
    assert.ok((await failedEvents(expired.ip)).includes('SAML_BAD_TIME_WINDOW'));
    assert.strictEqual((await samlLogin({ notBefore: Date.now() + hour })).status, 401, 'NotBefore en el futuro');

    // 30 s en el futuro: dentro de la tolerancia por defecto (60 s)
    assert.strictEqual((await samlLogin({ notBefore: Date.now() + 30_000, nameId: `t1-${crypto.randomBytes(4).toString('hex')}` })).status, 200);
    // 120 s: fuera
    assert.strictEqual((await samlLogin({ notBefore: Date.now() + 120_000 })).status, 401);
    // tolerancia 0: 30 s ya no vale
    configure({ SAML_CLOCK_SKEW_SECONDS: '0' });
    assert.strictEqual((await samlLogin({ notBefore: Date.now() + 30_000 })).status, 401);
    // el tope es 300 s aunque se pida más
    configure({ SAML_CLOCK_SKEW_SECONDS: '99999' });
    assert.strictEqual((await samlLogin({ notBefore: Date.now() + 600_000 })).status, 401);
});

// ---------------------------------------------------------------- InResponseTo y repetición

itDb('solo SP-initiated: sin InResponseTo, con uno desconocido o con una petición caducada → rechazadas', async () => {
    const unsolicited = await samlLogin({ inResponseTo: null });
    assert.strictEqual(unsolicited.status, 401);
    assert.ok((await failedEvents(unsolicited.ip)).includes('SAML_BAD_IN_RESPONSE_TO'));
    assert.strictEqual((await samlLogin({ inResponseTo: '_nunca-enviada' })).status, 401);

    const request = await begin();
    await db.query('UPDATE saml_cache SET expires_at = DATE_SUB(NOW(), INTERVAL 1 MINUTE) WHERE cache_key LIKE ?', [`%${request.id}`]);
    const built = idp.response(request, { audience: SP_ENTITY });
    assert.strictEqual((await acsPost(built.base64, request.ip)).status, 401, 'la petición caducó');
});

itDb('una respuesta válida solo vale UNA vez: repetirla (replay) falla, también si llegan varias a la vez', async () => {
    const request = await begin();
    const built = idp.response(request, { audience: SP_ENTITY, nameId: `once-${crypto.randomBytes(4).toString('hex')}` });
    assert.strictEqual((await acsPost(built.base64, request.ip)).status, 200);
    const replay = await acsPost(built.base64, request.ip);
    assert.strictEqual(replay.status, 401);

    const request2 = await begin();
    const built2 = idp.response(request2, { audience: SP_ENTITY, nameId: `race-${crypto.randomBytes(4).toString('hex')}` });
    const results = await Promise.all(Array.from({ length: 6 }, () => acsPost(built2.base64, request2.ip)));
    assert.strictEqual(results.filter(r => r.status === 200).length, 1, results.map(r => r.status).join(','));
});

itDb('la misma ASERCIÓN no vale en una segunda petición (el InResponseTo cambia, el ID de la aserción no)', async () => {
    const first = await begin();
    const assertionId = `_fija${crypto.randomBytes(6).toString('hex')}`;
    const nameId = `dup-${crypto.randomBytes(4).toString('hex')}`;
    assert.strictEqual((await acsPost(idp.response(first, { audience: SP_ENTITY, assertionId, nameId }).base64, first.ip)).status, 200);
    const second = await begin();
    const replayed = await acsPost(idp.response(second, { audience: SP_ENTITY, assertionId, nameId }).base64, second.ip);
    assert.strictEqual(replayed.status, 401, 'ID de aserción repetido');
});

// ---------------------------------------------------------------- entradas hostiles

itDb('entradas hostiles al ACS: sin cuerpo, no base64, enormes, XML roto, DOCTYPE/entidades (XXE, billion laughs) → 400/401 rápido', async () => {
    const ip = testIp();
    assert.strictEqual((await api(app.base, 'POST', '/api/saml/acs', { ip, raw: '', headers: { 'Content-Type': 'application/x-www-form-urlencoded' } })).status, 400);
    assert.strictEqual((await acsPost('esto no es base64 !!!', ip)).status, 400);
    assert.strictEqual((await acsPost('A'.repeat(600_000), ip)).status, 400, 'más de 512 KB');
    assert.strictEqual((await acsPost(Buffer.from('<<<esto no es xml').toString('base64'), ip)).status, 401);

    const xxe = '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">&x;</samlp:Response>';
    const laughs = '<?xml version="1.0"?><!DOCTYPE l [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;"><!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;"><!ENTITY d "&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;">]><samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">&d;</samlp:Response>';
    for (const xml of [xxe, laughs]) {
        const started = Date.now();
        const res = await acsPost(Buffer.from(xml).toString('base64'), ip);
        assert.strictEqual(res.status, 401);
        assert.ok(Date.now() - started < 3000, 'sin explosión de entidades');
        assert.ok(!res.text.includes('root:'), 'no se filtra /etc/passwd');
    }
    // el servidor sigue vivo
    assert.strictEqual((await api(app.base, 'GET', '/health', { ip })).status, 200);
});

itDb('quien insiste con respuestas falsas acaba bloqueado (strikes)', async () => {
    const ip = testIp();
    for (let i = 0; i < 10; i++) await acsPost(Buffer.from(`<x>${i}</x>`).toString('base64'), ip);
    const anomaly = require('./src/security/anomaly-detection.service');
    assert.strictEqual(await anomaly.isIPBlocked(ip), true);
    assert.strictEqual((await acsPost('AAAA', ip)).status, 403);
});

itDb('la limpieza periódica borra de saml_cache lo caducado', async () => {
    await db.query("INSERT INTO saml_cache (cache_key, cache_value, expires_at) VALUES ('viejo', 'x', DATE_SUB(NOW(), INTERVAL 2 HOUR))");
    assert.ok(await require('./src/sso/saml.service').purgeExpired() >= 1);
    assert.strictEqual((await db.query("SELECT 1 FROM saml_cache WHERE cache_key = 'viejo'"))[0].length, 0);
});
