// Pruebas de seguridad: cifrado, detector de inyecciones, estado en MySQL (no en memoria), bloqueo de
// cuentas, límites, JWT y análisis de anomalías.
//
//   npm run test:security
//
// Las pruebas de integración usan MySQL/MariaDB REAL y una aplicación con los mismos middlewares y
// rutas que producción (ver test_helpers/). Se omiten si no hay base de datos disponible.

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');

require('./test_helpers/env');
const helpers = require('./test_helpers/app');
const { api, rawRequest, registerAndLogin, uniqueName, testIp, PASSWORD } = helpers;

const withEnv = async (vars, fn) => {
    const saved = Object.fromEntries(Object.keys(vars).map(k => [k, process.env[k]]));
    Object.assign(process.env, vars);
    try { return await fn(); } finally {
        for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
    }
};
const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

// ============================================================================ CIFRADO (puro)

test('cifrado v4: AES-256-GCM, IV aleatorio, ida y vuelta (incluye vacío y unicode)', () => {
    const enc = require('./src/crypto/tripleEncryptor');
    for (const text of ['', 'hola', 'ñandú 🔐 日本語', 'x'.repeat(1_000_000)]) {
        const c = enc.encrypt(text);
        assert.ok(c.startsWith('v4:'));
        assert.strictEqual(enc.decrypt(c), text);
    }
    assert.notStrictEqual(enc.encrypt('igual'), enc.encrypt('igual'), 'dos cifrados del mismo texto deben diferir (IV aleatorio)');
});

test('cifrado v4: cualquier alteración del texto cifrado se detecta', () => {
    const enc = require('./src/crypto/tripleEncryptor');
    const raw = Buffer.from(enc.encrypt('dato sensible').slice(3), 'base64');
    // 0-11 IV · 12-27 etiqueta · 28.. datos: se voltea un bit en cada zona
    for (const position of [0, 11, 12, 27, 28, raw.length - 1]) {
        const copy = Buffer.from(raw);
        copy[position] ^= 0x01;
        assert.throws(() => enc.decrypt('v4:' + copy.toString('base64')), /descifrar/, `byte ${position}`);
    }
    assert.throws(() => enc.decrypt('v4:' + raw.subarray(0, 20).toString('base64')), /descifrar/);
    assert.throws(() => enc.decrypt('v4:'), /descifrar/);
    assert.throws(() => enc.decrypt(''), /descifrar/);
});

test('cifrado v4: una clave distinta no descifra, y withKey restaura la clave aunque falle', () => {
    const enc = require('./src/crypto/tripleEncryptor');
    const secureEnv = require('./src/config/secure-env');
    const c = enc.encrypt('secreto');
    const other = crypto.randomBytes(32).toString('hex');

    assert.throws(() => enc.withKey(other, () => enc.decrypt(c)), /descifrar/);
    assert.throws(() => enc.withKey(other, () => { throw new Error('boom'); }), /boom/);
    assert.strictEqual(enc.getKey(), secureEnv.getSecret('encryption'));
    assert.strictEqual(enc.decrypt(c), 'secreto');
});

test('cifrado: la clave de campo se deriva (HKDF) y no es la clave maestra', () => {
    const enc = require('./src/crypto/tripleEncryptor');
    assert.notStrictEqual(enc._fieldKey().toString('hex'), enc.getKey());
});

test('cifrado: los datos del formato triple antiguo siguen siendo legibles', () => {
    const enc = require('./src/crypto/tripleEncryptor');
    const [l1, l2, l3] = [require('./src/crypto/level1'), require('./src/crypto/level2'), require('./src/crypto/level3')];
    const legacy = l3.encrypt(l2.encrypt(l1.encrypt('dato antiguo')));
    assert.ok(enc.isLegacy(legacy));
    assert.strictEqual(enc.decrypt(legacy), 'dato antiguo');
});

test('cifrado: no escribe NADA en consola (ni claves, ni IV, ni fragmentos cifrados)', () => {
    const enc = require('./src/crypto/tripleEncryptor');
    const l3 = require('./src/crypto/level3');
    const calls = [];
    const saved = {};
    for (const m of ['log', 'info', 'warn', 'error', 'debug']) { saved[m] = console[m]; console[m] = (...a) => calls.push(a); }
    try {
        for (let i = 0; i < 20; i++) enc.decrypt(enc.encrypt(`dato ${i}`));
        try { enc.decrypt('v4:AAAA'); } catch { /* esperado */ }
        try { l3.decrypt('zz:zz:zz'); } catch { /* esperado */ }
        try { enc.decrypt('basura:basura:basura'); } catch { /* esperado */ }
    } finally {
        Object.assign(console, saved);
    }
    assert.deepStrictEqual(calls, []);
});

test('cifrado: healthCheck verifica v4, formato antiguo y rechazo de alterados', async () => {
    const enc = require('./src/crypto/tripleEncryptor');
    assert.deepStrictEqual((await enc.healthCheck()).healthy, true);
});

// ============================================================================ DETECTOR (puro)

const { scanText, scanObject, scanRequest, normalize } = require('./src/security/injection-detector');
const highRules = (text, opts = { location: 'query', field: 'q' }) => scanText(text, opts).filter(f => f.severity === 'high').map(f => f.rule);

const ATTACKS = [
    ["' OR '1'='1", /SQLI_TAUTOLOGY/],
    ["' OR 1=1--", /SQLI_TAUTOLOGY|SQLI_TAUTOLOGY_BARE/],
    ['1 OR 1=1', /SQLI_TAUTOLOGY_BARE/],
    ["x' AND 'a'='a", /SQLI_TAUTOLOGY/],
    ['1 UNION SELECT username,password FROM users', /SQLI_UNION/],
    ["' UNION ALL SELECT NULL,NULL--", /SQLI_UNION/],
    ['UNION/**/SELECT 1', /SQLI_UNION/],
    ['/*!50000UNION*/ /*!50000SELECT*/ 1,2', /SQLI_UNION/],
    ['UNION%0aSELECT 1', /SQLI_UNION/],
    ['UnIoN   aLl   SeLeCt 1', /SQLI_UNION/],
    ['%27%20UNION%20SELECT%201%2C2--', /SQLI_UNION/],
    ['%2527%2520UNION%2520SELECT%25201', /SQLI_UNION/],
    ['ＵＮＩＯＮ ＳＥＬＥＣＴ 1', /SQLI_UNION/],
    ["1; DROP TABLE users", /SQLI_STACKED/],
    ["'; DROP TABLE users;--", /SQLI_STACKED/],
    ["1; DELETE FROM user_notes", /SQLI_STACKED/],
    ["1'; INSERT INTO users VALUES (1)--", /SQLI_STACKED/],
    ["1' AND SLEEP(5)--", /SQLI_TIME_BASED/],
    ["1' WAITFOR DELAY '0:0:5'--", /SQLI_TIME_BASED/],
    ['SELECT * FROM information_schema.tables', /SQLI_SCHEMA_PROBE/],
    ["' AND extractvalue(1,concat(0x7e,version()))--", /SQLI_DANGEROUS_FUNC/],
    ['; EXEC xp_cmdshell("dir")', /SQLI_STACKED|SQLI_DANGEROUS_FUNC/],
    ['<script>alert(1)</script>', /XSS_SCRIPT_TAG/],
    ['<SCRIPT SRC=//evil.js>', /XSS_SCRIPT_TAG/],
    ['%3Cscript%3Ealert(1)%3C%2Fscript%3E', /XSS_SCRIPT_TAG/],
    ['<img src=x onerror=alert(1)>', /XSS_EVENT_HANDLER/],
    ['<svg/onload=alert(1)>', /XSS_EVENT_HANDLER/],
    ['<iframe src=//evil></iframe>', /XSS_EMBED_TAG/],
    ['data:text/html;base64,PHNjcmlwdD4=', /XSS_DATA_HTML/],
    ['${jndi:ldap://evil.example/a}', /LOG4SHELL_JNDI/],
    ['../../etc/passwd', /PATH_TRAVERSAL|PATH_SENSITIVE_FILE/],
    ['..\\..\\windows\\win.ini', /PATH_TRAVERSAL/],
    ['%2e%2e%2f%2e%2e%2fetc%2fpasswd', /PATH_TRAVERSAL|PATH_SENSITIVE_FILE/],
    ['/etc/shadow', /PATH_SENSITIVE_FILE/],
    ['x\r\nSet-Cookie: a=b', /CRLF_INJECTION/],
    ['x%0d%0aLocation: http://evil', /CRLF_INJECTION/],
    ['a\u0000b', /NUL_BYTE/],
    ['rm -rf /', /CMD_DESTRUCTIVE/]
];

for (const [payload, expected] of ATTACKS) {
    test(`detector: detecta ${JSON.stringify(payload).slice(0, 60)}`, () => {
        const rules = highRules(payload);
        assert.ok(rules.some(r => expected.test(r)), `esperaba ${expected}, obtuve [${rules}]`);
    });
}

const BENIGN = [
    'Hola, ¿cómo estás? Todo bien por aquí.',
    'Please select the file from the list',
    "I'd like an order of fries and a drink",
    "O'Brien & Sons, Ltd.",
    '5 > 3 and 2 < 4',
    'reunión: revisar presupuesto; borrar lo viejo después',
    'The union of two sets',
    "Don't drop the table at dinner",
    '--- separador ---',
    'correo@ejemplo.com',
    "Rock 'n' roll",
    'SELECT es una palabra clave de SQL',
    'Me gusta <3 el café',
    'javascript es un lenguaje',
    'Precio: $1,299.99 (IVA incluido)',
    'ls y cd son comandos',
    'mi nota con "comillas" y \'apóstrofes\''
];

for (const text of BENIGN) {
    test(`detector: no confunde texto normal: ${text.slice(0, 40)}`, () => {
        assert.deepStrictEqual(highRules(text), [], 'ninguna regla de severidad alta');
    });
}

test('detector: en el CUERPO, "../" y comandos se registran pero no se rechazan; en la URL sí', () => {
    const inBody = scanText('cd ../src && ls -la', { location: 'body', field: 'content', bodyLike: true });
    assert.ok(inBody.every(f => f.severity !== 'high'));
    const inUrl = scanText('../../etc/passwd', { location: 'url', field: 'path' });
    assert.ok(inUrl.some(f => f.severity === 'high'));
});

test('detector: claves de operadores NoSQL y de contaminación de prototipos', () => {
    const nosql = scanObject({ user: { $ne: null } }, 'body', true);
    assert.ok(nosql.some(f => f.rule === 'NOSQL_OPERATOR'));
    const polluted = scanObject(JSON.parse('{"__proto__":{"admin":true}}'), 'body', true);
    assert.ok(polluted.some(f => f.rule === 'PROTOTYPE_POLLUTION'));
});

test('detector: los campos de contraseña/token no se inspeccionan ni se registran', () => {
    const findings = scanObject({ password: "' OR 1=1--<script>", note: 'hola' }, 'body', true);
    assert.deepStrictEqual(findings, []);
});

test('detector: resistente a ReDoS (entradas hostiles terminan rápido)', () => {
    const hostile = [
        'a'.repeat(2_000_000), '/*'.repeat(500_000), '<a '.repeat(300_000), "' or ".repeat(200_000),
        'select '.repeat(300_000), '%'.repeat(1_000_000) + 'zz', '('.repeat(1_000_000), 'union '.repeat(200_000),
        '<' + 'a b='.repeat(100_000), ';'.repeat(500_000) + ' drop', '$'.repeat(500_000) + '{'
    ];
    for (const text of hostile) {
        const started = process.hrtime.bigint();
        scanText(text, { location: 'query', field: 'q' });
        const ms = Number(process.hrtime.bigint() - started) / 1e6;
        assert.ok(ms < 250, `tardó ${ms.toFixed(0)} ms con una entrada de ${text.length} caracteres`);
    }
});

test('detector: normalize decodifica %xx dos veces, Unicode y comentarios SQL', () => {
    assert.strictEqual(normalize('%2527'), "'");
    assert.strictEqual(normalize('UNION/**/SELECT'), 'union select');
    assert.strictEqual(normalize('/*!50000UNION*/ x').trim(), 'union x');
    assert.strictEqual(normalize('＜script＞'), '<script>');
});

// ============================================================================ IP (puro)

const { normalizeIp, ipSubject, isNeverBlocked } = require('./src/security/ip');

test('IP: IPv4 dentro de IPv6 se normaliza y IPv6 se agrupa por /64', () => {
    assert.strictEqual(normalizeIp('::ffff:1.2.3.4'), '1.2.3.4');
    assert.strictEqual(normalizeIp('basura'), 'unknown');
    assert.strictEqual(normalizeIp(undefined), 'unknown');
    assert.strictEqual(ipSubject('2001:db8:abcd:12::1'), ipSubject('2001:DB8:ABCD:12:ffff:ffff:ffff:ffff'));
    assert.notStrictEqual(ipSubject('2001:db8:abcd:12::1'), ipSubject('2001:db8:abcd:13::1'));
    assert.strictEqual(ipSubject('203.0.113.9'), '203.0.113.9');
    assert.ok(isNeverBlocked('127.0.0.1') && isNeverBlocked('::1') && !isNeverBlocked('203.0.113.9'));
});

// ============================================================================ SQL: sin interpolación

test('no hay SQL con interpolación: solo sqlInt()/sqlPlaceholders() dentro de ${...}', () => {
    // Excepciones justificadas: construyen identificadores (tabla/columna) a partir de constantes del
    // código (encrypted-columns.js), jamás de entrada del usuario.
    const TRUSTED = [
        path.join('src', 'maintenance') + path.sep,
        path.join('src', 'backup') + path.sep,
        path.join('src', 'notifications') + path.sep
    ];
    const SQL_WORDS = /\b(?:SELECT\s|INSERT\s+INTO|UPDATE\s+\S+\s+SET|DELETE\s+FROM|REPLACE\s+INTO|ALTER\s+TABLE|CREATE\s+TABLE|DROP\s+TABLE|FROM\s+\S|WHERE\s+\S|ORDER\s+BY|LIMIT\s+[\d$])/i;
    const SAFE = /^\s*(?:sqlInt|sqlPlaceholders)\(/;

    const files = [];
    (function walk(dir) {
        for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
            const full = path.join(dir, entry.name);
            if (entry.isDirectory()) walk(full);
            else if (entry.name.endsWith('.js')) files.push(full);
        }
    })('src');

    const offenders = [];
    for (const file of files) {
        if (TRUSTED.some(prefix => file.startsWith(prefix))) continue;
        const source = fs.readFileSync(file, 'utf8');
        for (const [literal] of source.matchAll(/`(?:[^`\\]|\\.)*`/gs)) {
            if (!literal.includes('${') || !SQL_WORDS.test(literal)) continue;
            for (const [, expr] of literal.matchAll(/\$\{([^}]*)\}/g)) {
                if (!SAFE.test(expr)) offenders.push(`${file}: \${${expr}}`);
            }
        }
    }
    assert.deepStrictEqual(offenders, [], 'SQL construido con interpolación (usa parámetros ? o sqlInt)');
});

// ============================================================================ INTEGRACIÓN (MySQL real)

let dbAvailable = false;
let app;
let db;
let enc;
let events;
let anomaly;
const children = [];

test.before(async () => {
    dbAvailable = await helpers.prepareDatabase();
    if (!dbAvailable) return;
    db = require('./src/config/database');
    enc = require('./src/crypto/tripleEncryptor');
    events = require('./src/security/security-events.service');
    anomaly = require('./src/security/anomaly-detection.service');
    app = await helpers.startApp();
});

test.after(async () => {
    children.forEach(child => child.kill());
    if (app) await app.close();
    if (db?.pool) await db.pool.end();
});

const itDb = (name, fn) => test(name, async (t) => {
    if (!dbAvailable) return t.skip('sin base de datos');
    await fn(t);
});

const eventsOf = async (ip, extra = '') => {
    const [rows] = await db.query('SELECT * FROM security_events WHERE ip_address = ? ORDER BY id', [ip]);
    return extra ? rows.filter(r => r.event_type === extra) : rows;
};

async function startChild(extraEnv = {}) {
    const child = spawn(process.execPath, [path.join(__dirname, 'test_helpers/serve.js')], {
        env: { ...process.env, ...extraEnv }, stdio: ['ignore', 'pipe', 'pipe']
    });
    children.push(child);
    const port = await new Promise((resolve, reject) => {
        let out = '';
        const timer = setTimeout(() => reject(new Error('el proceso hijo no arrancó')), 15000);
        child.stdout.on('data', (chunk) => {
            out += chunk;
            const m = /PORT (\d+)/.exec(out);
            if (m) { clearTimeout(timer); resolve(Number(m[1])); }
        });
        child.on('exit', () => reject(new Error('el proceso hijo terminó')));
    });
    return { port, base: `http://127.0.0.1:${port}` };
}

// Espera al comienzo de la siguiente ventana de 60 s si quedan pocos segundos (evita pruebas
// que cruzarían un cambio de ventana de los contadores)
async function waitForFreshWindow(windowSec = 60, margin = 4) {
    const rest = windowSec - (Math.floor(Date.now() / 1000) % windowSec);
    if (rest <= margin) await sleep((rest + 1) * 1000);
}

// ---------------------------------------------------------------- estado en tablas, no en memoria

itDb('el estado de seguridad está en tablas: contadores y eventos se ven en MySQL', async () => {
    const ip = testIp();
    await api(app.base, 'GET', '/api/notes', { ip });
    const [rows] = await db.query('SELECT hits FROM rate_limit_counters WHERE scope = ? AND subject = ?', ['ip', ip]);
    assert.ok(rows.length >= 1 && rows[0].hits >= 1);
});

itDb('el límite de peticiones se comparte entre PROCESOS distintos (no es memoria de uno)', async () => {
    await withEnv({ RATE_LIMIT_GLOBAL_PER_MIN: '5' }, async () => {
        const child = await startChild({ RATE_LIMIT_GLOBAL_PER_MIN: '5' });
        const ip = testIp();
        await waitForFreshWindow();

        const statuses = [];
        for (let i = 0; i < 3; i++) statuses.push((await api(app.base, 'GET', '/api/notes', { ip })).status);   // proceso A
        for (let i = 0; i < 3; i++) statuses.push((await api(child.base, 'GET', '/api/notes', { ip })).status); // proceso B

        assert.deepStrictEqual(statuses.slice(0, 5), [401, 401, 401, 401, 401], 'las 5 primeras pasan (sin token → 401)');
        assert.strictEqual(statuses[5], 429, 'la 6ª, en OTRO proceso, ya está limitada: el contador es de la base de datos');
    });
});

itDb('un bloqueo de IP persiste y lo ve otro proceso (sobrevive a un reinicio)', async () => {
    const child = await startChild();
    const ip = testIp();

    // 5 inyecciones rechazadas = 5 "strikes" → bloqueo automático
    for (let i = 0; i < 5; i++) {
        const r = await api(app.base, 'GET', `/api/notes?q=${encodeURIComponent("1' UNION SELECT password FROM users--")}`, { ip });
        assert.strictEqual(r.status, 403);
        assert.strictEqual(r.body.code, 'MALICIOUS_INPUT');
    }

    const blocked = await api(app.base, 'GET', '/health-check-not-health', { ip });
    assert.strictEqual(blocked.status, 403);
    assert.strictEqual(blocked.body.code, 'IP_BLOCKED');

    // Un proceso que nunca vio a esta IP también la rechaza
    const other = await api(child.base, 'GET', '/api/notes', { ip });
    assert.strictEqual(other.status, 403);
    assert.strictEqual(other.body.code, 'IP_BLOCKED');

    const [rows] = await db.query('SELECT block_count, blocked_until > NOW() AS active FROM blocked_ips WHERE ip_address = ?', [ip]);
    assert.strictEqual(rows[0].block_count, 1);
    assert.ok(rows[0].active);

    const logged = await eventsOf(ip, 'IP_BLOCKED');
    assert.strictEqual(logged.length, 1);
    assert.strictEqual(logged[0].action_taken, 'blocked_ip');

    // Desbloqueo manual
    assert.ok(await anomaly.unblockIP(ip));
    assert.notStrictEqual((await api(child.base, 'GET', '/api/notes', { ip })).status, 403);
});

itDb('bloqueo progresivo: el segundo bloqueo dura más que el primero', async () => {
    const ip = testIp();
    await anomaly.blockIP(ip, 'PRUEBA', { baseSeconds: 60 });
    const [[first]] = await db.query('SELECT TIMESTAMPDIFF(SECOND, NOW(), blocked_until) AS s FROM blocked_ips WHERE ip_address = ?', [ip]);
    await anomaly.blockIP(ip, 'PRUEBA', { baseSeconds: 60 });
    const [[second]] = await db.query('SELECT TIMESTAMPDIFF(SECOND, NOW(), blocked_until) AS s, block_count FROM blocked_ips WHERE ip_address = ?', [ip]);
    assert.ok(second.s >= first.s * 1.9, `${first.s}s → ${second.s}s`);
    assert.strictEqual(second.block_count, 2);
});

itDb('IPv6: el bloqueo afecta al /64 completo, no solo a una dirección', async () => {
    await anomaly.blockIP('2001:db8:abcd:12::1', 'PRUEBA IPV6');
    assert.ok(await anomaly.isIPBlocked('2001:db8:abcd:12:aaaa:bbbb:cccc:dddd'));
    assert.ok(!(await anomaly.isIPBlocked('2001:db8:abcd:13::1')));
});

itDb('loopback y PROTECTION_ALLOWLIST nunca se bloquean solos', async () => {
    assert.strictEqual(await anomaly.blockIP('127.0.0.1', 'PRUEBA'), false);
    await withEnv({ PROTECTION_ALLOWLIST: '198.51.100.7' }, async () => {
        assert.strictEqual(await anomaly.blockIP('198.51.100.7', 'PRUEBA'), false);
    });
    assert.ok(!(await anomaly.isIPBlocked('127.0.0.1')));
});

itDb('falla CERRADO: sin base de datos de seguridad la API responde 503 (y /health sigue vivo)', async () => {
    const original = db.pool.getConnection;
    db.pool.getConnection = async () => { throw new Error('BD caída (simulada)'); };
    try {
        const ip = testIp();
        const res = await api(app.base, 'GET', '/api/notes', { ip });
        assert.strictEqual(res.status, 503);
        assert.strictEqual(res.body.code, 'SECURITY_BACKEND_UNAVAILABLE');
        assert.strictEqual((await api(app.base, 'GET', '/health', { ip })).status, 200);
    } finally {
        db.pool.getConnection = original;
    }
});

// ---------------------------------------------------------------- límites

itDb('límite global por IP: 429 con Retry-After, evento registrado y /health exento', async () => {
    await withEnv({ RATE_LIMIT_GLOBAL_PER_MIN: '3' }, async () => {
        const ip = testIp();
        await waitForFreshWindow();

        const codes = [];
        for (let i = 0; i < 4; i++) codes.push((await api(app.base, 'GET', '/api/notes', { ip })).status);
        assert.deepStrictEqual(codes, [401, 401, 401, 429]);

        const limited = await api(app.base, 'GET', '/api/notes', { ip });
        assert.strictEqual(limited.status, 429);
        assert.ok(Number(limited.headers.get('retry-after')) > 0);
        assert.ok((await eventsOf(ip, 'RATE_LIMITED')).length >= 1);

        for (let i = 0; i < 10; i++) assert.strictEqual((await api(app.base, 'GET', '/health', { ip })).status, 200);
    });
});

itDb('exceso extremo del límite (×3) → la IP se bloquea', async () => {
    await withEnv({ RATE_LIMIT_GLOBAL_PER_MIN: '2' }, async () => {
        const ip = testIp();
        await waitForFreshWindow();
        for (let i = 0; i < 9; i++) await api(app.base, 'GET', '/api/notes', { ip });
        assert.ok(await anomaly.isIPBlocked(ip));
    });
});

itDb('límite estricto en login/registro: 429 al pasar el máximo por minuto', async () => {
    await withEnv({ SENSITIVE_RATE_LIMIT_PER_MIN: '3' }, async () => {
        const ip = testIp();
        await waitForFreshWindow();
        const codes = [];
        for (let i = 0; i < 4; i++) {
            codes.push((await api(app.base, 'POST', '/api/auth/login', { ip, json: { username: 'nadie', password: 'x' } })).status);
        }
        assert.deepStrictEqual(codes, [401, 401, 401, 429]);
    });
});

// ---------------------------------------------------------------- bloqueo de cuenta

const badLogin = (ip, username, password = 'incorrecta') => api(app.base, 'POST', '/api/auth/login', { ip, json: { username, password } });

itDb('bloqueo de cuenta: 5 fallos y el 6º intento (aunque sea correcto) devuelve 429', async () => {
    const ip = testIp();
    const user = await registerAndLogin(app.base, { ip });
    const hash = require('./src/security/secure-auth.service').generateUsernameHash(user.username);

    for (let i = 0; i < 5; i++) {
        const r = await badLogin(ip, user.username);
        assert.strictEqual(r.status, 401, `intento ${i + 1}`);
        assert.strictEqual(r.body.code, 'INVALID_CREDENTIALS');
    }

    const locked = await badLogin(ip, user.username, user.password); // contraseña CORRECTA
    assert.strictEqual(locked.status, 429);
    assert.strictEqual(locked.body.code, 'ACCOUNT_LOCKED');
    assert.ok(Number(locked.headers.get('retry-after')) > 0);

    // Mientras está bloqueada no se registran más fallos (si no, el bloqueo sería eterno)
    const [[{ failures }]] = await db.query('SELECT COUNT(*) AS failures FROM login_attempts WHERE username_hash = ? AND success = 0', [hash]);
    assert.strictEqual(failures, 5);

    const trail = await eventsOf(ip);
    assert.ok(trail.some(e => e.event_type === 'LOGIN_BLOCKED' && e.action_taken === 'locked_account'));
    assert.ok(trail.filter(e => e.event_type === 'LOGIN_FAILED').length >= 5);
});

itDb('bloqueo de cuenta: se levanta solo al pasar la ventana', async () => {
    await withEnv({ LOCKOUT_WINDOW_SECONDS: '3' }, async () => {
        const ip = testIp();
        const user = await registerAndLogin(app.base, { ip });
        for (let i = 0; i < 5; i++) await badLogin(ip, user.username);
        assert.strictEqual((await badLogin(ip, user.username, user.password)).status, 429);

        await sleep(3600);
        assert.strictEqual((await badLogin(ip, user.username, user.password)).status, 200);
    });
});

itDb('bloqueo de cuenta: un login correcto reinicia la cuenta de fallos', async () => {
    const ip = testIp();
    const user = await registerAndLogin(app.base, { ip });
    for (let i = 0; i < 4; i++) await badLogin(ip, user.username);
    assert.strictEqual((await badLogin(ip, user.username, user.password)).status, 200); // éxito: reinicia
    for (let i = 0; i < 4; i++) assert.strictEqual((await badLogin(ip, user.username)).status, 401);
    assert.strictEqual((await badLogin(ip, user.username)).status, 401);   // 5º fallo desde el éxito
    assert.strictEqual((await badLogin(ip, user.username, user.password)).status, 429);
});

itDb('bloqueo de cuenta: un usuario inexistente se comporta IGUAL (no sirve para descubrir cuentas)', async () => {
    const ip = testIp();
    const ghost = uniqueName('fantasma');
    const first = await badLogin(ip, ghost);
    assert.strictEqual(first.status, 401);
    assert.strictEqual(first.body.message, 'Credenciales inválidas');
    for (let i = 0; i < 4; i++) await badLogin(ip, ghost);
    const locked = await badLogin(ip, ghost);
    assert.strictEqual(locked.status, 429);
    assert.strictEqual(locked.body.code, 'ACCOUNT_LOCKED');
});

itDb('login: el tiempo de respuesta no delata si el usuario existe (siempre una comparación bcrypt)', async () => {
    const ip = testIp();
    const user = await registerAndLogin(app.base, { ip });
    const time = async (username) => {
        const started = process.hrtime.bigint();
        await badLogin(ip, username);
        return Number(process.hrtime.bigint() - started) / 1e6;
    };
    const median = (xs) => xs.sort((a, b) => a - b)[Math.floor(xs.length / 2)];

    const existing = median([await time(user.username), await time(user.username), await time(user.username)]);
    const missing = median([await time(uniqueName('nadie')), await time(uniqueName('nadie')), await time(uniqueName('nadie'))]);
    assert.ok(missing > existing * 0.5, `usuario inexistente ${missing.toFixed(0)} ms vs existente ${existing.toFixed(0)} ms`);
});

itDb('credential stuffing: muchos fallos desde una IP con usuarios distintos → la IP se bloquea', async () => {
    await withEnv({ LOGIN_IP_FAILURES_TO_BLOCK: '6' }, async () => {
        const ip = testIp();
        for (let i = 0; i < 6; i++) await badLogin(ip, uniqueName('victima'));
        assert.ok(await anomaly.isIPBlocked(ip));
    });
});

itDb('registro: contraseña corta/larga rechazada, espacios conservados, duplicados → 409 (también en carrera)', async () => {
    const ip = testIp();
    const name = uniqueName();
    const reg = (username, password) => api(app.base, 'POST', '/api/auth/register', { ip, json: { username, email: 'a@b.co', password } });

    assert.strictEqual((await reg(name, 'corta')).status, 400);
    assert.strictEqual((await reg(name, 'x'.repeat(73))).status, 400, '73 bytes: bcrypt los ignoraría en silencio');

    const spaced = uniqueName();
    assert.strictEqual((await reg(spaced, '  con espacios al borde  ')).status, 201);
    const okLogin = await badLogin(ip, spaced, '  con espacios al borde  ');
    assert.strictEqual(okLogin.status, 200, 'la contraseña se usa tal cual, sin recortar');
    assert.strictEqual((await badLogin(ip, spaced, 'con espacios al borde')).status, 401);

    const raced = uniqueName();
    const results = await Promise.all([reg(raced, PASSWORD), reg(raced, PASSWORD), reg(raced, PASSWORD)]);
    const codes = results.map(r => r.status).sort();
    assert.deepStrictEqual(codes, [201, 409, 409], 'índice único: solo un registro gana');
});

// ---------------------------------------------------------------- inyección SQL de extremo a extremo

itDb('SQL: con el detector en modo "solo registrar", los ataques NO funcionan porque las consultas usan parámetros', async () => {
    await withEnv({ INJECTION_BODY_MODE: 'log' }, async () => {
        const ip = testIp();
        const [[{ total_before }]] = await db.query('SELECT COUNT(*) AS total_before FROM users');

        // 1. El usuario cuyo NOMBRE es una inyección se registra como texto literal
        const evil = "bob'; DROP TABLE users; --";
        const user = await registerAndLogin(app.base, { ip, username: evil });
        assert.ok(user.token);
        const [[{ total_after }]] = await db.query('SELECT COUNT(*) AS total_after FROM users');
        assert.strictEqual(total_after, total_before + 1, 'la tabla users sigue existiendo y solo tiene una fila más');

        // 2. Login clásico de bypass: ni como usuario ni como contraseña
        for (const payload of ["' OR '1'='1", "admin'--", "' OR 1=1 --", '" OR ""="']) {
            const r = await badLogin(ip, payload, payload);
            assert.strictEqual(r.status, 401, payload);
        }

        // 3. Nota con SQL en título y contenido: se guarda y se lee TAL CUAL
        const title = "'); DELETE FROM user_notes; --";
        const content = "x' UNION SELECT username_hash, password_hash FROM users --";
        const created = await api(app.base, 'POST', '/api/notes', { ip, token: user.token, json: { title, content } });
        assert.strictEqual(created.status, 201);
        const read = await api(app.base, 'GET', `/api/notes/${created.body.note.id}`, { ip, token: user.token });
        assert.strictEqual(read.body.note.title, title);
        assert.strictEqual(read.body.note.content, content);

        // 4. Seguía todo en pie
        const [tables] = await db.query("SELECT TABLE_NAME AS name FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE()");
        const names = tables.map(t => t.name);
        for (const table of ['users', 'user_notes', 'security_events', 'user_files']) assert.ok(names.includes(table), table);

        // 5. Y todo quedó anotado para analizarlo después (registrado, no rechazado)
        const trail = (await eventsOf(ip, 'INJECTION_ATTEMPT')).filter(e => e.rule?.startsWith('SQLI'));
        assert.ok(trail.length >= 3, `eventos SQLI registrados: ${trail.length}`);
        assert.ok(trail.every(e => e.action_taken === 'logged'));
    });
});

itDb('SQL: parámetros de ruta y de consulta con inyección → rechazados antes de llegar a la BD', async () => {
    const ip = testIp();
    const user = await registerAndLogin(app.base, { ip });
    const cases = [
        ['GET', `/api/notes?limit=${encodeURIComponent('1; DROP TABLE users')}`],
        ['GET', `/api/notes?page=${encodeURIComponent('1 UNION SELECT 1')}`],
        ['GET', `/api/notes/${encodeURIComponent('1 OR 1=1')}`],
        ['GET', `/api/files?category=${encodeURIComponent("' OR '1'='1")}`],
        ['GET', `/api/files?before=${encodeURIComponent('1; SELECT SLEEP(5)')}`]
    ];
    for (const [method, route] of cases) {
        const r = await api(app.base, method, route, { ip: testIp(), token: user.token });
        assert.ok([400, 403].includes(r.status), `${route} → ${r.status}`);
    }
    const [[{ ok }]] = await db.query('SELECT COUNT(*) AS ok FROM users');
    assert.ok(ok >= 1);
});

// ---------------------------------------------------------------- modo bloqueo: ataques rechazados y registrados

const REJECTED = [
    ['cuerpo: SQL', 'POST', '/api/notes', { json: { title: "' OR '1'='1", content: 'x' } }, 400, /SQLI/],
    ['cuerpo: XSS <script>', 'POST', '/api/notes', { json: { title: '<script>alert(1)</script>', content: 'x' } }, 400, /XSS/],
    ['cuerpo: XSS onerror', 'POST', '/api/notes', { json: { title: 'a', content: '<img src=x onerror=alert(1)>' } }, 400, /XSS/],
    ['cuerpo: JNDI', 'POST', '/api/notes', { json: { title: 'a', content: '${jndi:ldap://evil/a}' } }, 400, /LOG4SHELL/],
    ['cuerpo: operador NoSQL', 'POST', '/api/notes', { json: { title: { $ne: null }, content: 'x' } }, 400, /NOSQL/],
    ['cuerpo: __proto__', 'POST', '/api/notes', { json: '{"title":"a","__proto__":{"admin":true}}' }, 400, /PROTOTYPE/],
    ['cuerpo: constructor', 'POST', '/api/notes', { json: '{"title":"a","constructor":{"prototype":{"x":1}}}' }, 400, /PROTOTYPE/],
    ['cuerpo: byte nulo', 'POST', '/api/notes', { json: '{"title":"a\\u0000b"}' }, 400, /NUL_BYTE/],
    ['query: SQL', 'GET', `/api/notes?x=${encodeURIComponent("1 UNION SELECT 1,2")}`, {}, 403, /SQLI/],
    ['query: XSS', 'GET', `/api/notes?x=${encodeURIComponent('<script>alert(1)</script>')}`, {}, 403, /XSS/],
    ['query: traversal', 'GET', `/api/notes?file=${encodeURIComponent('../../etc/passwd')}`, {}, 403, /PATH/],
    ['query: CRLF', 'GET', '/api/notes?x=%0d%0aSet-Cookie:%20a=b', {}, 403, /CRLF/],
    ['cabecera: User-Agent con SQL', 'GET', '/api/notes', { headers: { 'User-Agent': "' UNION SELECT password FROM users--" } }, 403, /SQLI/],
    ['cabecera: Referer con script', 'GET', '/api/notes', { headers: { Referer: 'http://x/<script>alert(1)</script>' } }, 403, /XSS/]
];

for (const [name, method, route, opts, expectedStatus, expectedRule] of REJECTED) {
    itDb(`ataque rechazado y registrado — ${name}`, async () => {
        const ip = testIp();
        const user = await registerAndLogin(app.base, { ip });
        const res = await api(app.base, method, route, { ip, token: user.token, ...opts });
        assert.strictEqual(res.status, expectedStatus);
        assert.strictEqual(res.body.code, 'MALICIOUS_INPUT');

        const trail = (await eventsOf(ip, 'INJECTION_ATTEMPT')).filter(e => expectedRule.test(e.rule));
        assert.ok(trail.length >= 1, `sin evento ${expectedRule}`);
        assert.strictEqual(trail[0].action_taken, 'rejected');
        assert.strictEqual(trail[0].severity, 'high');
        assert.ok(trail[0].path && trail[0].user_agent !== undefined && trail[0].method);
    });
}

itDb('la contaminación de prototipos no deja rastro en el proceso', async () => {
    const ip = testIp();
    const user = await registerAndLogin(app.base, { ip });
    await api(app.base, 'POST', '/api/notes', { ip, token: user.token, json: '{"title":"a","__proto__":{"polluted":"si"}}' });
    await api(app.base, 'POST', '/api/notes', { ip, token: user.token, json: '{"title":"a","constructor":{"prototype":{"polluted":"si"}}}' });
    assert.strictEqual({}.polluted, undefined);
    assert.strictEqual(Object.prototype.polluted, undefined);
});

itDb('ruta "../" y %2e%2e en la URL cruda → 403', async () => {
    const ip = testIp();
    for (const raw of ['/api/files/..%2f..%2f..%2fetc%2fpasswd', '/api/notes/%2e%2e/%2e%2e/etc/passwd', '/api/..%5c..%5cwindows%5cwin.ini']) {
        const r = await rawRequest(app.port, { path: raw, headers: { 'X-Forwarded-For': testIp() } });
        assert.strictEqual(r.status, 403, raw);
    }
    void ip;
});

itDb('escáneres: rutas como /.env o /wp-admin se registran y, repetidas, bloquean la IP', async () => {
    const ip = testIp();
    for (const route of ['/.env', '/wp-admin/setup.php', '/phpmyadmin/', '/.git/config', '/cgi-bin/x']) {
        const r = await api(app.base, 'GET', route, { ip });
        assert.ok([404, 403].includes(r.status), `${route} → ${r.status}`);
    }
    assert.ok((await eventsOf(ip, 'SCANNER_PATH')).length >= 5);
    assert.ok(await anomaly.isIPBlocked(ip), 'a la 5ª sonda la IP queda bloqueada');
});

itDb('texto normal que contiene palabras de SQL/HTML NO se rechaza (sin falsos positivos que bloqueen)', async () => {
    const ip = testIp();
    const user = await registerAndLogin(app.base, { ip });
    for (const text of ['Please select the file from the list', "O'Brien & Sons", 'cd ../src && ls -la', 'a < b and c > d', 'javascript: the good parts', '5 > 3 and 2 < 4']) {
        const r = await api(app.base, 'POST', '/api/notes', { ip, token: user.token, json: { title: 'nota', content: text } });
        assert.strictEqual(r.status, 201, text);
    }
    assert.ok(!(await anomaly.isIPBlocked(ip)));
});

itDb('exceso de ráfagas 401/403 desde una IP → bloqueo', async () => {
    await withEnv({ AUTH_FAILURES_TO_BLOCK: '8' }, async () => {
        const ip = testIp();
        for (let i = 0; i < 8; i++) await api(app.base, 'GET', '/api/notes', { ip }); // sin token: 401
        await sleep(300); // el recuento ocurre tras responder
        assert.ok(await anomaly.isIPBlocked(ip));
        assert.ok((await eventsOf(ip, 'AUTH_FAILURE_BURST')).length >= 1);
    });
});

// ---------------------------------------------------------------- JWT / sesiones

itDb('JWT: alg=none, firma ajena, payload alterado, HS512 y token sin sesión → 401', async () => {
    const jwt = require('jsonwebtoken');
    const credentialBuilder = require('./src/config/credential-builder');
    const ip = testIp();
    const user = await registerAndLogin(app.base, { ip });
    const secret = credentialBuilder.generateJWTSecret();
    const payload = { userId: user.userId, username: user.username, sessionId: 'x' };

    const [h, p, s] = user.token.split('.');
    const forged = {
        'alg none': `${Buffer.from('{"alg":"none","typ":"JWT"}').toString('base64url')}.${p}.`,
        'firma ajena': jwt.sign(payload, 'otra-clave', { algorithm: 'HS256' }),
        'payload alterado': `${h}.${Buffer.from(JSON.stringify({ ...JSON.parse(Buffer.from(p, 'base64url')), userId: 1 })).toString('base64url')}.${s}`,
        'HS512 con la clave correcta': jwt.sign(payload, secret, { algorithm: 'HS512' }),
        'firma válida pero sin sesión en BD': jwt.sign(payload, secret, { algorithm: 'HS256', expiresIn: '1h' }),
        'caducado': jwt.sign(payload, secret, { algorithm: 'HS256', expiresIn: -10 })
    };
    for (const [name, token] of Object.entries(forged)) {
        const r = await api(app.base, 'GET', '/api/notes', { ip: testIp(), token });
        assert.strictEqual(r.status, 401, name);
    }
    assert.strictEqual((await api(app.base, 'GET', '/api/notes', { ip, token: user.token })).status, 200, 'el legítimo sigue valiendo');
});

itDb('JWT: tras cerrar sesión el token deja de valer', async () => {
    const ip = testIp();
    const user = await registerAndLogin(app.base, { ip });
    assert.strictEqual((await api(app.base, 'POST', '/api/auth/logout', { ip, token: user.token })).status, 200);
    assert.strictEqual((await api(app.base, 'GET', '/api/notes', { ip, token: user.token })).status, 401);
});

itDb('login: el 500 interno no filtra detalles (solo mensaje genérico)', async () => {
    const original = db.pool.getConnection;
    const ip = testIp();
    const user = await registerAndLogin(app.base, { ip });
    // Falla solo la consulta de usuarios: la protección (otras consultas) sigue funcionando
    const realQuery = db.query.bind(db);
    db.query = async (sql, params) => {
        if (/FROM users WHERE username_hash/.test(sql)) throw Object.assign(new Error('Table crash at secret_table'), { code: 'ER_FAKE' });
        return realQuery(sql, params);
    };
    try {
        const r = await badLogin(ip, user.username, user.password);
        assert.strictEqual(r.status, 500);
        assert.ok(!/secret_table|crash/.test(r.text));
    } finally {
        db.query = realQuery;
        db.pool.getConnection = original;
    }
});

// ---------------------------------------------------------------- notas (SQL reescrito) y aislamiento

itDb('notas: un usuario no ve ni toca las de otro; PUT parcial conserva el otro campo', async () => {
    const ipA = testIp(), ipB = testIp();
    const a = await registerAndLogin(app.base, { ip: ipA });
    const b = await registerAndLogin(app.base, { ip: ipB });
    const created = await api(app.base, 'POST', '/api/notes', { ip: ipA, token: a.token, json: { title: 'titulo', content: 'contenido' } });
    const id = created.body.note.id;

    assert.strictEqual((await api(app.base, 'GET', `/api/notes/${id}`, { ip: ipB, token: b.token })).status, 404);
    assert.strictEqual((await api(app.base, 'PUT', `/api/notes/${id}`, { ip: ipB, token: b.token, json: { title: 'robado' } })).status, 404);
    assert.strictEqual((await api(app.base, 'DELETE', `/api/notes/${id}`, { ip: ipB, token: b.token })).status, 404);

    const onlyTitle = await api(app.base, 'PUT', `/api/notes/${id}`, { ip: ipA, token: a.token, json: { title: 'nuevo' } });
    assert.deepStrictEqual([onlyTitle.body.note.title, onlyTitle.body.note.content], ['nuevo', 'contenido']);
    const onlyContent = await api(app.base, 'PUT', `/api/notes/${id}`, { ip: ipA, token: a.token, json: { content: 'otro' } });
    assert.deepStrictEqual([onlyContent.body.note.title, onlyContent.body.note.content], ['nuevo', 'otro']);
    assert.strictEqual((await api(app.base, 'PUT', `/api/notes/${id}`, { ip: ipA, token: a.token, json: {} })).status, 400);
});

itDb('en la BD los campos van cifrados con v4 (nada en claro)', async () => {
    const ip = testIp();
    const user = await registerAndLogin(app.base, { ip });
    await api(app.base, 'POST', '/api/notes', { ip, token: user.token, json: { title: 'TITULO-EN-CLARO-XYZ', content: 'CONTENIDO-EN-CLARO-XYZ' } });
    const [rows] = await db.query('SELECT title_encrypted, content_encrypted FROM user_notes WHERE user_id = ?', [user.userId]);
    for (const row of rows) {
        assert.ok(row.title_encrypted.startsWith('v4:') && row.content_encrypted.startsWith('v4:'));
        assert.ok(!row.title_encrypted.includes('EN-CLARO') && !row.content_encrypted.includes('EN-CLARO'));
    }
    const [[u]] = await db.query('SELECT username_encrypted, email_encrypted FROM users WHERE id = ?', [user.userId]);
    assert.ok(u.username_encrypted.startsWith('v4:') && u.email_encrypted.startsWith('v4:'));
});

// ---------------------------------------------------------------- tabla de análisis

itDb('API de análisis: solo admin; filtros, paginación, resumen y SIN secretos en los eventos', async () => {
    const ipUser = testIp(), ipAttack = testIp();
    const user = await registerAndLogin(app.base, { ip: ipUser });
    await api(app.base, 'GET', `/api/notes?x=${encodeURIComponent("1 UNION SELECT 1")}`, { ip: ipAttack, token: user.token });
    await api(app.base, 'POST', '/api/auth/login', { ip: ipAttack, json: { username: 'nadie', password: PASSWORD } });

    // un usuario normal no entra
    assert.strictEqual((await api(app.base, 'GET', '/api/system/security-events', { ip: ipUser, token: user.token })).status, 403);

    await db.query("UPDATE users SET role = 'admin' WHERE id = ?", [user.userId]);

    const all = await api(app.base, 'GET', '/api/system/security-events?hours=1', { ip: ipUser, token: user.token });
    assert.strictEqual(all.status, 200);
    assert.ok(all.body.events.length > 0);

    const filtered = await api(app.base, 'GET', `/api/system/security-events?hours=1&ip=${ipAttack}&type=INJECTION_ATTEMPT`, { ip: ipUser, token: user.token });
    assert.ok(filtered.body.events.length >= 1);
    assert.ok(filtered.body.events.every(e => e.ip_address === ipAttack && e.event_type === 'INJECTION_ATTEMPT'));
    assert.ok(filtered.body.events[0].details.sample !== undefined, 'details llega como objeto');

    const page = await api(app.base, 'GET', '/api/system/security-events?hours=1&limit=1', { ip: ipUser, token: user.token });
    assert.strictEqual(page.body.events.length, 1);
    assert.ok(page.body.nextBefore);
    const next = await api(app.base, 'GET', `/api/system/security-events?hours=1&limit=1&before=${page.body.nextBefore}`, { ip: ipUser, token: user.token });
    assert.ok(next.body.events[0].id < page.body.events[0].id);

    assert.strictEqual((await api(app.base, 'GET', '/api/system/security-events?severity=extremo', { ip: ipUser, token: user.token })).status, 400);
    const sqli = await api(app.base, 'GET', `/api/system/security-events?type=${encodeURIComponent("' OR '1'='1")}`, { ip: testIp(), token: user.token });
    assert.ok([400, 403].includes(sqli.status));

    const summary = await api(app.base, 'GET', '/api/system/security-summary?hours=1', { ip: ipUser, token: user.token });
    assert.strictEqual(summary.status, 200);
    assert.ok(summary.body.summary.byType.length > 0 && summary.body.summary.topIps.length > 0 && summary.body.summary.timeline.length > 0);
    assert.ok(summary.body.summary.topRules.some(r => /SQLI/.test(r.rule)));

    // La tabla de análisis nunca guarda contraseñas ni tokens
    const [leaks] = await db.query(
        "SELECT COUNT(*) AS n FROM security_events WHERE CONCAT_WS(' ', details, path, user_agent) LIKE ? OR CONCAT_WS(' ', details, path) LIKE '%Bearer%' OR CONCAT_WS(' ', details, path) LIKE ?",
        [`%${PASSWORD}%`, `%${user.token.slice(0, 40)}%`]
    );
    assert.strictEqual(leaks[0].n, 0);
});

itDb('eventos: se redactan campos sensibles y se acota el tamaño', async () => {
    const ip = testIp();
    await events.record({ type: 'PRUEBA_REDACCION', ip, details: { password: 'x', nested: { apiKey: 'y', token: 'z', ok: 'visible' }, big: 'a'.repeat(5000) } });
    const [row] = await eventsOf(ip, 'PRUEBA_REDACCION');
    const details = JSON.parse(row.details);
    assert.strictEqual(details.password, '[redactado]');
    assert.strictEqual(details.nested.apiKey, '[redactado]');
    assert.strictEqual(details.nested.token, '[redactado]');
    assert.strictEqual(details.nested.ok, 'visible');
    assert.ok(details.big.length <= 301);
});

itDb('limpieza: purga contadores y eventos antiguos y no toca lo reciente', async () => {
    const housekeeping = require('./src/tasks/securityHousekeeping');
    await db.query("INSERT INTO rate_limit_counters (scope, subject, window_start, hits) VALUES ('old', 'x', 1000, 5)");
    await db.query("INSERT INTO security_events (event_type, ip_address, created_at) VALUES ('VIEJO', '198.51.100.250', DATE_SUB(NOW(), INTERVAL 400 DAY))");
    await db.query("INSERT INTO security_events (event_type, ip_address) VALUES ('RECIENTE', '198.51.100.251')");

    const result = await housekeeping.runOnce();
    assert.ok(result.rateLimitCounters >= 1 && result.securityEvents >= 1);

    assert.strictEqual((await db.query("SELECT 1 FROM rate_limit_counters WHERE scope = 'old'"))[0].length, 0);
    assert.strictEqual((await eventsOf('198.51.100.250')).length, 0);
    assert.strictEqual((await eventsOf('198.51.100.251')).length, 1);
});

itDb('inundación de eventos: el tope por (IP, tipo) protege la tabla y deja una marca EVENTS_THROTTLED', async () => {
    await withEnv({ SECURITY_EVENTS_MAX_PER_MINUTE: '10' }, async () => {
        const ip = testIp();
        await waitForFreshWindow();
        for (let i = 0; i < 60; i++) await events.record({ type: 'INUNDACION_PRUEBA', rule: 'X', ip });

        assert.strictEqual((await eventsOf(ip, 'INUNDACION_PRUEBA')).length, 10, 'solo se guardan 10');
        const marks = await eventsOf(ip, 'EVENTS_THROTTLED');
        assert.strictEqual(marks.length, 1, 'una sola marca que lo señala');
        assert.strictEqual(marks[0].rule, 'INUNDACION_PRUEBA');

        // otros tipos y otras IP no se ven afectados; los eventos graves nunca se descartan
        await events.record({ type: 'OTRO_TIPO', ip });
        assert.strictEqual((await eventsOf(ip, 'OTRO_TIPO')).length, 1);
        for (let i = 0; i < 15; i++) await events.record({ type: 'IP_BLOCKED', ip });
        assert.strictEqual((await eventsOf(ip, 'IP_BLOCKED')).length, 15);
    });
});
