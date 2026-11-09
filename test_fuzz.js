// FUZZING con propiedades (fast-check): entradas aleatorias y mutadas contra los componentes que procesan datos hostiles.
// No sustituye a un fuzzer de cobertura (AFL/libFuzzer) ni a un pentest, pero atrapa la clase de fallo más común:
// una excepción no controlada, un 500, una fuga de traza, un bucle lento (ReDoS) o una invariante de seguridad rota.
//
//   npm run test:fuzz                     (FUZZ_RUNS=500 para más iteraciones; FUZZ_SEED=<n> repite una ejecución)
//
// Si una propiedad falla, fast-check imprime la semilla y el contraejemplo reducido: ponlo como caso fijo en la suite
// correspondiente (test_security.js, test_files.js…) para que no vuelva.

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { pipeline } = require('stream/promises');
const { Readable } = require('stream');
const fc = require('fast-check');

const { filesDir } = require('./test_helpers/env');
const helpers = require('./test_helpers/app');
const { api, registerAndLogin, testIp } = helpers;

const RUNS = Number(process.env.FUZZ_RUNS) || 100;
const SEED = process.env.FUZZ_SEED ? Number(process.env.FUZZ_SEED) : undefined;
const cfg = (runs = RUNS, extra = {}) => ({ numRuns: Math.max(1, Math.round(runs)), seed: SEED, ...extra }); // numRuns debe ser entero: con fracción fast-check no termina

const types = require('./src/files/file-types');
const cipher = require('./src/files/file-cipher');
const sanitize = require('./src/files/sanitize');
const detector = require('./src/security/injection-detector');
const { sqlInt, sqlPlaceholders, sqlFragment } = require('./src/config/sql');
const { can, PERMISSIONS } = require('./src/security/permissions');
const { UploadError } = require('./src/files/upload');
const enc = require('./src/crypto/tripleEncryptor');

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'fuzz-'));
test.after(() => { fs.rmSync(tmp, { recursive: true, force: true }); fs.rmSync(filesDir, { recursive: true, force: true }); });

const bytes = fc.uint8Array({ maxLength: 4096 }).map(a => Buffer.from(a));
const anyString = fc.oneof(fc.string({ maxLength: 300 }), fc.string({ unit: 'binary', maxLength: 300 }), fc.fullUnicodeString({ maxLength: 300 }));
// Caracteres bidi / invisibles construidos desde su código (sin escribirlos literales en el fuente)
const INVISIBLE = new RegExp(`[${[0x200b, 0x200c, 0x200d, 0x200e, 0x200f, 0x202a, 0x202b, 0x202c, 0x202d, 0x202e, 0x2060, 0x2066, 0x2067, 0x2068, 0x2069, 0xfeff].map(c => String.fromCodePoint(c)).join('')}]`);
const CONTROL = new RegExp(`[${String.fromCharCode(0)}-${String.fromCharCode(0x1f)}${String.fromCharCode(0x7f)}-${String.fromCharCode(0x9f)}]`);

// ============================================================================ tipos de archivo y nombres

test('fuzz: detectType nunca lanza y devuelve un resultado bien formado', () => {
    fc.assert(fc.property(bytes, (head) => {
        const r = types.detectType(head);
        assert.ok(r === null || (typeof r === 'object' && (typeof r.mime === 'string' || typeof r.rejected === 'string')));
        types.looksLikeText(head); types.hasActiveContent(head);
    }), cfg());
});

test('fuzz: una cabecera de ejecutable/script se rechaza SIEMPRE, sea lo que sea lo que sigue', () => {
    const magics = [[0x4d, 0x5a], [0x7f, 0x45, 0x4c, 0x46], [0xcf, 0xfa, 0xed, 0xfe], [0xca, 0xfe, 0xba, 0xbe], [0x23, 0x21]];
    fc.assert(fc.property(fc.constantFrom(...magics), bytes, (magic, tail) => {
        assert.strictEqual(types.detectType(Buffer.concat([Buffer.from(magic), tail, Buffer.alloc(4)]))?.rejected, 'EXECUTABLE_CONTENT');
    }), cfg());
});

test('fuzz: sanitizeFilename — nunca vacío, sin rutas, controles ni bidi, ≤ 120 y estable al repetirse', () => {
    fc.assert(fc.property(anyString, (raw) => {
        const name = types.sanitizeFilename(raw);
        assert.ok(name.length > 0 && name.length <= 121, `longitud ${name.length}`);
        assert.ok(!/[\\/]/.test(name) && !CONTROL.test(name) && !INVISIBLE.test(name));
        assert.ok(!name.startsWith('.') && name !== '..');
        assert.strictEqual(types.sanitizeFilename(name), name, 'idempotente');
        const header = types.contentDisposition(name);
        assert.ok(!/[\r\n]/.test(header) && /^[\x20-\x7e]+$/.test(header), 'cabecera segura (solo ASCII imprimible)');
    }), cfg(RUNS * 3));
});

// ============================================================================ cifrado

test('fuzz: cifrado de campos — ida y vuelta para cualquier texto; cualquier alteración se detecta', () => {
    fc.assert(fc.property(fc.oneof(anyString, fc.constant('')), fc.nat(), (text, where) => {
        const c1 = enc.encrypt(text), c2 = enc.encrypt(text);
        assert.notStrictEqual(c1, c2, 'IV distinto en cada cifrado');
        assert.strictEqual(enc.decrypt(c1), text);

        const i = 3 + (where % (c1.length - 3));                // no se toca el prefijo "v4:"
        const swapped = c1[i] === 'A' ? 'B' : 'A';
        const tampered = c1.slice(0, i) + swapped + c1.slice(i + 1);
        assert.throws(() => { if (enc.decrypt(tampered) === text) throw new Error('alteración aceptada'); });
    }), cfg(RUNS));
});

test('fuzz: descifrar basura aleatoria lanza, nunca devuelve texto ni cuelga', () => {
    fc.assert(fc.property(anyString, (junk) => {
        for (const candidate of [junk, `v4:${junk}`, `v4:${Buffer.from(junk).toString('base64')}`]) {
            let out;
            try { out = enc.decrypt(candidate); } catch { continue; }
            assert.fail(`aceptó basura: ${JSON.stringify(candidate).slice(0, 60)} → ${JSON.stringify(out).slice(0, 40)}`);
        }
    }), cfg());
});

async function encryptToFile(plain, key) {
    const file = path.join(tmp, crypto.randomUUID());
    await pipeline(Readable.from([plain]), new cipher.EncryptStream(key), fs.createWriteStream(file));
    return file;
}
async function readRange(file, key, size, start, end) {
    const parts = [];
    for await (const part of cipher.decryptRange({ filePath: file, key, plainSize: size, start, end })) parts.push(part);
    return Buffer.concat(parts);
}

test('fuzz: archivo cifrado por bloques — cualquier rango devuelve exactamente esos bytes', async () => {
    await fc.assert(fc.asyncProperty(
        fc.integer({ min: 0, max: cipher.CHUNK * 2 + 5000 }), fc.nat(), fc.nat(),
        async (size, a, b) => {
            const plain = crypto.randomBytes(size), key = cipher.newDataKey();
            const file = await encryptToFile(plain, key);
            try {
                if (size === 0) { assert.strictEqual((await readRange(file, key, 0)).length, 0); return; }
                let start = a % size, end = b % size;
                if (start > end) [start, end] = [end, start];
                assert.ok((await readRange(file, key, size, start, end)).equals(plain.subarray(start, end + 1)));
            } finally { fs.rmSync(file, { force: true }); }
        }
    ), cfg(Math.max(10, RUNS / 4)));
});

test('fuzz: cambiar UN byte cualquiera del archivo cifrado (o truncarlo) se detecta al leerlo', async () => {
    await fc.assert(fc.asyncProperty(
        fc.integer({ min: 1, max: cipher.CHUNK + 3000 }), fc.nat(), fc.boolean(),
        async (size, where, truncate) => {
            const plain = crypto.randomBytes(size), key = cipher.newDataKey();
            const file = await encryptToFile(plain, key);
            try {
                const raw = fs.readFileSync(file);
                if (truncate) fs.writeFileSync(file, raw.subarray(0, where % raw.length));
                else { raw[where % raw.length] ^= 0x01; fs.writeFileSync(file, raw); }
                await assert.rejects(readRange(file, key, size, 0, size - 1));
            } finally { fs.rmSync(file, { force: true }); }
        }
    ), cfg(Math.max(10, RUNS / 4)));
});

test('fuzz: parseRange — nunca lanza; si acepta, 0 ≤ inicio ≤ fin < tamaño', () => {
    const header = fc.oneof(
        fc.string({ maxLength: 40 }),
        fc.tuple(fc.nat({ max: 1e12 }), fc.nat({ max: 1e12 })).map(([x, y]) => `bytes=${x}-${y}`),
        fc.nat({ max: 1e12 }).map(x => `bytes=-${x}`), fc.nat({ max: 1e12 }).map(x => `bytes=${x}-`),
        fc.constantFrom('bytes=0-0,5-9', 'bytes=--5', 'bytes=1e3-2e3', 'bytes= 5-9', `bytes=${'9'.repeat(40)}-`)
    );
    fc.assert(fc.property(header, fc.integer({ min: 0, max: 5e9 }), (h, size) => {
        const r = cipher.parseRange(h, size);
        if (r && r !== 'unsatisfiable') assert.ok(Number.isSafeInteger(r.start) && Number.isSafeInteger(r.end) && r.start >= 0 && r.start <= r.end && r.end < size, JSON.stringify([h, size, r]));
    }), cfg(RUNS * 5));
});

// ============================================================================ detector de inyección

const timed = (fn) => { const t = process.hrtime.bigint(); const out = fn(); return { out, ms: Number(process.hrtime.bigint() - t) / 1e6 }; };

test('fuzz: el detector nunca lanza y nunca tarda (sin ReDoS) con texto aleatorio o patológico', () => {
    const pathological = fc.oneof(
        anyString,
        fc.constantFrom('select ', 'union ', "' or ", '<a ', '/*', '--', '%25', '${', 'or 1=', '<svg ').chain(piece => fc.integer({ min: 1, max: 2500 }).map(n => piece.repeat(n))),
        fc.array(fc.constantFrom('%', '2', '5', 'e', '0', '/', '*', '!', '<', '>', '"', "'", ' '), { maxLength: 6000 }).map(a => a.join(''))
    );
    fc.assert(fc.property(pathological, (text) => {
        const { out, ms } = timed(() => detector.scanText(text, { location: 'body', field: 'x', bodyLike: true }));
        assert.ok(Array.isArray(out));
        assert.ok(ms < 250, `${ms.toFixed(0)} ms para ${text.length} caracteres`);
    }), cfg(RUNS * 2));
});

test('fuzz: scanObject soporta JSON arbitrario, muy anidado o con claves hostiles', () => {
    const hostileKey = fc.constantFrom('__proto__', 'constructor', 'prototype', '$ne', '$where', 'a.b', '');
    const json = fc.letrec(tie => ({
        node: fc.oneof({ maxDepth: 12 }, fc.jsonValue(), fc.array(tie('node'), { maxLength: 4 }), fc.dictionary(fc.oneof(fc.string({ maxLength: 8 }), hostileKey), tie('node'), { maxKeys: 4 }))
    })).node;
    fc.assert(fc.property(json, (value) => {
        const { out, ms } = timed(() => detector.scanObject(value, 'body', true));
        assert.ok(Array.isArray(out) && ms < 250, `${ms} ms`);
    }), cfg());
    // Un objeto de 5000 niveles no tumba el proceso
    let deep = {}; const root = deep;
    for (let i = 0; i < 5000; i++) { deep.a = {}; deep = deep.a; }
    assert.doesNotThrow(() => detector.scanObject(root, 'body', true));
});

test('fuzz: ataques conocidos se siguen detectando con mayúsculas, espacios, comentarios y codificación mezclados', () => {
    const sep = fc.constantFrom(' ', '  ', '\t', '\n', '/**/', ' /**/ ', '%20');
    const rand = (word) => fc.array(fc.boolean(), { minLength: word.length, maxLength: word.length }).map(flags => [...word].map((c, i) => (flags[i] ? c.toUpperCase() : c)).join(''));
    const attack = fc.oneof(
        fc.tuple(rand('union'), sep, rand('select')).map(([a, s, b]) => ({ text: `1${s}${a}${s}${b}${s}1,2,3`, rule: 'SQLI_UNION' })),
        fc.tuple(rand('script')).map(([s]) => ({ text: `<${s}>alert(1)</${s}>`, rule: 'XSS_SCRIPT_TAG' })),
        fc.tuple(fc.constantFrom('../', '..\\', '%2e%2e/', '%2e%2e%2f', '..%2f', '....//')).map(([t]) => ({ text: `${t.repeat(4)}etc/passwd`, family: 'PATH_TRAVERSAL' }))
    );
    fc.assert(fc.property(attack, fc.constantFrom(null, 'url', 'twice'), ({ text, rule, family }, wrap) => {
        fc.pre(!(wrap === 'twice' && text.includes('%')));   // %20 ya codificado + doble codificación = tres capas: fuera del contrato (dos pasadas)
        let payload = text;
        if (wrap === 'url') payload = encodeURIComponent(text);
        if (wrap === 'twice') payload = encodeURIComponent(encodeURIComponent(text));
        const found = detector.scanText(payload, { location: 'query', field: 'q', bodyLike: false });
        assert.ok(found.some(f => (rule ? f.rule === rule : f.family === family) && f.severity === 'high'),
            `no detectado: ${JSON.stringify(payload)} → ${found.map(f => f.rule)}`);
    }), cfg(RUNS * 2));
});

// ============================================================================ SQL y permisos

test('fuzz: sqlInt/sqlPlaceholders/sqlFragment — solo producen texto seguro o lanzan', () => {
    fc.assert(fc.property(fc.anything(), (value) => {
        try {
            const out = sqlInt(value);
            assert.match(out, /^\d{1,16}$/);
        } catch (error) { assert.ok(error instanceof RangeError || error instanceof TypeError, String(error)); }
        try { assert.match(sqlPlaceholders(value), /^\?(, \?){0,999}$/); } catch (error) { assert.ok(error instanceof RangeError || error instanceof TypeError); }
        try { assert.match(sqlFragment(value), /^[A-Za-z_ ()<>=.]+$/); } catch (error) { assert.ok(error instanceof RangeError); }
    }), cfg(RUNS * 3));
});

test('fuzz: permisos — un rol inventado nunca tiene ningún permiso; los admin-only no se abren a otros roles', () => {
    fc.assert(fc.property(fc.oneof(fc.string(), fc.constantFrom('__proto__', 'constructor', 'Admin', 'ADMIN', 'root', ' admin', 'admin ', 'admin\0')), (role) => {
        for (const permission of Object.keys(PERMISSIONS)) assert.strictEqual(can(role, permission), false, `${permission} abierto a ${JSON.stringify(role)}`);
    }), cfg());
    assert.throws(() => can('admin', 'permiso:inexistente'));
});

// ============================================================================ PDF e imágenes

// Las que sanitize.js rechaza (OpenAction/AA solos no son peligrosos: lo que ejecutan sí está en la lista)
const DANGEROUS = ['JavaScript', 'JS', 'Launch', 'EmbeddedFile', 'EmbeddedFiles', 'EF', 'FileAttachment', 'RichMedia', 'SubmitForm', 'ImportData', 'GoToR', 'GoToE', 'Rendition', 'Movie', 'Sound', 'XFA', 'Encrypt'];
const hexEscape = (name, mask) => [...name].map((c, i) => (mask[i % mask.length] ? `#${c.charCodeAt(0).toString(16).padStart(2, '0')}` : c)).join('');

test('fuzz: PDF — contenido activo ofuscado con #hex se rechaza; basura aleatoria jamás lanza algo que no sea UploadError', () => {
    fc.assert(fc.property(fc.constantFrom(...DANGEROUS), fc.array(fc.boolean(), { minLength: 1, maxLength: 12 }), bytes, bytes, (name, mask, before, after) => {
        const pdf = Buffer.concat([Buffer.from('%PDF-1.7\n'), before, Buffer.from(`\n1 0 obj\n<< /${hexEscape(name, mask)} (x) >>\nendobj\n`), after, Buffer.from('\n%%EOF')]);
        assert.throws(() => sanitize.inspectPdf(pdf, UploadError), (e) => e instanceof UploadError, `${name} ofuscado no se rechazó`);
    }), cfg(RUNS));

    fc.assert(fc.property(bytes, (junk) => {
        try { sanitize.inspectPdf(Buffer.concat([Buffer.from('%PDF-1.4\n'), junk]), UploadError); } catch (e) { assert.ok(e instanceof UploadError, e.stack); }
    }), cfg(RUNS));
});

test('fuzz: PDF con streams Flate corruptos o en bomba no agotan memoria ni tiempo', () => {
    const zlib = require('zlib');
    fc.assert(fc.property(bytes, fc.boolean(), (junk, bomb) => {
        const payload = bomb ? zlib.deflateSync(Buffer.alloc(40 * 1024 * 1024)) : junk;
        const pdf = Buffer.concat([Buffer.from('%PDF-1.5\n1 0 obj\n<< /Type /ObjStm /Filter /FlateDecode /N 1 /First 5 >>\nstream\n'), payload, Buffer.from('\nendstream\nendobj\n%%EOF')]);
        const { ms } = timed(() => { try { sanitize.inspectPdf(pdf, UploadError); } catch (e) { assert.ok(e instanceof UploadError, e.stack); } });
        assert.ok(ms < 3000, `${ms} ms`);
    }), cfg(Math.max(10, RUNS / 5)));
});

test('fuzz: imágenes — bytes aleatorios con cabecera de imagen se rechazan con UploadError, sin colgar el proceso', async () => {
    const headers = { 'image/jpeg': [0xff, 0xd8, 0xff, 0xe0], 'image/png': [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a], 'image/gif': [0x47, 0x49, 0x46, 0x38, 0x39, 0x61], 'image/webp': [0x52, 0x49, 0x46, 0x46, 0, 0, 0, 0, 0x57, 0x45, 0x42, 0x50] };
    await fc.assert(fc.asyncProperty(fc.constantFrom(...Object.keys(headers)), bytes, async (mime, junk) => {
        try { await sanitize.sanitizeImage(Buffer.concat([Buffer.from(headers[mime]), junk]), mime, UploadError); }
        catch (e) { assert.ok(e instanceof UploadError, e.stack); assert.ok(!/\/home\/|node_modules/.test(e.message)); }
    }), cfg(Math.max(15, RUNS / 3)));
});

// ============================================================================ HTTP: todas las rutas documentadas

let dbAvailable = false, app, db;
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

const SKIP = new Set(['POST /api/system/rotate-keys', 'POST /api/system/test-communications', 'POST /api/system/integrity-check']); // lanzan trabajo real
const documented = () => {
    const spec = require('./docs/openapi.json');
    const out = [];
    for (const [route, ops] of Object.entries(spec.paths)) {
        for (const method of Object.keys(ops).filter(m => ['get', 'post', 'put', 'patch', 'delete'].includes(m))) {
            if (!SKIP.has(`${method.toUpperCase()} ${route}`)) out.push({ method: method.toUpperCase(), route });
        }
    }
    return out;
};

const pathParam = fc.oneof(fc.nat(), fc.constantFrom('0', '-1', '99999999999999999999', '%00', '..%2f..%2fetc', '1;DROP TABLE users', "' OR '1'='1", 'null', '[]', '1e3'), fc.string({ maxLength: 40 }).map(encodeURIComponent));
const queryValue = fc.oneof(fc.string({ maxLength: 60 }), fc.nat().map(String), fc.constantFrom('-1', '1e9', 'NaN', '[]', '{}', '%', '\u0000', 'a'.repeat(3000)));
const bodyValue = fc.oneof(fc.jsonValue({ maxDepth: 4 }), fc.dictionary(fc.string({ maxLength: 12 }), fc.oneof(fc.jsonValue({ maxDepth: 2 }), fc.string({ maxLength: 200 })), { maxKeys: 8 }));

function fill(route, values) {
    let i = 0;
    return route.replace(/\{[^}]+\}/g, () => values[i++ % values.length]);
}

async function actor(role) {
    if (role === 'anon') return { token: undefined };
    const user = await registerAndLogin(app.base, { ip: testIp() });
    if (role === 'admin') {
        await db.query("UPDATE users SET role = 'admin' WHERE id = ?", [user.userId]);
    }
    return user;
}

test('fuzz HTTP: ninguna ruta documentada responde 5xx ni filtra trazas, con cualquier rol y entradas hostiles', async (t) => {
    if (!dbAvailable) return t.skip('sin base de datos');
    const roles = ['anon', 'user', 'admin'];
    const routes = documented();
    assert.ok(routes.length >= 50, `solo ${routes.length} rutas en la especificación`);

    for (const role of roles) {
        for (const { method, route } of routes) {
            const user = await actor(role);
            await fc.assert(fc.asyncProperty(
                fc.array(pathParam, { minLength: 1, maxLength: 3 }),
                fc.dictionary(fc.string({ maxLength: 10 }).filter(k => k.length > 0), queryValue, { maxKeys: 4 }),
                bodyValue,
                fc.constantFrom('json', 'json', 'text', 'badjson', 'none'),
                async (ids, query, body, kind) => {
                    const qs = new URLSearchParams(query).toString();
                    const url = `${fill(route, ids)}${qs ? `?${qs}` : ''}`;
                    const options = { token: user.token, ip: testIp() };
                    if (method !== 'GET' && method !== 'DELETE') {
                        if (kind === 'json') options.json = body;
                        else if (kind === 'text') { options.raw = JSON.stringify(body); options.headers = { 'Content-Type': 'text/plain' }; }
                        else if (kind === 'badjson') { options.raw = JSON.stringify(body).slice(0, -1) + '}}'; options.headers = { 'Content-Type': 'application/json' }; }
                    }
                    const res = await api(app.base, method, url, options);
                    assert.ok(res.status < 500, `${role} ${method} ${url} → ${res.status}: ${res.text.slice(0, 200)}`);
                    // Trazas y errores de SQL no salen nunca; las rutas del servidor tampoco, salvo a un admin (el estado del sistema
                    // enumera sus archivos críticos a propósito)
                    const leak = role === 'admin' ? /\n\s+at .*\(|\bER_[A-Z_]+|mysql2?:/i : /\n\s+at .*\(|node_modules|\/home\/|\bER_[A-Z_]+|mysql2?/i;
                    assert.ok(!leak.test(res.text), `fuga de detalles (${role}) en ${method} ${url}: ${res.text.slice(0, 300)}`);
                }
            ), cfg(Math.max(5, Math.round(RUNS / 10))));
        }
    }
});

test('fuzz HTTP: subida de archivos con multipart malformado y contenido aleatorio — nunca 5xx ni archivos huérfanos', async (t) => {
    if (!dbAvailable) return t.skip('sin base de datos');
    process.env.IMAGE_SANITIZE = 'on';
    const user = await registerAndLogin(app.base, { ip: testIp() });
    const left = () => (fs.existsSync(path.join(filesDir, 'tmp')) ? fs.readdirSync(path.join(filesDir, 'tmp')).length : 0);
    const before = left();

    await fc.assert(fc.asyncProperty(bytes, anyString, fc.constantFrom('file', 'otro', ''), fc.boolean(), async (data, name, field, malformed) => {
        let res;
        if (malformed) {
            const boundary = '----fuzz' + crypto.randomBytes(4).toString('hex');
            const body = Buffer.concat([Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="${field}"; filename="${name.replace(/["\r\n]/g, '')}"\r\n\r\n`), data]); // sin cierre
            res = await api(app.base, 'POST', '/api/files', { token: user.token, ip: testIp(), raw: body, headers: { 'Content-Type': `multipart/form-data; boundary=${boundary}` } });
        } else {
            const form = new FormData();
            form.append(field || 'file', new Blob([data]), name || 'x');
            res = await api(app.base, 'POST', '/api/files', { token: user.token, ip: testIp(), form });
        }
        assert.ok(res.status < 500, `${res.status}: ${res.text.slice(0, 200)}`);
    }), cfg(Math.max(20, RUNS / 2)));

    assert.strictEqual(left(), before, 'quedaron temporales de subidas fallidas');
    const [[{ n }]] = await db.query('SELECT COUNT(*) AS n FROM user_files WHERE user_id = ?', [user.userId]);
    const stored = fs.existsSync(path.join(filesDir, 'files')) ? fs.readdirSync(path.join(filesDir, 'files'), { recursive: true }).filter(f => /[0-9a-f-]{36}/.test(f)).length : 0;
    assert.ok(stored >= n, 'hay filas sin archivo');
});
