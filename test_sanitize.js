// Saneamiento de archivos: imágenes recodificadas y PDF inspeccionados, con archivos REALES y de ataque.
// Integración con MariaDB real y el servidor real.
//
//   npm run test:sanitize

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const fs = require('fs');
const zlib = require('zlib');
const sharp = require('sharp');

const { filesDir } = require('./test_helpers/env');
const helpers = require('./test_helpers/app');
const { api, registerAndLogin, testIp } = helpers;
const sanitize = require('./src/files/sanitize');

let app, db, enabled = false, user, ip;
test.before(async () => {
    enabled = await helpers.prepareDatabase();
    if (!enabled) return;
    db = require('./src/config/database');
    app = await helpers.startApp();
    ip = testIp();
    user = await registerAndLogin(app.base, { ip });
});
test.after(async () => {
    if (app) await app.close();
    if (db?.pool) await db.pool.end();
    fs.rmSync(filesDir, { recursive: true, force: true });
});
const itDb = (name, fn) => test(name, async (t) => { if (!enabled) return t.skip('sin BD'); await fn(t); });
const withEnv = async (vars, fn) => {
    const saved = Object.fromEntries(Object.keys(vars).map(k => [k, process.env[k]]));
    Object.assign(process.env, vars);
    try { return await fn(); } finally {
        for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
    }
};

const multipart = (data, name) => { const f = new FormData(); f.append('file', new Blob([data]), name); return f; };
// Cada subida sale de una IP distinta: varios rechazos graves seguidos desde la misma bloquean la IP (y eso funciona)
const upload = (data, name, who = user, from = testIp()) => api(app.base, 'POST', '/api/files', { token: who.token, ip: from, form: multipart(data, name) });
const download = (id) => api(app.base, 'GET', `/api/files/${id}/download`, { token: user.token, ip });
const rejectedEvents = async (rule) => (await db.query("SELECT * FROM security_events WHERE ip_address = ? AND event_type = 'FILE_REJECTED' AND rule = ?", [ip, rule]))[0];
const storedCount = () => { const dir = `${filesDir}/files`; let n = 0; (function walk(d) { if (!fs.existsSync(d)) return; for (const e of fs.readdirSync(d, { withFileTypes: true })) e.isDirectory() ? walk(`${d}/${e.name}`) : n++; })(dir); return n; };

// ------------------------------------------------------------------ fabricación de archivos

const solid = (w, h, color = '#336699') => ({ create: { width: w, height: h, channels: 3, background: color } });
const SECRET = 'SECRET-COPYRIGHT-GPS-37.77,-122.41';

// JPEG con EXIF (autor + giro de 90°) y un comentario COM, y datos extra detrás del final del archivo
async function dirtyJpeg() {
    const base = await sharp(solid(40, 20)).withMetadata({ orientation: 6, exif: { IFD0: { Copyright: SECRET } } }).jpeg().toBuffer();
    const trailer = Buffer.from('\n<?php system($_GET["c"]); ?>PK\u0003\u0004<script>alert(1)</script>');
    return Buffer.concat([base, trailer]);
}

function pngChunk(type, data) {
    const body = Buffer.concat([Buffer.from(type, 'ascii'), data]);
    const out = Buffer.alloc(12 + data.length);
    out.writeUInt32BE(data.length, 0);
    body.copy(out, 4);
    out.writeUInt32BE(zlib.crc32(body), 8 + data.length);
    return out;
}
// PNG real con un chunk tEXt que lleva un secreto
async function pngWithText() {
    const png = await sharp(solid(24, 24, '#aa3300')).png().toBuffer();
    const ihdrEnd = 8 + 12 + 13;
    return Buffer.concat([png.subarray(0, ihdrEnd), pngChunk('tEXt', Buffer.from(`Comment\0${SECRET}`)), png.subarray(ihdrEnd)]);
}

// ------------------------------------------------------------------ imágenes

itDb('JPEG con EXIF, giro y datos ocultos tras el final: sale limpio, derecho y sin el código incrustado', async () => {
    const dirty = await dirtyJpeg();
    assert.ok(dirty.includes(Buffer.from(SECRET)) && dirty.includes(Buffer.from('<?php')), 'el archivo de prueba está sucio');

    const up = await upload(dirty, 'foto.jpg');
    assert.strictEqual(up.status, 201, up.text);
    assert.strictEqual(up.body.file.sanitizeStatus, 'reencoded');

    const down = await download(up.body.file.id);
    assert.strictEqual(down.status, 200);
    const clean = down.buffer;
    for (const needle of [SECRET, '<?php', '<script', 'PK\u0003\u0004', 'Copyright']) assert.ok(!clean.includes(Buffer.from(needle)), `quedó "${needle}"`);

    const meta = await sharp(clean).metadata();
    assert.strictEqual(meta.format, 'jpeg');
    assert.strictEqual(meta.exif, undefined, 'sin EXIF');
    assert.deepStrictEqual([meta.width, meta.height], [20, 40], 'la orientación EXIF se aplicó antes de quitarla (40x20 girado 90°)');
    assert.strictEqual(meta.orientation, undefined);

    // Coherencia: lo almacenado es lo saneado (tamaño y hash)
    assert.strictEqual(up.body.file.size, clean.length);
    assert.strictEqual(up.body.file.sha256, crypto.createHash('sha256').update(clean).digest('hex'));
    assert.ok(clean.length < dirty.length);
});

itDb('PNG con chunk tEXt secreto: el secreto desaparece y la imagen sigue siendo la misma', async () => {
    const dirty = await pngWithText();
    assert.ok(dirty.includes(Buffer.from(SECRET)));
    const up = await upload(dirty, 'logo.png');
    assert.strictEqual(up.status, 201, up.text);
    const clean = (await download(up.body.file.id)).buffer;
    assert.ok(!clean.includes(Buffer.from(SECRET)) && !clean.includes(Buffer.from('tEXt')));
    const before = await sharp(dirty).raw().toBuffer();
    const after = await sharp(clean).raw().toBuffer();
    assert.ok(before.equals(after), 'los píxeles son idénticos (PNG sin pérdida)');
});

itDb('WebP, GIF animado y AVIF se sanean conservando formato y fotogramas', async () => {
    const red = await sharp(solid(16, 16, '#f00')).png().toBuffer();
    const blue = await sharp(solid(16, 16, '#00f')).png().toBuffer();
    const samples = {
        'a.webp': await sharp(solid(32, 32)).withMetadata({ exif: { IFD0: { Copyright: SECRET } } }).webp().toBuffer(),
        'a.gif': await sharp([red, blue], { join: { animated: true } }).gif().toBuffer(),
        'a.avif': await sharp(solid(32, 32)).avif().toBuffer()
    };
    const expected = { 'a.webp': ['webp', 1], 'a.gif': ['gif', 2], 'a.avif': ['heif', 1] };
    for (const [name, data] of Object.entries(samples)) {
        const up = await upload(data, name);
        assert.strictEqual(up.status, 201, `${name}: ${up.text}`);
        assert.strictEqual(up.body.file.sanitizeStatus, 'reencoded', name);
        const meta = await sharp((await download(up.body.file.id)).buffer, { animated: true }).metadata();
        assert.deepStrictEqual([meta.format, meta.pages || 1], expected[name], name);
    }
});

itDb('imagen con cabecera válida pero contenido corrupto → 422 IMAGE_INVALID, evento y nada almacenado', async () => {
    const before = storedCount();
    const broken = Buffer.concat([Buffer.from('ffd8ffe000104a46494600010100000100010000', 'hex'), crypto.randomBytes(3000)]);
    const up = await upload(broken, 'rota.jpg', user, ip);
    assert.strictEqual(up.status, 422);
    assert.strictEqual(up.body.code, 'IMAGE_INVALID');
    assert.strictEqual(storedCount(), before, 'no quedó nada en disco');
    assert.ok((await rejectedEvents('IMAGE_INVALID')).length >= 1);
});

itDb('bomba de descompresión: PNG diminuto que declara 30000x30000 px se rechaza sin decodificarlo', async () => {
    const png = await sharp(solid(8, 8)).png().toBuffer();
    const ihdr = Buffer.alloc(13);
    ihdr.writeUInt32BE(30000, 0); ihdr.writeUInt32BE(30000, 4); ihdr.writeUInt8(8, 8); ihdr.writeUInt8(2, 9);
    const bomb = Buffer.concat([png.subarray(0, 8), pngChunk('IHDR', ihdr), png.subarray(8 + 12 + 13)]);
    const started = Date.now();
    const up = await upload(bomb, 'bomba.png');
    assert.strictEqual(up.status, 422, up.text);
    assert.ok(Date.now() - started < 5000, 'se rechaza rápido');

    // y el límite se puede bajar: una imagen de 20x20 con IMAGE_MAX_PIXELS=100
    const small = await sharp(solid(20, 20)).png().toBuffer();
    await withEnv({ IMAGE_MAX_PIXELS: '100' }, async () => {
        assert.strictEqual((await upload(small, 'grande.png')).status, 422);
    });
    assert.strictEqual((await upload(small, 'normal.png')).status, 201);
});

itDb('HEIC no se puede sanear: se rechaza; el operador puede aceptarlo sin sanear con IMAGE_SANITIZE_PASSTHROUGH', async () => {
    const heic = Buffer.concat([Buffer.from([0, 0, 0, 24]), Buffer.from('ftypheic'), Buffer.alloc(8), crypto.randomBytes(600)]);
    const denied = await upload(heic, 'foto.heic');
    assert.strictEqual(denied.status, 415);
    assert.strictEqual(denied.body.code, 'IMAGE_NOT_SANITIZABLE');

    await withEnv({ IMAGE_SANITIZE_PASSTHROUGH: 'heic' }, async () => {
        const ok = await upload(heic, 'foto.heic');
        assert.strictEqual(ok.status, 201, ok.text);
        assert.strictEqual(ok.body.file.sanitizeStatus, 'none', 'se guardó sin sanear y consta así');
        assert.ok((await download(ok.body.file.id)).buffer.equals(heic));
    });
});

itDb('IMAGE_SANITIZE=off guarda la imagen tal cual (consta como none)', async () => {
    const dirty = await dirtyJpeg();
    await withEnv({ IMAGE_SANITIZE: 'off' }, async () => {
        const up = await upload(dirty, 'tal-cual.jpg');
        assert.strictEqual(up.status, 201);
        assert.strictEqual(up.body.file.sanitizeStatus, 'none');
        assert.ok((await download(up.body.file.id)).buffer.equals(dirty));
    });
});

itDb('varias imágenes a la vez con SANITIZE_MAX_CONCURRENT=1: todas terminan (la cola no se bloquea)', async () => {
    const img = await sharp(solid(300, 300)).jpeg().toBuffer();
    await withEnv({ SANITIZE_MAX_CONCURRENT: '1' }, async () => {
        const results = await Promise.all(Array.from({ length: 6 }, (_, i) => upload(img, `c${i}.jpg`)));
        assert.deepStrictEqual(results.map(r => r.status), [201, 201, 201, 201, 201, 201]);
    });
});

// ------------------------------------------------------------------ PDF

function pdf({ body = '', extraObjects = '' } = {}) {
    return Buffer.from(`%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R ${body} >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n` +
        `3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Contents 4 0 R >>\nendobj\n` +
        `4 0 obj\n<< /Length 44 >>\nstream\nBT /F1 12 Tf 20 100 Td (Hola mundo) Tj ET\nendstream\nendobj\n${extraObjects}trailer\n<< /Root 1 0 R >>\n%%EOF\n`, 'latin1');
}
// object stream comprimido (Flate) que contiene `content`
function objStm(content, { filter = '/FlateDecode', compress = true, extraDict = '' } = {}) {
    const header = '10 0 ';
    const text = Buffer.from(header + content, 'latin1');
    const data = compress ? zlib.deflateSync(text) : text;
    return Buffer.concat([
        Buffer.from(`5 0 obj\n<< /Type /ObjStm /N 1 /First ${header.length} /Filter ${filter} ${extraDict} /Length ${data.length} >>\nstream\n`, 'latin1'),
        data, Buffer.from('\nendstream\nendobj\n', 'latin1')
    ]);
}
const withObjStm = (stm) => Buffer.concat([pdf().subarray(0, pdf().length - '%%EOF\n'.length), stm, Buffer.from('%%EOF\n')]);

itDb('PDF limpio: se acepta, el contenido NO se modifica y consta como inspeccionado', async () => {
    const clean = pdf({ body: '/Lang (es)' });
    const up = await upload(clean, 'informe.pdf');
    assert.strictEqual(up.status, 201, up.text);
    assert.strictEqual(up.body.file.sanitizeStatus, 'inspected');
    assert.ok((await download(up.body.file.id)).buffer.equals(clean), 'byte a byte idéntico');
});

itDb('PDF que habla de JavaScript (sin usarlo) no es un falso positivo', async () => {
    const text = Buffer.from(pdf().toString('latin1').replace('Hola mundo', 'Aprende JavaScript y la clase EF'), 'latin1');
    assert.strictEqual((await upload(text, 'libro.pdf')).status, 201);
});

const ACTIVE = [
    ['/OpenAction con JavaScript', pdf({ body: '/OpenAction << /S /JavaScript /JS (app.alert(1)) >>' })],
    ['solo /JS', pdf({ body: '/AA << /O << /JS (this.print()) >> >>' })],
    ['nombre ofuscado /J#61vaScript', pdf({ body: '/OpenAction << /S /J#61vaScript /JS (x) >>' })],
    ['mayúsculas distintas /javascript', pdf({ body: '/OpenAction << /S /javascript >>' })],
    ['/Launch (ejecutar un programa)', pdf({ body: '/OpenAction << /S /Launch /F (cmd.exe) >>' })],
    ['archivo adjunto /EmbeddedFile', pdf({ extraObjects: '6 0 obj\n<< /Type /EmbeddedFile /Length 3 >>\nstream\nabc\nendstream\nendobj\n' })],
    ['/EmbeddedFiles en el catálogo', pdf({ body: '/Names << /EmbeddedFiles 6 0 R >>' })],
    ['formulario XFA', pdf({ body: '/AcroForm << /XFA 7 0 R >>' })],
    ['multimedia /RichMedia', pdf({ body: '/AA << /RichMedia 1 0 R >>' })],
    ['/SubmitForm', pdf({ body: '/OpenAction << /S /SubmitForm /F (http://evil) >>' })],
    ['JavaScript dentro de un object stream comprimido (Flate)', withObjStm(objStm('<< /S /JavaScript /JS (app.alert(1)) >>'))],
    ['JavaScript ofuscado dentro de un object stream comprimido', withObjStm(objStm('<< /S /J#61va#53cript /JS (x) >>'))]
];
for (const [name, data] of ACTIVE) {
    itDb(`PDF con contenido activo se rechaza: ${name}`, async () => {
        const before = storedCount();
        const up = await upload(data, 'malo.pdf');
        assert.strictEqual(up.status, 415, up.text);
        assert.strictEqual(up.body.code, 'PDF_ACTIVE_CONTENT');
        assert.strictEqual(storedCount(), before);
    });
}

itDb('PDF cifrado o que no se puede inspeccionar se RECHAZA (falla cerrado), no se acepta por defecto', async () => {
    const encrypted = await upload(pdf({ body: '/Encrypt 9 0 R' }), 'cifrado.pdf');
    assert.strictEqual(encrypted.status, 415);
    assert.strictEqual(encrypted.body.code, 'PDF_ENCRYPTED');

    const cases = {
        'object stream con ASCII85': withObjStm(objStm('<< /S /JavaScript >>', { filter: '[/ASCII85Decode /FlateDecode]', compress: false })),
        'object stream corrupto': withObjStm(Buffer.concat([Buffer.from('5 0 obj\n<< /Type /ObjStm /N 1 /First 5 /Filter /FlateDecode /Length 20 >>\nstream\n'), crypto.randomBytes(20), Buffer.from('\nendstream\nendobj\n')])),
        'object stream con predictor': withObjStm(objStm('<< /A 1 >>', { extraDict: '/DecodeParms << /Predictor 12 /Columns 4 >>' })),
        'stream con Crypt': withObjStm(Buffer.from('5 0 obj\n<< /Type /ObjStm /Filter /Crypt /Length 3 >>\nstream\nabc\nendstream\nendobj\n'))
    };
    for (const [name, data] of Object.entries(cases)) {
        const up = await upload(data, 'raro.pdf');
        assert.strictEqual(up.status, 415, name);
        assert.strictEqual(up.body.code, 'PDF_UNINSPECTABLE', name);
    }
});

itDb('PDF_ACTIVE_CONTENT=allow desactiva la inspección (consta como none)', async () => {
    await withEnv({ PDF_ACTIVE_CONTENT: 'allow' }, async () => {
        const up = await upload(ACTIVE[0][1], 'permitido.pdf');
        assert.strictEqual(up.status, 201);
        assert.strictEqual(up.body.file.sanitizeStatus, 'none');
    });
});

itDb('bomba zip en un object stream de PDF: se rechaza sin agotar la memoria', async () => {
    const huge = zlib.deflateSync(Buffer.alloc(40 * 1024 * 1024, 0x20)); // 40 MB de espacios que comprimen a ~40 KB
    const stm = Buffer.concat([Buffer.from(`5 0 obj\n<< /Type /ObjStm /N 1 /First 5 /Filter /FlateDecode /Length ${huge.length} >>\nstream\n`), huge, Buffer.from('\nendstream\nendobj\n')]);
    await withEnv({ PDF_MAX_INFLATED_MB: '4' }, async () => {
        const up = await upload(withObjStm(stm), 'bomba.pdf');
        assert.strictEqual(up.status, 415);
        assert.strictEqual(up.body.code, 'PDF_UNINSPECTABLE');
    });
});

// ------------------------------------------------------------------ unidades

test('decodeName y dangerousNames: nombres con #xx, mayúsculas y nombres peligrosos entre texto', () => {
    assert.strictEqual(sanitize.decodeName('J#61vaScript'), 'JavaScript');
    assert.strictEqual(sanitize.decodeName('A#2FB'), 'A/B');
    const found = sanitize.dangerousNames('<< /S/JavaScript /js (x) /Normal /Launch/F >> /J#61vascript');
    assert.deepStrictEqual([...found].sort(), ['javascript', 'js', 'launch']);
    assert.deepStrictEqual([...sanitize.dangerousNames('<< /Type /Page /Contents 4 0 R /Resources << >> >>')], []);
});

test('planFor: qué se hace con cada tipo según la configuración', () => {
    assert.strictEqual(sanitize.planFor('image/jpeg', 'image'), 'image');
    assert.strictEqual(sanitize.planFor('image/heic', 'image'), 'unsanitizable');
    assert.strictEqual(sanitize.planFor('application/pdf', 'document'), 'pdf');
    assert.strictEqual(sanitize.planFor('audio/mpeg', 'audio'), 'pass');
    assert.strictEqual(sanitize.planFor('text/plain', 'text'), 'pass');
    process.env.IMAGE_SANITIZE = 'off';
    try { assert.strictEqual(sanitize.planFor('image/heic', 'image'), 'pass'); } finally { delete process.env.IMAGE_SANITIZE; }
});
