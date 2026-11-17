// API de archivos con FILES_STORAGE=s3: MariaDB real + el servidor de pruebas + un S3 SIMULADO (test/helpers/mock-s3.js).
// Comprueba que el modo S3 es un cambio de DÓNDE se guardan los bytes cifrados, no de lo que se garantiza.
//
//   npm run test:files-s3

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { filesDir } = require('./helpers/env');
const helpers = require('./helpers/app');
const { createMockS3 } = require('./helpers/mock-s3');
const { api, registerAndLogin, testIp } = helpers;

let dbAvailable = false, app, db, s3, user, ip;
const ENV = ['FILES_STORAGE', 'S3_BUCKET', 'S3_ENDPOINT', 'S3_FORCE_PATH_STYLE', 'S3_REGION', 'S3_PREFIX', 'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY'];
const saved = Object.fromEntries(ENV.map(k => [k, process.env[k]]));

test.before(async () => {
    s3 = await createMockS3();
    Object.assign(process.env, {
        FILES_STORAGE: 's3', S3_BUCKET: s3.bucket, S3_ENDPOINT: s3.endpoint, S3_FORCE_PATH_STYLE: 'true', S3_REGION: 'eu-west-1',
        S3_PREFIX: 'api', AWS_ACCESS_KEY_ID: 'AKIAPRUEBAS', AWS_SECRET_ACCESS_KEY: 'secreto-de-pruebas'
    });
    dbAvailable = await helpers.prepareDatabase();
    if (!dbAvailable) return;
    db = require('../src/config/database');
    app = await helpers.startApp();
    ip = testIp();
    user = await registerAndLogin(app.base, { ip });
});
test.after(async () => {
    for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
    if (app) await app.close();
    if (db?.pool) await db.pool.end();
    await s3?.close();
    fs.rmSync(filesDir, { recursive: true, force: true });
});
const itDb = (name, fn) => test(name, async (t) => { if (!dbAvailable) return t.skip('sin base de datos'); await fn(t); });

const text = (n) => Buffer.from(Array.from({ length: n }, (_, i) => `línea ${i} ${crypto.randomBytes(6).toString('hex')}\n`).join(''));
function upload(data, name = 'notas.txt') {
    const form = new FormData();
    form.append('file', new Blob([data]), name);
    return api(app.base, 'POST', '/api/files', { token: user.token, ip, form });
}
const download = (id, headers = {}, method = 'GET') => api(app.base, method, `/api/files/${id}/download`, { token: user.token, ip, headers });
const objectFor = async (id) => {
    const [[row]] = await db.query('SELECT storage_name FROM user_files WHERE id = ?', [id]);
    return { name: row.storage_name, key: `api/files/${row.storage_name.slice(0, 2)}/${row.storage_name}.enc` };
};
const localFiles = () => {
    const dir = path.join(filesDir, 'files');
    const out = [];
    const walk = (d) => { if (!fs.existsSync(d)) return; for (const e of fs.readdirSync(d, { withFileTypes: true })) e.isDirectory() ? walk(path.join(d, e.name)) : out.push(e.name); };
    walk(dir);
    return out;
};

itDb('subida → el objeto CIFRADO está en el bucket (nada en disco local); descarga entera, por rango y HEAD idénticas', async () => {
    const data = text(6000); // ~150 KB: varios bloques
    const res = await upload(data);
    assert.strictEqual(res.status, 201, res.text);
    const { key } = await objectFor(res.body.file.id);
    const object = s3.objects.get(key);
    assert.ok(object, 'objeto en el bucket');
    assert.ok(!object.body.includes(data.subarray(100, 160)), 'el bucket no ve el contenido');
    assert.strictEqual(object.sse, 'AES256');
    assert.deepStrictEqual(localFiles(), [], 'nada en FILES_DIR/files');
    assert.deepStrictEqual(fs.existsSync(path.join(filesDir, 'tmp')) ? fs.readdirSync(path.join(filesDir, 'tmp')) : [], [], 'sin temporales');

    const full = await download(res.body.file.id);
    assert.strictEqual(full.status, 200);
    assert.ok(full.buffer.equals(data));

    const ranged = await download(res.body.file.id, { Range: 'bytes=70000-70099' });
    assert.strictEqual(ranged.status, 206);
    assert.strictEqual(ranged.headers.get('content-range'), `bytes 70000-70099/${data.length}`);
    assert.ok(ranged.buffer.equals(data.subarray(70000, 70100)));

    const head = await download(res.body.file.id, {}, 'HEAD');
    assert.strictEqual(head.status, 200);
    assert.strictEqual(head.headers.get('content-length'), String(data.length));
});

itDb('borrar por la API borra el objeto del bucket', async () => {
    const res = await upload(text(100));
    const { key } = await objectFor(res.body.file.id);
    assert.ok(s3.objects.has(key));
    const del = await api(app.base, 'DELETE', `/api/files/${res.body.file.id}`, { token: user.token, ip });
    assert.strictEqual(del.status, 200, del.text);
    assert.ok(!s3.objects.has(key), 'objeto borrado');
    assert.strictEqual((await download(res.body.file.id)).status, 404);
});

itDb('si el bucket falla al confirmar: error, NINGUNA fila en la BD y ningún temporal', async () => {
    const [[before]] = await db.query('SELECT COUNT(*) AS n FROM user_files WHERE user_id = ?', [user.userId]);
    s3.behaviors.failPut = true;
    try {
        const res = await upload(text(50), 'falla.txt');
        assert.ok(res.status >= 500, `${res.status} ${res.text}`);
    } finally { s3.behaviors.failPut = false; }
    const [[after]] = await db.query('SELECT COUNT(*) AS n FROM user_files WHERE user_id = ?', [user.userId]);
    assert.strictEqual(after.n, before.n);
    assert.deepStrictEqual(fs.existsSync(path.join(filesDir, 'tmp')) ? fs.readdirSync(path.join(filesDir, 'tmp')) : [], []);
});

itDb('objeto alterado o desaparecido en el bucket → la descarga falla limpia (FILE_CORRUPT) y queda un evento', async () => {
    const res = await upload(text(3000));
    const { key } = await objectFor(res.body.file.id);
    const object = s3.objects.get(key);
    object.body = Buffer.from(object.body);
    object.body[10] ^= 1;
    const bad = await download(res.body.file.id);
    assert.strictEqual(bad.status, 500);
    assert.strictEqual(bad.body.code, 'FILE_CORRUPT');

    s3.objects.delete(key);
    const gone = await download(res.body.file.id);
    assert.strictEqual(gone.status, 500);
    const [events] = await db.query("SELECT COUNT(*) AS n FROM security_events WHERE user_id = ? AND event_type LIKE 'FILE_%' AND severity IN ('high', 'critical')", [user.userId]);
    assert.ok(events[0].n >= 2, 'eventos de integridad registrados');
});
