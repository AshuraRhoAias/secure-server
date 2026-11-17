// Almacenamiento de archivos en S3 (FILES_STORAGE=s3) contra un S3 SIMULADO (test/helpers/mock-s3.js). Sin base de datos:
// driver, subida del temporal, lectura por rangos con UNA petición, integridad y configuración. La API completa en modo S3,
// con MariaDB, está en test_files_s3.js.
//
//   npm run test:s3

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { pipeline } = require('stream/promises');
const { Readable } = require('stream');
const { createMockS3 } = require('./helpers/mock-s3');

const filesDir = fs.mkdtempSync(path.join(os.tmpdir(), 's3-test-'));
const ENV = ['FILES_STORAGE', 'FILES_DIR', 'S3_BUCKET', 'S3_ENDPOINT', 'S3_FORCE_PATH_STYLE', 'S3_REGION', 'S3_PREFIX', 'S3_SSE', 'S3_SSE_KMS_KEY_ID', 'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'NODE_ENV', 'S3_ALLOW_HTTP', 'FILES_BACKUP_DIR'];
const saved = Object.fromEntries(ENV.map(k => [k, process.env[k]]));
let s3;

const storage = require('../src/files/storage');
const cipher = require('../src/files/file-cipher');

test.before(async () => {
    s3 = await createMockS3();
    Object.assign(process.env, {
        FILES_STORAGE: 's3', FILES_DIR: filesDir, S3_BUCKET: s3.bucket, S3_ENDPOINT: s3.endpoint, S3_FORCE_PATH_STYLE: 'true',
        S3_REGION: 'eu-west-1', S3_PREFIX: 'pruebas', AWS_ACCESS_KEY_ID: 'AKIAPRUEBAS', AWS_SECRET_ACCESS_KEY: 'secreto-de-pruebas'
    });
    delete process.env.S3_SSE;
});
test.after(async () => {
    for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
    await s3?.close();
    fs.rmSync(filesDir, { recursive: true, force: true });
});

// Cifra `plain` a un temporal como haría una subida y lo confirma en el bucket
async function stored(plain) {
    const name = storage.newStorageName();
    const key = cipher.newDataKey();
    await pipeline(Readable.from([plain]), new cipher.EncryptStream(key), storage.createTempWriteStream(name));
    await storage.commit(name);
    return { name, key, objectKey: `pruebas/files/${name.slice(0, 2)}/${name}.enc` };
}
const readAll = async (iterable) => { const parts = []; for await (const p of iterable) parts.push(p); return Buffer.concat(parts); };
const gets = () => s3.log.filter(l => l.method === 'GET').length;

test('commit: el objeto llega CIFRADO al bucket, con SSE AES256 por defecto, firmado, y el temporal local desaparece', async () => {
    const plain = crypto.randomBytes(200_000);
    const { name, objectKey } = await stored(plain);
    const object = s3.objects.get(objectKey);
    assert.ok(object, `objeto en ${objectKey}`);
    assert.strictEqual(object.body.length, cipher.cipherSize(plain.length));
    assert.ok(!object.body.includes(plain.subarray(1000, 1064)), 'el bucket nunca ve el contenido en claro');
    assert.strictEqual(object.sse, 'AES256');
    assert.ok(s3.log.every(l => l.authorized), 'todas las peticiones van firmadas (SigV4)');
    assert.ok(!fs.existsSync(storage.tmpPath(name)), 'sin temporal');
    const local = path.join(filesDir, 'files');
    assert.ok(!fs.existsSync(local) || fs.readdirSync(local).length === 0, 'nada en FILES_DIR/files');
});

test('lectura: entero y por rangos aleatorios, exactamente esos bytes, con UNA petición GetObject por lectura', async () => {
    const plain = crypto.randomBytes(5 * cipher.CHUNK + 777);
    const { name, key } = await stored(plain);
    let before = gets();
    assert.ok((await readAll(cipher.decryptRange({ blob: storage.blob(name), key, plainSize: plain.length }))).equals(plain));
    assert.strictEqual(gets() - before, 1, 'una sola petición para todo el archivo');

    for (let n = 0; n < 25; n++) {
        const start = crypto.randomInt(plain.length);
        const end = start + crypto.randomInt(plain.length - start);
        before = gets();
        const got = await readAll(cipher.decryptRange({ blob: storage.blob(name), key, plainSize: plain.length, start, end }));
        assert.ok(got.equals(plain.subarray(start, end + 1)), `rango ${start}-${end}`);
        assert.strictEqual(gets() - before, 1);
        const last = s3.log.filter(l => l.method === 'GET').at(-1);
        const [, from, to] = /bytes=(\d+)-(\d+)/.exec(last.range).map(Number);
        assert.ok(to - from + 1 <= (Math.floor(end / cipher.CHUNK) - Math.floor(start / cipher.CHUNK) + 1) * (cipher.CHUNK + cipher.TAG), 'solo los bloques necesarios');
    }
});

test('integridad: un byte alterado, un objeto truncado o ausente, o un servidor que ignora Range → error, nunca datos', async () => {
    const plain = crypto.randomBytes(3 * cipher.CHUNK);
    const { name, key, objectKey } = await stored(plain);
    const original = Buffer.from(s3.objects.get(objectKey).body);
    const read = () => readAll(cipher.decryptRange({ blob: storage.blob(name), key, plainSize: plain.length }));

    for (const position of [0, cipher.CHUNK + 5, original.length - 1]) {
        const tampered = Buffer.from(original); tampered[position] ^= 1;
        s3.objects.get(objectKey).body = tampered;
        await assert.rejects(read(), /FILE_CORRUPT/, `byte ${position}`);
    }
    s3.objects.get(objectKey).body = original.subarray(0, original.length - 10);
    await assert.rejects(read(), /FILE_CORRUPT/, 'truncado');

    s3.objects.get(objectKey).body = original;
    s3.behaviors.ignoreRange = true;
    try {
        await assert.rejects(readAll(cipher.decryptRange({ blob: storage.blob(name), key, plainSize: plain.length, start: cipher.CHUNK + 1, end: cipher.CHUNK + 9 })), /FILE_CORRUPT/, 'sin Range no se descifra a ciegas');
    } finally { s3.behaviors.ignoreRange = false; }
    assert.ok((await read()).equals(plain), 'el original sigue bien');

    await storage.removeFinal(name);
    assert.ok(!s3.objects.has(objectKey), 'borrado');
    await assert.rejects(read(), /FILE_MISSING/);
});

test('si el bucket rechaza la subida, commit falla y el temporal se queda para que el llamante lo limpie', async () => {
    const name = storage.newStorageName();
    await pipeline(Readable.from([Buffer.from('hola')]), new cipher.EncryptStream(cipher.newDataKey()), storage.createTempWriteStream(name));
    s3.behaviors.failPut = true;
    try {
        await assert.rejects(storage.commit(name));
    } finally { s3.behaviors.failPut = false; }
    assert.ok(fs.existsSync(storage.tmpPath(name)));
    await storage.removeTemp(name);
});

test('configuración: SSE con KMS, sin SSE, prefijo, https obligatorio en producción, y las copias de FILES_DIR se niegan', async () => {
    const withEnv = async (vars, fn) => {
        const old = Object.fromEntries(Object.keys(vars).map(k => [k, process.env[k]]));
        for (const [k, v] of Object.entries(vars)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
        try { return await fn(); } finally { for (const [k, v] of Object.entries(old)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; } }
    };
    await withEnv({ S3_SSE: 'aws:kms', S3_SSE_KMS_KEY_ID: 'alias/archivos' }, async () => {
        await stored(Buffer.from('kms'));
        const put = s3.log.filter(l => l.method === 'PUT').at(-1);
        assert.strictEqual(put.sse, 'aws:kms');
        assert.strictEqual(put.kmsKeyId, 'alias/archivos');
    });
    await withEnv({ S3_SSE: 'none' }, async () => {
        await stored(Buffer.from('sin sse'));
        assert.strictEqual(s3.log.filter(l => l.method === 'PUT').at(-1).sse, null);
    });
    await withEnv({ S3_SSE: 'rot13' }, async () => assert.throws(() => require('../src/files/s3-store').config(), /S3_SSE/));
    await withEnv({ S3_PREFIX: '../otro' }, async () => assert.throws(() => require('../src/files/s3-store').config(), /S3_PREFIX/));
    await withEnv({ S3_BUCKET: undefined }, async () => assert.throws(() => require('../src/files/s3-store').config(), /S3_BUCKET/));
    await withEnv({ NODE_ENV: 'production' }, async () => assert.throws(() => require('../src/files/s3-store').config(), /https/));
    await withEnv({ NODE_ENV: 'production', S3_ALLOW_HTTP: 'true' }, async () => assert.ok(require('../src/files/s3-store').config()));

    assert.throws(() => storage.blob('../../etc/passwd'), /inválido/, 'el nombre sigue siendo un UUID del servidor');
    await withEnv({ FILES_BACKUP_DIR: path.join(os.tmpdir(), 'no-se-usa') }, async () => {
        await assert.rejects(require('../src/files/files-backup').backup({ db: null }), /FILES_STORAGE=s3/);
    });
});
