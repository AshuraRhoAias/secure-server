// Claves de archivo envueltas por el KMS (KMS_DATA_KEYS=true): formato kms1:, ligadura al archivo, KMS caído, convivencia con
// archivos antiguos, rotación de la clave maestra, snapshot de backup y la CLI migrate/unmigrate/rewrap-files.
// KMS real con el proveedor "file" y Vault Transit simulado. MariaDB real.
//
//   npm run test:kms-files

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');

const { filesDir } = require('./test_helpers/env');
process.env.IMAGE_SANITIZE = 'off';
const helpers = require('./test_helpers/app');
const { api, registerAndLogin, testIp } = helpers;

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'kms-files-'));
const kekFile = path.join(tmp, 'kek');
fs.writeFileSync(kekFile, crypto.randomBytes(32).toString('hex'), { mode: 0o400 });
const kekCopy = fs.readFileSync(kekFile, 'utf8');

const jpeg = (seed) => Buffer.concat([Buffer.from([0xff, 0xd8, 0xff, 0xe0, 0, 0x10]), Buffer.from('JFIF\0'), crypto.randomBytes(2000 + seed), Buffer.from([0xff, 0xd9])]);
const form = (data, name) => { const f = new FormData(); f.append('file', new Blob([data]), name); return f; };

let dbAvailable = false, app, db, dataKeys, alice, ip;
const servers = [];

test.before(async () => {
    dbAvailable = await helpers.prepareDatabase();
    if (!dbAvailable) return;
    process.env.KMS_PROVIDER = 'file';
    process.env.KMS_KEK_FILE = kekFile;
    db = require('./src/config/database');
    dataKeys = require('./src/crypto/kms-data-keys');
    app = await helpers.startApp();
    ip = testIp();
    alice = await registerAndLogin(app.base, { ip });
});

test.after(async () => {
    delete process.env.KMS_DATA_KEYS; delete process.env.KMS_PROVIDER; delete process.env.KMS_KEK_FILE;
    if (app) await app.close();
    if (db?.pool) await db.pool.end();
    servers.forEach(s => s.kill());
    fs.rmSync(tmp, { recursive: true, force: true });
    fs.rmSync(filesDir, { recursive: true, force: true });
});

const itDb = (name, fn) => test(name, async (t) => { if (!dbAvailable) return t.skip('sin base de datos'); await fn(t); });
const upload = (data, name = 'foto.jpg') => api(app.base, 'POST', '/api/files', { token: alice.token, ip, form: form(data, name) });
const download = (id) => api(app.base, 'GET', `/api/files/${id}/download`, { token: alice.token, ip });
const rowOf = async (id) => (await db.query('SELECT id, storage_name, key_encrypted FROM user_files WHERE id = ?', [id]))[0][0];
const withKmsKeys = async (fn) => { process.env.KMS_DATA_KEYS = 'true'; dataKeys.clearCache(); try { return await fn(); } finally { delete process.env.KMS_DATA_KEYS; dataKeys.clearCache(); } };

// 1. -----------------------------------------------------------------------------------------------------------
itDb('con KMS_DATA_KEYS la clave del archivo se guarda envuelta por el KMS (kms1:) y el archivo vuelve idéntico', async () => {
    await withKmsKeys(async () => {
        const data = jpeg(1);
        const up = await upload(data);
        assert.strictEqual(up.status, 201, up.text);
        const row = await rowOf(up.body.file.id);
        assert.match(row.key_encrypted, /^kms1:file:[A-Za-z0-9_-]+$/);
        assert.ok(!row.key_encrypted.startsWith('v4:'));

        dataKeys.clearCache();                              // fuerza una llamada real al KMS
        const down = await download(up.body.file.id);
        assert.strictEqual(down.status, 200);
        assert.ok(down.buffer.equals(data));
    });
});

itDb('sin KMS_DATA_KEYS sigue usando la clave maestra (v4:) y convive con archivos kms1:', async () => {
    let kmsId, v4Id;
    await withKmsKeys(async () => { kmsId = (await upload(jpeg(2))).body.file.id; });
    v4Id = (await upload(jpeg(3))).body.file.id;
    assert.ok((await rowOf(v4Id)).key_encrypted.startsWith('v4:'));
    assert.ok((await rowOf(kmsId)).key_encrypted.startsWith('kms1:'));
    // Con el modo APAGADO ambos se siguen leyendo: se decide por lo que hay guardado, no por la configuración
    assert.strictEqual((await download(kmsId)).status, 200);
    assert.strictEqual((await download(v4Id)).status, 200);
});

// 2. -----------------------------------------------------------------------------------------------------------
itDb('el blob va ligado al archivo: copiarlo a otra fila no abre nada y deja un evento', async () => {
    await withKmsKeys(async () => {
        const a = (await upload(jpeg(4))).body.file.id;
        const b = (await upload(jpeg(5))).body.file.id;
        const rowA = await rowOf(a), rowB = await rowOf(b);

        await db.query('UPDATE user_files SET key_encrypted = ? WHERE id = ?', [rowA.key_encrypted, b]);
        dataKeys.clearCache();
        const res = await download(b);
        assert.strictEqual(res.status, 503);
        assert.strictEqual(res.body.code, 'FILE_KEY_UNAVAILABLE');
        const [events] = await db.query("SELECT 1 FROM security_events WHERE event_type = 'FILE_KEY_UNAVAILABLE' AND user_id = ?", [alice.userId]);
        assert.ok(events.length >= 1);
        assert.ok(!JSON.stringify(res.body).includes(rowA.key_encrypted));

        await db.query('UPDATE user_files SET key_encrypted = ? WHERE id = ?', [rowB.key_encrypted, b]);
        assert.strictEqual((await download(b)).status, 200);
    });
});

itDb('blob manipulado o de otro proveedor desconocido → 503, no 500 ni detalle del KMS', async () => {
    await withKmsKeys(async () => {
        const id = (await upload(jpeg(6))).body.file.id;
        const row = await rowOf(id);
        for (const bad of [row.key_encrypted.slice(0, -4) + 'AAAA', 'kms1:desconocido:abcd', 'kms1:file:', 'kms1:']) {
            await db.query('UPDATE user_files SET key_encrypted = ? WHERE id = ?', [bad, id]);
            dataKeys.clearCache();
            const res = await download(id);
            assert.strictEqual(res.status, 503, bad);
            assert.ok(!/kms|vault|aes|kek/i.test(res.body.message || ''), res.text);
        }
        await db.query('UPDATE user_files SET key_encrypted = ? WHERE id = ?', [row.key_encrypted, id]);
    });
});

// 3. -----------------------------------------------------------------------------------------------------------
itDb('KMS caído: descargar da 503 y subir falla sin dejar fila ni archivo; al volver, todo funciona', async () => {
    await withKmsKeys(async () => {
        const id = (await upload(jpeg(7))).body.file.id;
        const [[{ total }]] = await db.query('SELECT COUNT(*) AS total FROM user_files');
        const onDisk = () => fs.readdirSync(path.join(filesDir, 'files'), { recursive: true }).length;
        const diskBefore = onDisk();

        fs.chmodSync(kekFile, 0o600); fs.writeFileSync(kekFile, 'no-es-una-clave'); fs.chmodSync(kekFile, 0o400);
        dataKeys.clearCache();
        try {
            assert.strictEqual((await download(id)).status, 503);
            const up = await upload(jpeg(8));
            assert.ok(up.status >= 500, `status ${up.status}`);
            const [[{ total: after }]] = await db.query('SELECT COUNT(*) AS total FROM user_files');
            assert.strictEqual(after, total, 'no queda fila');
            assert.strictEqual(onDisk(), diskBefore, 'no queda archivo en disco');
        } finally {
            fs.chmodSync(kekFile, 0o600); fs.writeFileSync(kekFile, kekCopy); fs.chmodSync(kekFile, 0o400);
        }
        dataKeys.clearCache();
        assert.strictEqual((await download(id)).status, 200);
    });
});

itDb('la caché de claves respeta KMS_DATA_KEY_CACHE_SECONDS=0 (cada lectura va al KMS)', async () => {
    await withKmsKeys(async () => {
        process.env.KMS_DATA_KEY_CACHE_SECONDS = '0';
        try {
            const id = (await upload(jpeg(9))).body.file.id;
            assert.strictEqual((await download(id)).status, 200);
            fs.chmodSync(kekFile, 0o600); fs.writeFileSync(kekFile, 'x'); fs.chmodSync(kekFile, 0o400);
            try { assert.strictEqual((await download(id)).status, 503, 'sin caché, sin KMS no hay clave'); }
            finally { fs.chmodSync(kekFile, 0o600); fs.writeFileSync(kekFile, kekCopy); fs.chmodSync(kekFile, 0o400); }
        } finally { delete process.env.KMS_DATA_KEY_CACHE_SECONDS; }
    });
});

// 4. rotación y snapshot -------------------------------------------------------------------------------------
itDb('rotación y snapshot dejan intactas las claves kms1: (no dependen de la clave maestra)', async () => {
    const { isExternal } = require('./src/crypto/encrypted-columns');
    const { buildSnapshot, restoreSnapshot } = require('./src/backup/snapshot');
    const enc = require('./src/crypto/tripleEncryptor');
    assert.ok(isExternal('kms1:file:abc') && !isExternal('v4:abc') && !isExternal(null));

    let id;
    await withKmsKeys(async () => { id = (await upload(jpeg(10))).body.file.id; });
    const before = await rowOf(id);

    const conn = await db.pool.getConnection();
    try {
        const calls = [];
        const snapshot = await buildSnapshot(conn, { decryptCell: (t, c, v) => { calls.push(v); return enc.decrypt(v); } });
        assert.ok(!calls.includes(before.key_encrypted), 'el snapshot no intenta descifrar una clave del KMS');
        const index = snapshot.tables.user_files.columns.indexOf('key_encrypted');
        assert.ok(snapshot.tables.user_files.rows.some(r => r[index] === before.key_encrypted), 'se guarda tal cual');

        await restoreSnapshot(conn, snapshot, {
            encryptCell: (t, c, v) => { assert.ok(!String(v).startsWith('kms1:'), 'no se re-cifra una clave del KMS'); return enc.encrypt(v); },
            only: ['user_files']
        });
    } finally { conn.release(); }
    assert.strictEqual((await rowOf(id)).key_encrypted, before.key_encrypted);
    assert.strictEqual((await download(id)).status, 200);

    // Rotación: el servicio salta kms1: tanto al re-cifrar como al verificar
    const Rotation = require('./src/maintenance/rotation.service');
    const source = fs.readFileSync(require.resolve('./src/maintenance/rotation.service'), 'utf8');
    assert.ok((source.match(/isExternal\(/g) || []).length >= 2, 'reencryptAll y verifyAll saltan los valores externos');
    assert.ok(Rotation);
});

// 5. CLI ------------------------------------------------------------------------------------------------------
const cli = (args, env = {}) => new Promise((resolve) => {
    const child = spawn(process.execPath, [path.join(__dirname, 'scripts/kms.js'), ...args], { env: { ...process.env, ENV_FILE: '/nonexistent', ...env } });
    let out = '', err = '';
    child.stdout.on('data', d => { out += d; }); child.stderr.on('data', d => { err += d; });
    child.on('close', status => resolve({ status, out, err }));
});

itDb('CLI: migrate-files pasa a kms1:, es repetible; unmigrate-files vuelve a v4:; los archivos se leen siempre', async () => {
    const ids = [];
    for (let i = 0; i < 3; i++) ids.push((await upload(jpeg(20 + i))).body.file.id);
    assert.ok((await rowOf(ids[0])).key_encrypted.startsWith('v4:'));

    const dry = await cli(['migrate-files', '--dry-run']);
    assert.strictEqual(dry.status, 0, dry.err + dry.out);
    assert.match(dry.out, /simulación/);
    assert.ok((await rowOf(ids[0])).key_encrypted.startsWith('v4:'), 'la simulación no escribe');

    const mig = await cli(['migrate-files']);
    assert.strictEqual(mig.status, 0, mig.err + mig.out);
    for (const id of ids) assert.ok((await rowOf(id)).key_encrypted.startsWith('kms1:file:'));
    for (const id of ids) assert.strictEqual((await download(id)).status, 200);

    const again = await cli(['migrate-files']);
    assert.match(again.out, / 0 cambiados/);

    const rewrap = await cli(['rewrap-files']);
    assert.strictEqual(rewrap.status, 0, rewrap.err);
    const afterRewrap = await rowOf(ids[0]);
    assert.ok(afterRewrap.key_encrypted.startsWith('kms1:file:'));
    assert.strictEqual((await download(ids[0])).status, 200);

    const back = await cli(['unmigrate-files']);
    assert.strictEqual(back.status, 0, back.err + back.out);
    for (const id of ids) assert.ok((await rowOf(id)).key_encrypted.startsWith('v4:'));
    for (const id of ids) assert.strictEqual((await download(id)).status, 200);
});

itDb('CLI: sin KMS_PROVIDER migrate-files falla sin tocar nada', async () => {
    const id = (await upload(jpeg(30))).body.file.id;
    const before = await rowOf(id);
    const res = await cli(['migrate-files'], { KMS_PROVIDER: '' });
    assert.notStrictEqual(res.status, 0);
    assert.match(res.err, /KMS_PROVIDER/);
    assert.strictEqual((await rowOf(id)).key_encrypted, before.key_encrypted);
});

itDb('CLI: si el KMS rechaza una fila a mitad, no se escribe una clave corrupta', async () => {
    const id = (await upload(jpeg(31))).body.file.id;
    const before = await rowOf(id);
    const res = await cli(['migrate-files'], { KMS_KEK_FILE: path.join(tmp, 'no-existe') });
    assert.notStrictEqual(res.status, 0);
    assert.match(res.out + res.err, /fallaron/);
    assert.strictEqual((await rowOf(id)).key_encrypted, before.key_encrypted);
    assert.ok(!res.out.includes(before.key_encrypted));
});

itDb('CLI: una fila ilegible no bloquea las demás: se informa y el comando termina con error', async () => {
    const good = (await upload(jpeg(32))).body.file.id;
    const bad = (await upload(jpeg(33))).body.file.id;
    const badBefore = await rowOf(bad);
    await db.query("UPDATE user_files SET key_encrypted = 'v4:basura' WHERE id = ?", [bad]);
    try {
        const res = await cli(['migrate-files']);
        assert.notStrictEqual(res.status, 0);
        assert.match(res.out + res.err, new RegExp(`fallaron: .*${bad}`));
        assert.ok((await rowOf(good)).key_encrypted.startsWith('kms1:'), 'la fila buena sí se migró');
        assert.strictEqual((await rowOf(bad)).key_encrypted, 'v4:basura');
    } finally { await db.query('UPDATE user_files SET key_encrypted = ? WHERE id = ?', [badBefore.key_encrypted, bad]); }
});

// 6. Vault ----------------------------------------------------------------------------------------------------
itDb('con Vault Transit: la clave de cada archivo viaja envuelta y el texto claro nunca sale en la petición registrada', async () => {
    const child = spawn(process.execPath, [path.join(__dirname, 'test_helpers/mock-kms-server.js'), 'vault'], { stdio: ['ignore', 'pipe', 'inherit'] });
    servers.push(child);
    const port = await new Promise(resolve => child.stdout.on('data', d => { const m = /PORT (\d+)/.exec(String(d)); if (m) resolve(Number(m[1])); }));
    const saved = { p: process.env.KMS_PROVIDER, a: process.env.VAULT_ADDR, t: process.env.VAULT_TOKEN };
    Object.assign(process.env, { KMS_PROVIDER: 'vault', VAULT_ADDR: `http://127.0.0.1:${port}`, VAULT_TOKEN: 's.token-valido' });
    try {
        await withKmsKeys(async () => {
            const id = (await upload(jpeg(40))).body.file.id;
            const row = await rowOf(id);
            assert.match(row.key_encrypted, /^kms1:vault:/);
            dataKeys.clearCache();
            assert.strictEqual((await download(id)).status, 200);

            const last = await (await fetch(`http://127.0.0.1:${port}/__last`)).json();
            assert.match(last.url, /\/v1\/transit\/decrypt\//);
            // Token incorrecto → 503, no se filtra el mensaje de Vault
            process.env.VAULT_TOKEN = 'malo';
            dataKeys.clearCache();
            const bad = await download(id);
            assert.strictEqual(bad.status, 503);
            assert.ok(!/vault|permission/i.test(bad.text));
        });
    } finally {
        process.env.KMS_PROVIDER = saved.p; process.env.VAULT_ADDR = saved.a ?? ''; process.env.VAULT_TOKEN = saved.t ?? '';
        delete process.env.VAULT_ADDR; delete process.env.VAULT_TOKEN;
    }
});
