// Pruebas de las copias de seguridad de FILES_DIR: incremental, retención, verificación, restauración y detección
// de pérdidas. MariaDB real y el servidor con sus middlewares reales.
//
//   npm run test:files-backup

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { filesDir } = require('./test_helpers/env');
// Archivos sintéticos (relleno con cabecera): se prueba la copia, no el saneamiento de imágenes (ver test_sanitize.js)
process.env.IMAGE_SANITIZE = 'off';
const helpers = require('./test_helpers/app');
const { api, registerAndLogin, testIp } = helpers;

const backupDir = fs.mkdtempSync(path.join(os.tmpdir(), 'files-backup-'));
process.env.FILES_BACKUP_DIR = backupDir;

const bytes = (...parts) => Buffer.concat(parts.map(p => (Buffer.isBuffer(p) ? p : Buffer.from(p))));
const png = (n, seed = 1) => bytes([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a], crypto.randomBytes(n + seed));
const multipart = (data, name) => { const f = new FormData(); f.append('file', new Blob([data]), name); return f; };

let dbAvailable = false;
let app, db, user, ip, backup;

test.before(async () => {
    dbAvailable = await helpers.prepareDatabase();
    if (!dbAvailable) return;
    db = require('./src/config/database');
    backup = require('./src/files/files-backup');
    app = await helpers.startApp();
    ip = testIp();
    user = await registerAndLogin(app.base, { ip });
});
test.after(async () => {
    if (app) await app.close();
    if (db?.pool) await db.pool.end();
    fs.rmSync(filesDir, { recursive: true, force: true });
    fs.rmSync(backupDir, { recursive: true, force: true });
});

const itDb = (name, fn) => test(name, async (t) => {
    if (!dbAvailable) return t.skip('sin base de datos');
    await fn(t);
});

const upload = async (data, name) => {
    const res = await api(app.base, 'POST', '/api/files', { token: user.token, ip, form: multipart(data, name) });
    assert.strictEqual(res.status, 201, res.text);
    return res.body.file;
};
const storageName = async (id) => (await db.query('SELECT storage_name FROM user_files WHERE id = ?', [id]))[0][0].storage_name;
const sourceFile = async (id) => path.join(filesDir, 'files', (await storageName(id)).slice(0, 2), `${await storageName(id)}.enc`);
const download = (id) => api(app.base, 'GET', `/api/files/${id}/download`, { token: user.token, ip });
const sha = (buf) => crypto.createHash('sha256').update(buf).digest('hex');

itDb('el destino no puede estar dentro de FILES_DIR ni contenerlo; sin FILES_BACKUP_DIR hay un error claro', async () => {
    const saved = process.env.FILES_BACKUP_DIR;
    try {
        for (const bad of [path.join(filesDir, 'copias'), filesDir, path.dirname(filesDir)]) {
            process.env.FILES_BACKUP_DIR = bad;
            await assert.rejects(backup.backup({ db }), /no puede estar dentro de FILES_DIR/);
        }
        delete process.env.FILES_BACKUP_DIR;
        await assert.rejects(backup.backup({ db }), /Define FILES_BACKUP_DIR/);
    } finally { process.env.FILES_BACKUP_DIR = saved; }
});

itDb('copia incremental: la primera copia todo, la segunda solo lo nuevo, y todo se verifica', async () => {
    const files = [await upload(png(5000), 'a.png'), await upload(png(300_000), 'b.png'), await upload(Buffer.from('texto de prueba'), 'c.txt')];

    const first = await backup.backup({ db });
    assert.strictEqual(first.copied, 3);
    assert.deepStrictEqual([first.missingFiles, first.wrongSize, first.errors], [[], [], []]);
    assert.ok(first.bytesCopied > 300_000);

    const second = await backup.backup({ db });
    assert.deepStrictEqual([second.copied, second.alreadyBackedUp], [0, 3], 'no se copia dos veces');

    const extra = await upload(png(2000), 'd.png');
    const third = await backup.backup({ db });
    assert.deepStrictEqual([third.copied, third.alreadyBackedUp], [1, 3]);

    // La copia es byte a byte lo que hay en disco (texto cifrado) y no contiene nada legible
    for (const file of [...files, extra]) {
        const name = await storageName(file.id);
        const copy = fs.readFileSync(path.join(backupDir, 'files', name.slice(0, 2), `${name}.enc`));
        assert.ok(copy.equals(fs.readFileSync(await sourceFile(file.id))));
        assert.ok(!copy.includes('texto de prueba') && !copy.includes('PNG'));
    }
    const index = fs.readFileSync(path.join(backupDir, 'index.json'), 'utf8');
    assert.ok(!/a\.png|b\.png|c\.txt|d\.png/.test(index), 'el índice no contiene nombres reales');
    assert.strictEqual(fs.statSync(path.join(backupDir, 'index.json')).mode & 0o777, 0o600);

    const verified = await backup.verify({ db });
    assert.deepStrictEqual([verified.corrupt, verified.missingInBackup, verified.notBackedUp], [[], [], []]);
    assert.ok(verified.checked >= 4 && verified.lastBackupAt);
});

itDb('verify detecta copias dañadas, truncadas o borradas y archivos de la BD sin copia', async () => {
    const a = await upload(png(10_000), 'v1.png');
    const b = await upload(png(10_000), 'v2.png');
    const c = await upload(png(10_000), 'v3.png');
    await backup.backup({ db });
    const d = await upload(png(10_000), 'v4.png'); // todavía sin copia

    const copy = async (file) => { const n = await storageName(file.id); return path.join(backupDir, 'files', n.slice(0, 2), `${n}.enc`); };
    const flipped = fs.readFileSync(await copy(a)); flipped[100] ^= 1; fs.writeFileSync(await copy(a), flipped);
    fs.truncateSync(await copy(b), 100);
    fs.rmSync(await copy(c));

    const report = await backup.verify({ db });
    assert.deepStrictEqual(report.corrupt.sort(), [await storageName(a.id), await storageName(b.id)].sort());
    assert.deepStrictEqual(report.missingInBackup, [await storageName(c.id)]);
    assert.deepStrictEqual(report.notBackedUp, [await storageName(d.id)]);

    // Reparación (y para no contaminar las pruebas siguientes): se descartan las copias dañadas y se vuelve a copiar desde el origen sano
    const index = backup.readIndex(backupDir);
    for (const file of [a, b, c]) {
        fs.rmSync(await copy(file), { force: true });
        delete index.files[await storageName(file.id)];
    }
    backup.writeIndex(backupDir, index);
    const repaired = await backup.backup({ db });
    assert.ok(repaired.copied >= 4);
    const clean = await backup.verify({ db });
    assert.deepStrictEqual([clean.corrupt, clean.missingInBackup, clean.notBackedUp], [[], [], []]);
});

itDb('pérdida en el disco de origen: backup la señala (y restore la recupera) en vez de dar la copia por buena', async () => {
    const file = await upload(png(80_000), 'perdido.png');
    const original = (await download(file.id)).buffer;
    await backup.backup({ db });

    fs.rmSync(await sourceFile(file.id));                 // el disco pierde el archivo
    assert.strictEqual((await download(file.id)).status === 200 && (await download(file.id)).buffer.equals(original), false);

    const report = await backup.backup({ db });
    assert.deepStrictEqual(report.missingFiles, [await storageName(file.id)], 'la BD cree tenerlo y no está');

    const restored = await backup.restore({ db });
    assert.ok(restored.restored >= 1);
    assert.deepStrictEqual(restored.refused, []);
    const after = await download(file.id);
    assert.ok(after.buffer.equals(original), 'tras restaurar se descarga idéntico (la clave sigue en la BD)');
    assert.strictEqual(after.headers.get('x-content-sha256'), sha(original));
    assert.deepStrictEqual((await backup.backup({ db })).missingFiles, []);
});

itDb('archivo truncado en origen: se detecta por tamaño y se restaura desde la copia', async () => {
    const file = await upload(png(200_000), 'truncado.png');
    const original = (await download(file.id)).buffer;
    await backup.backup({ db });

    fs.truncateSync(await sourceFile(file.id), 70_000);
    const report = await backup.backup({ db });
    assert.ok(report.wrongSize.includes(await storageName(file.id)));
    assert.ok(report.changedInSource.includes(await storageName(file.id)), 'no se sobrescribe la copia buena con el original dañado');
    const goodCopy = path.join(backupDir, 'files', (await storageName(file.id)).slice(0, 2), `${await storageName(file.id)}.enc`);
    assert.ok((await backup.verify({ db })).corrupt.length === 0 || !(await backup.verify({ db })).corrupt.includes(await storageName(file.id)), 'la copia sigue íntegra');
    assert.strictEqual(fs.statSync(goodCopy).size > 70_000, true);

    // Un archivo existente NO se pisa sin --force; con force sí
    assert.ok((await backup.restore({ db })).skippedExisting >= 1);
    assert.ok((await backup.restore({ db, force: true })).restored >= 1);
    assert.ok((await download(file.id)).buffer.equals(original));
});

itDb('restore se niega a colocar una copia dañada (verifica el hash antes) y no deja temporales', async () => {
    const file = await upload(png(30_000), 'danado.png');
    await backup.backup({ db });
    const name = await storageName(file.id);
    const copy = path.join(backupDir, 'files', name.slice(0, 2), `${name}.enc`);
    const raw = fs.readFileSync(copy); raw[50] ^= 1; fs.writeFileSync(copy, raw);

    fs.rmSync(await sourceFile(file.id));
    const report = await backup.restore({ db });
    assert.ok(report.refused.some(r => r.name === name && /dañada/.test(r.reason)));
    assert.ok(!fs.existsSync(await sourceFile(file.id)), 'no se restauró un archivo dañado');
    const leftovers = fs.readdirSync(path.join(filesDir, 'files', name.slice(0, 2))).filter(f => f.endsWith('.part'));
    assert.deepStrictEqual(leftovers, []);

    // Limpieza: este archivo ya no tiene remedio y no debe contaminar las pruebas siguientes
    await db.query('DELETE FROM user_files WHERE id = ?', [file.id]);
    fs.rmSync(copy);
    await backup.backup({ db });
});

itDb('desastre total: se pierde TODO FILES_DIR y se recupera con la copia + la BD; con otro --target también', async () => {
    const batch = [];
    for (let i = 0; i < 4; i++) {
        const data = png(20_000 + i * 50_000, i);
        const file = await upload(data, `d${i}.png`);
        batch.push({ id: file.id, data });
    }
    await backup.backup({ db });
    const originals = await Promise.all(batch.map(async f => (await download(f.id)).buffer));

    fs.rmSync(path.join(filesDir, 'files'), { recursive: true, force: true }); // el disco entero desaparece

    const alt = fs.mkdtempSync(path.join(os.tmpdir(), 'restore-alt-'));
    const toAlt = await backup.restore({ db, target: alt });
    assert.ok(toAlt.restored >= 4);
    assert.ok(fs.existsSync(path.join(alt, 'files')), 'restaurado en el directorio alternativo');
    fs.rmSync(alt, { recursive: true, force: true });

    const restored = await backup.restore({ db });
    assert.ok(restored.restored >= 4);
    assert.deepStrictEqual(restored.refused, []);
    for (const [i, f] of batch.entries()) assert.ok((await download(f.id)).buffer.equals(originals[i]), `archivo ${i}`);
    assert.deepStrictEqual((await backup.backup({ db })).missingFiles, []);
});

itDb('lo borrado en origen se conserva en la copia durante la retención y después se elimina', async () => {
    const file = await upload(png(4000), 'borrar.png');
    const name = await storageName(file.id);
    await backup.backup({ db });
    const copy = path.join(backupDir, 'files', name.slice(0, 2), `${name}.enc`);
    assert.ok(fs.existsSync(copy));

    assert.strictEqual((await api(app.base, 'DELETE', `/api/files/${file.id}`, { token: user.token, ip })).status, 200);

    const kept = await backup.backup({ db });                     // retención por defecto: 30 días
    assert.strictEqual(kept.pruned, 0);
    assert.ok(fs.existsSync(copy), 'se conserva por si fue un error');
    assert.ok(backup.readIndex(backupDir).files[name].missingSince);

    // No se restaura (no está referenciado por la BD) salvo con --all
    fs.rmSync(path.join(filesDir, 'files', name.slice(0, 2)), { recursive: true, force: true });
    assert.ok((await backup.restore({ db })).skippedUnreferenced >= 1);
    assert.ok(!fs.existsSync(path.join(filesDir, 'files', name.slice(0, 2), `${name}.enc`)));
    assert.ok((await backup.restore({ db, onlyReferenced: false })).restored >= 1);

    process.env.FILES_BACKUP_RETENTION_DAYS = '0';
    try {
        fs.rmSync(path.join(filesDir, 'files', name.slice(0, 2), `${name}.enc`), { force: true });
        const pruned = await backup.backup({ db });
        assert.ok(pruned.pruned >= 1);
        assert.ok(!fs.existsSync(copy), 'pasada la retención, se elimina');
        assert.ok(!backup.readIndex(backupDir).files[name]);
    } finally { delete process.env.FILES_BACKUP_RETENTION_DAYS; }
});

itDb('archivos huérfanos (sin fila en la BD) se cuentan; la copia en curso no deja .part', async () => {
    const orphan = crypto.randomUUID();
    fs.mkdirSync(path.join(filesDir, 'files', orphan.slice(0, 2)), { recursive: true });
    fs.writeFileSync(path.join(filesDir, 'files', orphan.slice(0, 2), `${orphan}.enc`), crypto.randomBytes(100));
    const report = await backup.backup({ db });
    assert.ok(report.orphans >= 1);

    const parts = [];
    (function walk(dir) { for (const e of fs.readdirSync(dir, { withFileTypes: true })) { const f = path.join(dir, e.name); e.isDirectory() ? walk(f) : f.endsWith('.part') && parts.push(f); } })(backupDir);
    assert.deepStrictEqual(parts, []);
});

itDb('CLI: backup / verify / restore devuelven códigos de salida útiles para cron', async () => {
    const { spawn } = require('child_process');
    const run = (args) => new Promise((resolve) => {
        const child = spawn(process.execPath, [path.join(__dirname, 'scripts/filesBackup.js'), ...args], { env: { ...process.env, ENV_FILE: '/nonexistent' } });
        let out = '';
        child.stdout.on('data', d => { out += d; });
        child.stderr.on('data', d => { out += d; });
        child.on('close', status => resolve({ status, out }));
    });

    // Estado limpio: sin archivos previos en BD, disco ni copia
    await db.query('DELETE FROM user_files');
    fs.rmSync(path.join(filesDir, 'files'), { recursive: true, force: true });
    fs.rmSync(backupDir, { recursive: true, force: true });

    const file = await upload(png(9000), 'cli.png');
    assert.strictEqual((await run(['backup'])).status, 0);
    assert.strictEqual((await run(['verify'])).status, 0);

    fs.rmSync(await sourceFile(file.id));
    const lost = await run(['backup']);
    assert.strictEqual(lost.status, 2, 'archivo perdido → código 2 (alerta)');
    assert.match(lost.out, /ARCHIVOS PERDIDOS/);
    assert.strictEqual((await run(['restore'])).status, 0);
    assert.strictEqual((await run(['backup'])).status, 0);

    const name = await storageName(file.id);
    const copy = path.join(backupDir, 'files', name.slice(0, 2), `${name}.enc`);
    fs.writeFileSync(copy, crypto.randomBytes(50));
    assert.strictEqual((await run(['verify'])).status, 2, 'copia dañada → código 2');
    assert.strictEqual((await run(['nada'])).status, 2);
});
