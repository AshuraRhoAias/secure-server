// Pruebas del antivirus: cliente INSTREAM contra un clamd SIMULADO (siempre) y contra un clamd REAL (si está
// instalado). Integración con la subida de archivos y MariaDB real.
//
//   npm run test:av

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn, spawnSync } = require('child_process');

const { filesDir } = require('./test_helpers/env');
// Esta suite prueba la integración del antivirus con archivos sintéticos (relleno con cabecera): el saneamiento de
// imágenes los rechazaría. El orden antivirus → saneamiento se prueba con una imagen real más abajo.
process.env.IMAGE_SANITIZE = 'off';
const helpers = require('./test_helpers/app');
const { api, registerAndLogin, testIp } = helpers;
const { startFakeClamd, EICAR } = require('./test_helpers/fake-clamd');

const parseResult = (stdout) => JSON.parse(/^\{[\s\S]*?^\}$/m.exec(stdout)[0]); // el JSON del script, ignorando los logs de arranque
const bytes = (...parts) => Buffer.concat(parts.map(p => (Buffer.isBuffer(p) ? p : Buffer.from(p))));
const filler = (n, seed = 1) => { const b = Buffer.alloc(n); for (let i = 0; i < n; i++) b[i] = (i * 31 + seed) & 0xff; return b; };
const PNG = (n = 2000) => bytes([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a], filler(n, 2));
const multipart = (data, name) => { const f = new FormData(); f.append('file', new Blob([data]), name); return f; };

let dbAvailable = false;
let app, db, fake, alice, ipA;
const SCAN_VARS = ['FILE_SCAN', 'CLAMAV_HOST', 'CLAMAV_PORT', 'CLAMAV_SOCKET', 'CLAMAV_TIMEOUT_MS', 'CLAMAV_MAX_BYTES', 'FILE_SCAN_ON_OVERSIZE'];

function scanEnv(vars) {
    SCAN_VARS.forEach(k => delete process.env[k]);
    Object.assign(process.env, vars);
}
const viaFake = (mode, extra = {}) => scanEnv({ FILE_SCAN: mode, CLAMAV_HOST: '127.0.0.1', CLAMAV_PORT: String(fake.port), ...extra });

test.before(async () => {
    dbAvailable = await helpers.prepareDatabase();
    if (!dbAvailable) return;
    db = require('./src/config/database');
    app = await helpers.startApp();
    fake = await startFakeClamd();
    ipA = testIp();
    alice = await registerAndLogin(app.base, { ip: ipA });
});
test.after(async () => {
    SCAN_VARS.forEach(k => delete process.env[k]);
    if (fake) await fake.close();
    if (app) await app.close();
    if (db?.pool) await db.pool.end();
    fs.rmSync(filesDir, { recursive: true, force: true });
});

const itDb = (name, fn) => test(name, async (t) => {
    if (!dbAvailable) return t.skip('sin base de datos');
    fake.reset();
    scanEnv({});
    await fn(t);
});

const upload = (data, name, user = alice, ip = ipA) => api(app.base, 'POST', '/api/files', { token: user.token, ip, form: multipart(data, name) });
const tmpFiles = () => (fs.existsSync(path.join(filesDir, 'tmp')) ? fs.readdirSync(path.join(filesDir, 'tmp')) : []);
const rows = async () => (await db.query('SELECT COUNT(*) AS n FROM user_files'))[0][0].n;
const event = async (ip, rule) => (await db.query("SELECT severity, action_taken FROM security_events WHERE ip_address = ? AND rule = ?", [ip, rule]))[0];

// ============================================================================ protocolo (puro)

test('parseReply: OK, FOUND con firma saneada, ERROR y basura', () => {
    const { parseReply } = require('./src/files/av-scanner');
    assert.deepStrictEqual(parseReply('stream: OK\0'), { status: 'clean' });
    assert.deepStrictEqual(parseReply('stream: Win.Test.EICAR_HDB-1 FOUND\0'), { status: 'found', signature: 'Win.Test.EICAR_HDB-1' });
    assert.strictEqual(parseReply('stream: Evil; DROP TABLE x <script> FOUND\0').signature, 'Evil__DROP_TABLE_x__script_');
    assert.strictEqual(parseReply('INSTREAM size limit exceeded. ERROR\0').status, 'error');
    assert.strictEqual(parseReply('').status, 'error');
    assert.ok(parseReply('stream: ' + 'A'.repeat(500) + ' FOUND').signature.length <= 60);
});

// ============================================================================ con clamd simulado

itDb('FILE_SCAN desactivado (por defecto): no se contacta con clamd y el archivo queda "unscanned"', async () => {
    const res = await upload(Buffer.from(EICAR), 'prueba.txt');
    assert.strictEqual(res.status, 201);
    assert.strictEqual(res.body.file.scanStatus, 'unscanned');
    assert.strictEqual(fake.connections, 0);
});

itDb('required: un archivo limpio se escanea ENTERO (mismos bytes y hash) y queda "clean"', async () => {
    viaFake('required');
    const data = PNG(300_000);
    const res = await upload(data, 'limpio.png');
    assert.strictEqual(res.status, 201, res.text);
    assert.strictEqual(res.body.file.scanStatus, 'clean');
    assert.strictEqual(fake.received.length, 1);
    assert.strictEqual(fake.received[0].bytes, data.length);
    assert.strictEqual(fake.received[0].sha256, crypto.createHash('sha256').update(data).digest('hex'), 'clamd recibió exactamente el archivo');

    const got = await api(app.base, 'GET', `/api/files/${res.body.file.id}`, { token: alice.token, ip: ipA });
    assert.strictEqual(got.body.file.scanStatus, 'clean');
    const listed = await api(app.base, 'GET', '/api/files?limit=100', { token: alice.token, ip: ipA });
    assert.strictEqual(listed.body.files.find(f => f.id === res.body.file.id).scanStatus, 'clean');
    const dl = await api(app.base, 'GET', `/api/files/${res.body.file.id}/download`, { token: alice.token, ip: ipA });
    assert.ok(dl.buffer.equals(data));
});

itDb('el antivirus ve el archivo ORIGINAL: un EICAR escondido tras una imagen real salta como malware, no se pierde al recodificar', async () => {
    const sharp = require('sharp');
    const photo = await sharp({ create: { width: 30, height: 30, channels: 3, background: '#468' } }).jpeg().toBuffer();
    const user = await registerAndLogin(app.base, { ip: testIp() });
    const ip = testIp();
    viaFake('required');
    process.env.IMAGE_SANITIZE = 'on';
    try {
        const before = await rows();
        const res = await upload(bytes(photo, EICAR), 'foto.jpg', user, ip);
        assert.strictEqual(res.status, 422, res.text);
        assert.strictEqual(res.body.code, 'MALWARE_DETECTED', 'lo detecta el antivirus, no se limpia en silencio');
        assert.strictEqual(await rows(), before);
        assert.strictEqual((await event(ip, 'MALWARE_Eicar-Test-Signature')).length, 1);

        // sin el EICAR: pasa por el antivirus y después se recodifica
        const ok = await upload(photo, 'foto.jpg', user, ip);
        assert.strictEqual(ok.status, 201, ok.text);
        assert.deepStrictEqual([ok.body.file.scanStatus, ok.body.file.sanitizeStatus], ['clean', 'reencoded']);
    } finally { process.env.IMAGE_SANITIZE = 'off'; }
});

itDb('malware (EICAR): rechazo 422, sin fila ni archivos, evento CRÍTICO y strike', async () => {
    viaFake('required');
    const user = await registerAndLogin(app.base, { ip: testIp() });
    const ip = testIp();
    const before = { rows: await rows(), tmp: tmpFiles().length };

    const res = await upload(Buffer.from(EICAR), 'inofensivo.txt', user, ip);
    assert.strictEqual(res.status, 422);
    assert.strictEqual(res.body.code, 'MALWARE_DETECTED');
    assert.ok(!res.body.token);

    assert.strictEqual(await rows(), before.rows);
    assert.strictEqual(tmpFiles().length, before.tmp, 'ningún temporal');
    const trail = await event(ip, 'MALWARE_Eicar-Test-Signature');
    assert.strictEqual(trail.length, 1);
    assert.deepStrictEqual([trail[0].severity, trail[0].action_taken], ['critical', 'rejected']);
});

itDb('malware escondido: a caballo entre dos bloques, en medio de un archivo grande y dentro de una imagen', async () => {
    viaFake('required');
    const user = await registerAndLogin(app.base, { ip: testIp() });
    const ip = testIp();

    const text = Buffer.from('línea de texto normal\n'.repeat(30_000));
    const astride = bytes(text.subarray(0, 65_530), EICAR, text.subarray(65_530)); // cruza el límite de 64 KiB
    assert.strictEqual((await upload(astride, 'grande.txt', user, ip)).status, 422);

    assert.strictEqual((await upload(bytes(PNG(100_000), EICAR, filler(100_000)), 'foto.png', user, ip)).status, 422);

    // el mismo archivo SIN el EICAR pasa
    assert.strictEqual((await upload(text, 'limpio.txt', user, ip)).status, 201);
});

itDb('un archivo rechazado por TIPO (ejecutable) ni siquiera llega al antivirus', async () => {
    viaFake('required');
    const res = await upload(bytes('MZ', filler(500)), 'x.jpg');
    assert.strictEqual(res.status, 415);
    assert.strictEqual(fake.connections, 0);
});

itDb('archivo vacío: no hay nada que escanear (sin conexión) y se acepta como "clean"', async () => {
    viaFake('required');
    const res = await upload(Buffer.alloc(0), 'vacio.txt');
    assert.strictEqual(res.status, 201);
    assert.strictEqual(res.body.file.scanStatus, 'clean');
    assert.strictEqual(fake.connections, 0);
});

const BROKEN = {
    'clamd apagado (conexión rechazada)': () => viaFake('required', { CLAMAV_PORT: '1' }),
    'clamd corta la conexión a mitad': () => { viaFake('required'); fake.dropAfterBytes = 10_000; },
    'clamd no contesta nunca (timeout)': () => { viaFake('required', { CLAMAV_TIMEOUT_MS: '600' }); fake.behavior = 'silent'; },
    'clamd devuelve un error': () => { viaFake('required'); fake.behavior = 'error'; }
};

for (const [name, setup] of Object.entries(BROKEN)) {
    itDb(`required, ${name} → 503 SCANNER_UNAVAILABLE y no se guarda NADA (falla cerrado)`, async () => {
        setup();
        const ip = testIp();
        const user = await registerAndLogin(app.base, { ip: testIp() });
        const before = { rows: await rows(), tmp: tmpFiles().length };
        const res = await upload(PNG(80_000), 'x.png', user, ip);
        assert.strictEqual(res.status, 503, res.text);
        assert.strictEqual(res.body.code, 'SCANNER_UNAVAILABLE');
        assert.strictEqual(await rows(), before.rows);
        assert.strictEqual(tmpFiles().length, before.tmp);
        assert.ok(!/ECONN|127\.0\.0\.1|clamd/i.test(res.text), 'no se filtran detalles internos');
    });
}

itDb('optional, con clamd caído: se acepta marcado "unscanned" y queda un evento; con clamd sano SÍ rechaza malware', async () => {
    viaFake('optional', { CLAMAV_PORT: '1' });
    const user = await registerAndLogin(app.base, { ip: testIp() });
    const ip = testIp();
    const res = await upload(PNG(5000), 'a.png', user, ip);
    assert.strictEqual(res.status, 201);
    assert.strictEqual(res.body.file.scanStatus, 'unscanned');
    assert.ok((await event(ip, 'SCAN_SKIPPED_OPTIONAL')).length >= 1);

    viaFake('optional');
    assert.strictEqual((await upload(Buffer.from(EICAR), 'a.txt', user, ip)).status, 422);
    assert.strictEqual((await upload(PNG(5000), 'b.png', user, ip)).body.file.scanStatus, 'clean');
});

itDb('optional, con clamd que cae A MITAD de la subida: el archivo se guarda COMPLETO y íntegro, sin escanear', async () => {
    viaFake('optional');
    fake.dropAfterBytes = 10_000;
    const data = PNG(200_000);
    const res = await upload(data, 'mitad.png');
    assert.strictEqual(res.status, 201, res.text);
    assert.strictEqual(res.body.file.scanStatus, 'unscanned');
    const dl = await api(app.base, 'GET', `/api/files/${res.body.file.id}/download`, { token: alice.token, ip: ipA });
    assert.ok(dl.buffer.equals(data), 'ni un byte perdido');
    assert.strictEqual(dl.headers.get('x-content-sha256'), crypto.createHash('sha256').update(data).digest('hex'));
});

itDb('límite del escáner: reject → 413 SCAN_SIZE_LIMIT; skip → se guarda "skipped"', async () => {
    viaFake('required', { CLAMAV_MAX_BYTES: '100000' });
    const big = PNG(250_000);
    const rejected = await upload(big, 'grande.png');
    assert.strictEqual(rejected.status, 413);
    assert.strictEqual(rejected.body.code, 'SCAN_SIZE_LIMIT');
    assert.deepStrictEqual(tmpFiles().filter(f => f.endsWith('.part')), []);

    viaFake('required', { CLAMAV_MAX_BYTES: '100000', FILE_SCAN_ON_OVERSIZE: 'skip' });
    const skipped = await upload(big, 'grande2.png');
    assert.strictEqual(skipped.status, 201);
    assert.strictEqual(skipped.body.file.scanStatus, 'skipped');
    assert.ok((await api(app.base, 'GET', `/api/files/${skipped.body.file.id}/download`, { token: alice.token, ip: ipA })).buffer.equals(big));
});

itDb('clamd con StreamMaxLength menor que el nuestro: su "size limit exceeded" no deja pasar el archivo', async () => {
    viaFake('required');
    fake.maxBytes = 50_000; // clamd rechaza, aunque CLAMAV_MAX_BYTES (25 MB) no lo sepa
    const res = await upload(PNG(120_000), 'x.png');
    assert.strictEqual(res.status, 503);
    assert.strictEqual(await (async () => (await db.query("SELECT COUNT(*) AS n FROM user_files WHERE size_bytes = 120008"))[0][0].n)(), 0);
});

itDb('subidas simultáneas: cada una con su sesión de clamd y su propio veredicto', async () => {
    viaFake('required');
    const user = await registerAndLogin(app.base, { ip: testIp() });
    const jobs = [
        ...Array.from({ length: 6 }, (_, i) => ({ data: PNG(60_000 + i), name: `ok${i}.png`, expect: 201 })),
        ...Array.from({ length: 3 }, (_, i) => ({ data: bytes(PNG(30_000 + i), EICAR), name: `mal${i}.png`, expect: 422 }))
    ];
    const results = await Promise.all(jobs.map(j => upload(j.data, j.name, user, testIp())));
    results.forEach((r, i) => assert.strictEqual(r.status, jobs[i].expect, `${jobs[i].name}: ${r.text}`));
    assert.strictEqual(fake.connections, 9);
});

// ============================================================================ revisión de lo ya guardado

itDb('rescan-files: encuentra malware que se coló antes de activar el antivirus, lo borra si se pide y marca el resto "clean"', async () => {
    const user = await registerAndLogin(app.base, { ip: testIp() });
    const ip = testIp();
    // Sin antivirus (FILE_SCAN=off): entra todo
    const clean = (await upload(PNG(150_000), 'a.png', user, ip)).body.file;
    const bad = (await upload(Buffer.from(EICAR), 'b.txt', user, ip)).body.file;
    const alsoBad = (await upload(bytes(PNG(100_000), EICAR), 'c.png', user, ip)).body.file;
    assert.deepStrictEqual([clean.scanStatus, bad.scanStatus], ['unscanned', 'unscanned']);

    // spawn ASÍNCRONO: el clamd simulado vive en este proceso y un spawnSync lo dejaría sin atender
    const run = (extra = []) => new Promise((resolve) => {
        const child = spawn(process.execPath, [path.join(__dirname, 'scripts/rescanFiles.js'), ...extra], {
            env: { ...process.env, FILE_SCAN: 'required', CLAMAV_HOST: '127.0.0.1', CLAMAV_PORT: String(fake.port), ENV_FILE: '/nonexistent' }
        });
        let stdout = '', stderr = '';
        child.stdout.on('data', d => { stdout += d; });
        child.stderr.on('data', d => { stderr += d; });
        child.on('close', status => resolve({ status, stdout, stderr }));
    });

    const report = await run();
    assert.strictEqual(report.status, 3, report.stderr + report.stdout.slice(-600));
    const summary = parseResult(report.stdout);
    const infectedIds = summary.infected.map(i => i.id);
    assert.ok(infectedIds.includes(bad.id) && infectedIds.includes(alsoBad.id), 'encuentra los dos nuevos (y el EICAR de la primera prueba)');
    assert.ok(!infectedIds.includes(clean.id));
    assert.ok(summary.infected.every(i => i.signature === 'Eicar-Test-Signature'));
    assert.strictEqual((await db.query('SELECT scan_status FROM user_files WHERE id = ?', [clean.id]))[0][0].scan_status, 'clean');
    assert.strictEqual((await db.query('SELECT 1 FROM user_files WHERE id = ?', [bad.id]))[0].length, 1, 'sin --delete-infected no se borra');

    const purge = await run(['--delete-infected', '--all']);
    assert.strictEqual(purge.status, 3);
    assert.ok(parseResult(purge.stdout).deleted >= 2);
    assert.strictEqual((await db.query('SELECT 1 FROM user_files WHERE id IN (?, ?)', [bad.id, alsoBad.id]))[0].length, 0);
    assert.strictEqual((await api(app.base, 'GET', `/api/files/${clean.id}/download`, { token: user.token, ip })).status, 200, 'el limpio sigue');
    assert.strictEqual((await run()).status, 0, 'ya no queda nada sospechoso');
});

// ============================================================================ con clamd REAL (si está instalado)

const clamdBinary = spawnSync('which', ['clamd'], { encoding: 'utf8' }).stdout.trim();
let real = null;

async function startRealClamd() {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'clamd-'));
    const db = path.join(dir, 'db');
    fs.mkdirSync(db);
    // Firmas locales (no hace falta descargar nada): el hash MD5 del archivo EICAR y un patrón del contenido
    fs.writeFileSync(path.join(db, 'eicar.hdb'), '44d88612fea8a8f36de82e1278abb02f:68:Eicar-Test-Signature\n');
    fs.writeFileSync(path.join(db, 'eicar-body.ndb'), `Eicar.Embedded:0:*:${Buffer.from('EICAR-STANDARD-ANTIVIRUS-TEST-FILE!').toString('hex')}\n`);

    const socket = path.join(dir, 'clamd.sock');
    const asRoot = process.getuid() === 0;
    const conf = path.join(dir, 'clamd.conf');
    fs.writeFileSync(conf, [
        `DatabaseDirectory ${db}`, `LocalSocket ${socket}`, `LogFile ${dir}/clamd.log`, 'Foreground yes', 'StreamMaxLength 25M',
        'MaxThreads 4', ...(asRoot ? ['User clamav'] : [])
    ].join('\n') + '\n');
    if (asRoot) spawnSync('chown', ['-R', 'clamav:clamav', dir]);
    fs.chmodSync(dir, 0o755);

    const child = spawn(clamdBinary, ['-c', conf], { stdio: 'ignore' });
    for (let i = 0; i < 120; i++) {
        if (fs.existsSync(socket)) {
            const ok = await new Promise((resolve) => {
                const s = require('net').connect(socket, () => s.write('zPING\0'));
                s.on('data', (d) => { resolve(String(d).startsWith('PONG')); s.destroy(); });
                s.on('error', () => resolve(false));
            });
            if (ok) return { socket, child, dir };
        }
        await new Promise(r => setTimeout(r, 500));
    }
    child.kill();
    return null;
}

test('clamd REAL: arranca con firmas locales', async (t) => {
    if (!dbAvailable || !clamdBinary) return t.skip('clamd no instalado');
    real = await startRealClamd();
    if (!real) return t.skip('clamd no pudo arrancar en este entorno');
    assert.ok(real.socket);
});

const itReal = (name, fn) => test(`clamd REAL: ${name}`, async (t) => {
    if (!real) return t.skip('sin clamd real');
    scanEnv({ FILE_SCAN: 'required', CLAMAV_SOCKET: real.socket });
    await fn();
});

itReal('un archivo limpio pasa y queda "clean"', async () => {
    const res = await upload(PNG(1_000_000), 'real-limpio.png');
    assert.strictEqual(res.status, 201, res.text);
    assert.strictEqual(res.body.file.scanStatus, 'clean');
});

itReal('EICAR (firma de hash) → 422 con el nombre de la firma real', async () => {
    const ip = testIp();
    const res = await upload(Buffer.from(EICAR), 'real-eicar.txt', alice, ip);
    assert.strictEqual(res.status, 422, res.text);
    assert.strictEqual(res.body.code, 'MALWARE_DETECTED');
    const rules = (await db.query("SELECT rule FROM security_events WHERE ip_address = ? AND event_type = 'FILE_REJECTED'", [ip]))[0].map(r => r.rule);
    assert.ok(rules.some(r => /^MALWARE_Eicar/.test(r)), `reglas registradas: ${rules}`);
});

itReal('EICAR escondido en un archivo grande y a caballo entre bloques → 422 (firma de contenido)', async () => {
    const ip = testIp();
    const text = Buffer.from('texto normal de relleno\n'.repeat(60_000)); // ~1,4 MB
    const res = await upload(bytes(text.subarray(0, 131_070), EICAR, text.subarray(131_070)), 'real-grande.txt', alice, ip);
    assert.strictEqual(res.status, 422, res.text);
    const rules = (await db.query("SELECT rule FROM security_events WHERE ip_address = ? AND event_type = 'FILE_REJECTED'", [ip]))[0].map(r => r.rule);
    assert.ok(rules.some(r => /^MALWARE_Eicar/.test(r)), `reglas registradas: ${rules}`);
    assert.strictEqual((await upload(bytes(PNG(300_000), EICAR), 'real-img.png', alice, ip)).status, 422);
});

itReal('con clamd real apagado, required falla cerrado', async () => {
    process.env.CLAMAV_SOCKET = path.join(os.tmpdir(), 'no-existe.sock');
    assert.strictEqual((await upload(PNG(1000), 'x.png')).status, 503);
});

test.after(() => { if (real) { real.child.kill(); fs.rmSync(real.dir, { recursive: true, force: true }); } });
