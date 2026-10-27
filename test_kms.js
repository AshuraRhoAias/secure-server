// Pruebas de la envoltura de secretos con KMS: proveedor "file" real, Vault Transit y AWS KMS (SDK oficial)
// contra servidores simulados, la CLI, el arranque falla-cerrado y la equivalencia de claves.
//
//   npm run test:kms

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn, spawnSync, execFileSync } = require('child_process');

const ROOT = __dirname;
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'kms-test-'));
test.after(() => { fs.rmSync(tmp, { recursive: true, force: true }); servers.forEach(s => s.kill()); });

// Cada prueba trabaja con su propio entorno limpio de KMS_*
const KMS_VARS = ['KMS_PROVIDER', 'KMS_KEK_FILE', 'KMS_KEK_ALLOW_LOOSE_PERMS', 'KMS_KEY_ID', 'KMS_ENDPOINT', 'VAULT_ADDR', 'VAULT_TOKEN', 'VAULT_TRANSIT_KEY', 'AWS_REGION', 'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY'];
function withKms(vars, fn) {
    const saved = Object.fromEntries(KMS_VARS.map(k => [k, process.env[k]]));
    KMS_VARS.forEach(k => delete process.env[k]);
    Object.assign(process.env, vars);
    const kms = require('./src/crypto/kms');
    kms.clearCache();
    try { return fn(kms); } finally {
        KMS_VARS.forEach(k => { if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k]; });
        kms.clearCache();
    }
}

const newKekFile = (name = 'kek', mode = 0o400) => {
    const file = path.join(tmp, `${name}-${crypto.randomBytes(3).toString('hex')}`);
    fs.writeFileSync(file, crypto.randomBytes(32).toString('hex'), { mode });
    fs.chmodSync(file, mode);
    return file;
};

const servers = [];
async function startMock(kind) {
    const child = spawn(process.execPath, [path.join(ROOT, 'test_helpers/mock-kms-server.js'), kind], { stdio: ['ignore', 'pipe', 'inherit'] });
    servers.push(child);
    const port = await new Promise(resolve => child.stdout.on('data', d => { const m = /PORT (\d+)/.exec(String(d)); if (m) resolve(Number(m[1])); }));
    return { port, url: `http://127.0.0.1:${port}`, last: async () => (await fetch(`http://127.0.0.1:${port}/__last`)).json() };
}

// ============================================================================ proveedor "file"

test('file: ida y vuelta; el valor nunca aparece en claro; dos envoltorios del mismo valor difieren', () => {
    withKms({ KMS_PROVIDER: 'file', KMS_KEK_FILE: newKekFile() }, (kms) => {
        const secret = 'semilla-ultra-secreta-' + crypto.randomBytes(8).toString('hex');
        const a = kms.wrapValue('ENCRYPTION_SEED', secret);
        const b = kms.wrapValue('ENCRYPTION_SEED', secret);
        assert.match(a, /^kms:file:[A-Za-z0-9_-]+$/);
        assert.notStrictEqual(a, b);
        assert.ok(!a.includes(secret) && !Buffer.from(a.split(':')[2], 'base64url').includes(secret));

        kms.clearCache();
        assert.strictEqual(kms.resolveValue('ENCRYPTION_SEED', a), secret);
        assert.strictEqual(kms.resolveValue('ENCRYPTION_SEED', b), secret);
        assert.strictEqual(kms.resolveValue('SIN_ENVOLVER', 'valor normal'), 'valor normal', 'lo que no está envuelto pasa tal cual');
    });
});

test('file: valores con saltos de línea, unicode, vacíos y largos', () => {
    withKms({ KMS_PROVIDER: 'file', KMS_KEK_FILE: newKekFile() }, (kms) => {
        for (const value of ['con\nsalto', 'ñandú 🔐 日本語', 'x'.repeat(100_000), 'a:b:c', 'kms:file:fake']) {
            const wrapped = kms.wrapValue('X', value);
            kms.clearCache();
            assert.strictEqual(kms.resolveValue('X', wrapped), value);
        }
    });
});

test('file: el blob de una variable NO sirve para otra (el nombre va dentro del valor cifrado)', () => {
    withKms({ KMS_PROVIDER: 'file', KMS_KEK_FILE: newKekFile() }, (kms) => {
        const wrapped = kms.wrapValue('JWT_SEED', 'valor-de-jwt');
        kms.clearCache();
        assert.throws(() => kms.resolveValue('ENCRYPTION_SEED', wrapped), /no pertenece a la variable ENCRYPTION_SEED/);
    });
});

test('file: un blob alterado, truncado o con otra KEK se rechaza', () => {
    const kek = newKekFile();
    let wrapped;
    withKms({ KMS_PROVIDER: 'file', KMS_KEK_FILE: kek }, (kms) => { wrapped = kms.wrapValue('X', 'secreto'); });

    withKms({ KMS_KEK_FILE: kek }, (kms) => {
        const raw = Buffer.from(wrapped.split(':')[2], 'base64url');
        for (const pos of [0, 12, 28, raw.length - 1]) {
            const copy = Buffer.from(raw); copy[pos] ^= 1;
            assert.throws(() => kms.resolveValue('X', `kms:file:${copy.toString('base64url')}`), /KMS/, `byte ${pos}`);
        }
        assert.throws(() => kms.resolveValue('X', `kms:file:${raw.subarray(0, 20).toString('base64url')}`), /KMS/);
        assert.strictEqual(kms.resolveValue('X', wrapped), 'secreto', 'el original sigue válido');
    });
    withKms({ KMS_KEK_FILE: newKekFile() }, (kms) => {
        assert.throws(() => kms.resolveValue('X', wrapped), /KMS/, 'otra KEK');
    });
});

test('file: KEK con permisos abiertos, ausente o de tamaño erróneo → error claro', () => {
    const loose = newKekFile('loose', 0o644);
    withKms({ KMS_PROVIDER: 'file', KMS_KEK_FILE: loose }, (kms) => {
        assert.throws(() => kms.wrapValue('X', 'v'), /legible por otros usuarios.*chmod 400/);
    });
    withKms({ KMS_PROVIDER: 'file', KMS_KEK_FILE: loose, KMS_KEK_ALLOW_LOOSE_PERMS: 'true' }, (kms) => {
        assert.ok(kms.wrapValue('X', 'v'));
    });
    withKms({ KMS_PROVIDER: 'file', KMS_KEK_FILE: path.join(tmp, 'no-existe') }, (kms) => {
        assert.throws(() => kms.wrapValue('X', 'v'), /KMS/);
    });
    const short = path.join(tmp, 'short'); fs.writeFileSync(short, 'abcd', { mode: 0o400 });
    withKms({ KMS_PROVIDER: 'file', KMS_KEK_FILE: short }, (kms) => {
        assert.throws(() => kms.wrapValue('X', 'v'), /32 bytes/);
    });
    withKms({ KMS_PROVIDER: 'inventado' }, (kms) => {
        assert.throws(() => kms.wrapValue('X', 'v'), /proveedor desconocido/);
    });
    withKms({}, (kms) => assert.throws(() => kms.wrapValue('X', 'v'), /KMS_PROVIDER/));
});

test('al leer manda el proveedor del propio valor, aunque KMS_PROVIDER sea otro', () => {
    const kek = newKekFile();
    let wrapped;
    withKms({ KMS_PROVIDER: 'file', KMS_KEK_FILE: kek }, (kms) => { wrapped = kms.wrapValue('X', 'v'); });
    withKms({ KMS_PROVIDER: 'aws', KMS_KEK_FILE: kek }, (kms) => assert.strictEqual(kms.resolveValue('X', wrapped), 'v'));
});

// ============================================================================ arranque: falla cerrado y claves idénticas

const fingerprintScript = "const e=require('./src/config/secure-env');console.log(JSON.stringify({fp:e.fingerprint,epoch:e.epoch,base:process.env.BASE_SEED,enc:process.env.ENCRYPTION_SEED}))";
const runSecureEnv = (env) => spawnSync(process.execPath, ['-e', fingerprintScript], { cwd: ROOT, env: { PATH: process.env.PATH, ...env }, encoding: 'utf8' });

test('arranque: con semillas envueltas deriva EXACTAMENTE las mismas claves que con las semillas en claro', () => {
    const kek = newKekFile();
    const seeds = { BASE_SEED: 'base-' + crypto.randomBytes(16).toString('hex'), ENCRYPTION_SEED: 'enc-' + crypto.randomBytes(16).toString('hex'), JWT_SEED: 'jwt-' + crypto.randomBytes(16).toString('hex'), KEY_EPOCH: 'EPOCH-1' };

    const plain = runSecureEnv(seeds);
    assert.strictEqual(plain.status, 0, plain.stderr);

    const wrapped = {};
    withKms({ KMS_PROVIDER: 'file', KMS_KEK_FILE: kek }, (kms) => {
        for (const name of ['BASE_SEED', 'ENCRYPTION_SEED', 'JWT_SEED']) wrapped[name] = kms.wrapValue(name, seeds[name]);
    });
    const viaKms = runSecureEnv({ ...seeds, ...wrapped, KMS_KEK_FILE: kek });
    assert.strictEqual(viaKms.status, 0, viaKms.stderr);

    const a = JSON.parse(plain.stdout.split('\n').filter(Boolean).pop());
    const b = JSON.parse(viaKms.stdout.split('\n').filter(Boolean).pop());
    assert.deepStrictEqual(b, a, 'misma huella, época y semillas descifradas');
    assert.match(viaKms.stdout, /3 secretos descifrados con el KMS/);
});

test('arranque: si el KMS no responde o la KEK es incorrecta, el proceso NO arranca (falla cerrado)', () => {
    const kek = newKekFile();
    const wrapped = {};
    withKms({ KMS_PROVIDER: 'file', KMS_KEK_FILE: kek }, (kms) => {
        wrapped.BASE_SEED = kms.wrapValue('BASE_SEED', 'base-seed');
        wrapped.ENCRYPTION_SEED = kms.wrapValue('ENCRYPTION_SEED', 'enc-seed');
        wrapped.JWT_SEED = kms.wrapValue('JWT_SEED', 'jwt-seed');
    });
    const base = { ...wrapped, KEY_EPOCH: 'EPOCH-1' };

    const noKek = runSecureEnv({ ...base });
    assert.notStrictEqual(noKek.status, 0);
    assert.match(noKek.stderr, /KMS: falta KMS_KEK_FILE/);

    const wrongKek = runSecureEnv({ ...base, KMS_KEK_FILE: newKekFile() });
    assert.notStrictEqual(wrongKek.status, 0);
    assert.match(wrongKek.stderr, /KMS/);
    assert.ok(!/base-seed|enc-seed|jwt-seed/.test(wrongKek.stdout + wrongKek.stderr), 'no se filtra ningún valor');
});

test('el texto claro no viaja por argumentos ni por el entorno del proceso hijo', () => {
    const src = fs.readFileSync(path.join(ROOT, 'src/crypto/kms.js'), 'utf8');
    assert.match(src, /input: JSON\.stringify/, 'los valores van por stdin');
    assert.ok(!/execFileSync\(process\.execPath, \[WORKER, [^\]]*JSON/.test(src), 'nada en argv');
});

// ============================================================================ Vault (Transit)

test('vault: ida y vuelta contra Transit simulado; token incorrecto y variable cruzada fallan', async () => {
    const vault = await startMock('vault');
    withKms({ KMS_PROVIDER: 'vault', VAULT_ADDR: vault.url, VAULT_TOKEN: 's.token-valido' }, (kms) => {
        const wrapped = kms.wrapValue('ENCRYPTION_SEED', 'semilla-vault');
        assert.match(wrapped, /^kms:vault:/);
        assert.ok(!Buffer.from(wrapped.split(':')[2], 'base64url').toString().includes('semilla-vault'));
        kms.clearCache();
        assert.strictEqual(kms.resolveValue('ENCRYPTION_SEED', wrapped), 'semilla-vault');
        kms.clearCache();
        assert.throws(() => kms.resolveValue('JWT_SEED', wrapped), /no pertenece a la variable JWT_SEED/);
    });
    const last = await vault.last();
    assert.strictEqual(last.headers['x-vault-token'], 's.token-valido');

    withKms({ KMS_PROVIDER: 'vault', VAULT_ADDR: vault.url, VAULT_TOKEN: 'token-malo' }, (kms) => {
        assert.throws(() => kms.wrapValue('X', 'v'), /Vault respondió 403.*permission denied/);
    });
    withKms({ KMS_PROVIDER: 'vault', VAULT_ADDR: vault.url }, (kms) => assert.throws(() => kms.wrapValue('X', 'v'), /VAULT_TOKEN/));
    withKms({ KMS_PROVIDER: 'vault', VAULT_ADDR: 'http://127.0.0.1:1', VAULT_TOKEN: 'x' }, (kms) => assert.throws(() => kms.wrapValue('X', 'v'), /KMS/), 'Vault caído');
});

test('vault en producción exige https', () => {
    const r = spawnSync(process.execPath, ['-e', "const k=require('./src/crypto/kms');try{k.wrapValue('X','v')}catch(e){console.log(e.message)}"], {
        cwd: ROOT, encoding: 'utf8', env: { PATH: process.env.PATH, NODE_ENV: 'production', KMS_PROVIDER: 'vault', VAULT_ADDR: 'http://vault.interno:8200', VAULT_TOKEN: 't' }
    });
    assert.match(r.stdout, /https:\/\/ en producción/);
});

// ============================================================================ AWS KMS (SDK oficial)

test('aws: ida y vuelta con el SDK oficial (petición firmada SigV4); el contexto de cifrado liga el valor a su variable', async () => {
    const aws = await startMock('aws');
    const cfg = { KMS_PROVIDER: 'aws', KMS_KEY_ID: 'arn:aws:kms:us-east-1:111122223333:key/test', KMS_ENDPOINT: aws.url, AWS_REGION: 'us-east-1', AWS_ACCESS_KEY_ID: 'AKIATEST', AWS_SECRET_ACCESS_KEY: 'secret' };
    withKms(cfg, (kms) => {
        const wrapped = kms.wrapValue('ENCRYPTION_SEED', 'semilla-aws');
        assert.match(wrapped, /^kms:aws:/);
        kms.clearCache();
        assert.strictEqual(kms.resolveValue('ENCRYPTION_SEED', wrapped), 'semilla-aws');
        kms.clearCache();
        assert.throws(() => kms.resolveValue('JWT_SEED', wrapped), /KMS/, 'otro EncryptionContext');
    });

    const last = await aws.last();
    assert.match(last.headers.authorization, /^AWS4-HMAC-SHA256 Credential=AKIATEST\/\d{8}\/us-east-1\/kms\/aws4_request/);
    assert.match(last.headers['x-amz-target'], /^TrentService\.(Encrypt|Decrypt)$/);
    assert.deepStrictEqual(JSON.parse(last.body).EncryptionContext, { app: 'secure-server', variable: last.body.includes('JWT_SEED') ? 'JWT_SEED' : 'ENCRYPTION_SEED' });

    withKms({ ...cfg, KMS_KEY_ID: '' }, (kms) => assert.throws(() => kms.wrapValue('X', 'v'), /KMS_KEY_ID/));
});

// ============================================================================ CLI

const cli = (args, { env = {}, input } = {}) => spawnSync(process.execPath, [path.join(ROOT, 'scripts/kms.js'), ...args], {
    cwd: ROOT, encoding: 'utf8', input, env: { PATH: process.env.PATH, ...env }
});

test('CLI: wrap lee el valor por stdin y status verifica el proveedor', () => {
    const env = { KMS_PROVIDER: 'file', KMS_KEK_FILE: newKekFile() };
    const wrapped = cli(['wrap', 'JWT_SEED'], { env, input: 'valor-por-stdin\n' });
    assert.strictEqual(wrapped.status, 0, wrapped.stderr);
    assert.match(wrapped.stdout, /^JWT_SEED=kms:file:/);
    assert.ok(!wrapped.stdout.includes('valor-por-stdin'));
    assert.match(cli(['status'], { env }).stdout, /Prueba de cifrado\/descifrado correcta/);
    assert.notStrictEqual(cli(['wrap', 'MAL NOMBRE'], { env, input: 'x' }).status, 0);
    assert.notStrictEqual(cli(['wrap', 'X'], { env, input: '' }).status, 0);
    assert.strictEqual(cli(['nada'], { env }).status, 2);
});

test('CLI: migrate-env envuelve en el sitio, conserva comentarios y otras variables, deja copia 0600 y unwrap-env devuelve el original', () => {
    const env = { KMS_PROVIDER: 'file', KMS_KEK_FILE: newKekFile() };
    const file = path.join(tmp, 'migrar.env');
    const original = '# configuración\nPORT=3000\nBASE_SEED=base-en-claro\nENCRYPTION_SEED=enc-en-claro\nJWT_SEED=jwt-en-claro\nDB_FRAGMENT_1=mysql://u:clave@\nNODE_ENV=production\n';
    fs.writeFileSync(file, original, { mode: 0o600 });

    const out = cli(['migrate-env', '--file', file], { env });
    assert.strictEqual(out.status, 0, out.stderr);

    const migrated = fs.readFileSync(file, 'utf8');
    for (const plain of ['base-en-claro', 'enc-en-claro', 'jwt-en-claro', 'clave@']) assert.ok(!migrated.includes(plain), plain);
    assert.match(migrated, /^# configuración\nPORT=3000\n/);
    assert.match(migrated, /NODE_ENV=production\n$/);
    for (const name of ['BASE_SEED', 'ENCRYPTION_SEED', 'JWT_SEED', 'DB_FRAGMENT_1']) assert.match(migrated, new RegExp(`^${name}=kms:file:`, 'm'));
    assert.strictEqual(fs.readFileSync(`${file}.pre-kms`, 'utf8'), original);
    assert.strictEqual(fs.statSync(`${file}.pre-kms`).mode & 0o777, 0o600);
    assert.strictEqual(fs.statSync(file).mode & 0o777, 0o600);

    assert.match(cli(['migrate-env', '--file', file], { env }).stdout, /Nada que migrar/, 'idempotente');
    assert.strictEqual(cli(['unwrap-env', '--file', file], { env }).stdout, original);
    assert.match(cli(['status', '--file', file], { env }).stdout, /BASE_SEED, ENCRYPTION_SEED, JWT_SEED, DB_FRAGMENT_1/);
});

test('CLI: si la verificación falla o el KMS no responde, el archivo NO se modifica', () => {
    const file = path.join(tmp, 'intacto.env');
    const original = 'BASE_SEED=base\nENCRYPTION_SEED=enc\nJWT_SEED=jwt\n';
    fs.writeFileSync(file, original);
    const r = cli(['migrate-env', '--file', file], { env: { KMS_PROVIDER: 'file', KMS_KEK_FILE: path.join(tmp, 'no-hay-kek') } });
    assert.notStrictEqual(r.status, 0);
    assert.strictEqual(fs.readFileSync(file, 'utf8'), original);
    assert.ok(!fs.existsSync(`${file}.pre-kms`));
    assert.notStrictEqual(cli(['migrate-env', '--file', file], { env: {} }).status, 0, 'sin KMS_PROVIDER');
});

test('CLI: --rewrap pasa los secretos de una KEK a otra (cambio de proveedor/clave de envoltura)', () => {
    const kekA = newKekFile(), kekB = newKekFile();
    const file = path.join(tmp, 'rewrap.env');
    fs.writeFileSync(file, 'BASE_SEED=base\nENCRYPTION_SEED=enc\nJWT_SEED=jwt\n');
    assert.strictEqual(cli(['migrate-env', '--file', file, '--no-backup'], { env: { KMS_PROVIDER: 'file', KMS_KEK_FILE: kekA } }).status, 0);
    const underA = fs.readFileSync(file, 'utf8');

    // Con la KEK nueva todavía no se puede leer: hace falta la anterior para re-envolver
    assert.notStrictEqual(cli(['unwrap-env', '--file', file], { env: { KMS_KEK_FILE: kekB } }).status, 0);
    // (re-envolver necesita leer con A y escribir con B: ambas KEK deben estar a mano en el entorno)
    const both = cli(['migrate-env', '--file', file, '--rewrap', '--no-backup'], { env: { KMS_PROVIDER: 'file', KMS_KEK_FILE: kekA } });
    assert.strictEqual(both.status, 0, both.stderr);
    assert.notStrictEqual(fs.readFileSync(file, 'utf8'), underA, 'los blobs cambian al re-envolver');
    assert.strictEqual(cli(['unwrap-env', '--file', file], { env: { KMS_KEK_FILE: kekA } }).stdout, 'BASE_SEED=base\nENCRYPTION_SEED=enc\nJWT_SEED=jwt\n');
});
