// Tests de claves estables, backups, modo mantenimiento y rotación con migración de datos.
//
//   npm run test:rotation
//
// Las pruebas de integración usan una base de datos MySQL/MariaDB REAL (tablas del esquema del
// proyecto) y se omiten si no hay una disponible. Por defecto:
//
//   mysql://sec:sec_test_pw@127.0.0.1:3306/secure_platform_test      (cámbialo con TEST_DB_URL)
//
// Preparación (una vez): CREATE DATABASE secure_platform_test; y un usuario con todos los permisos sobre ella.

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync, spawnSync } = require('child_process');

const dbUrl = new URL(process.env.TEST_DB_URL || 'mysql://sec:sec_test_pw@127.0.0.1:3306/secure_platform_test');
const DB_NAME = dbUrl.pathname.slice(1);

// El entorno se fija ANTES de cargar cualquier módulo del proyecto (secure-env deriva las claves al cargarse)
Object.assign(process.env, {
    NODE_ENV: 'test',
    BASE_SEED: 'base-seed-de-tests',
    ENCRYPTION_SEED: 'enc-seed-inicial',
    JWT_SEED: 'jwt-seed-inicial',
    KEY_EPOCH: 'T0-inicial',
    DB_FRAGMENT_1: `mysql://${dbUrl.username}:${dbUrl.password}@`,
    DB_FRAGMENT_2: dbUrl.host,
    DB_FRAGMENT_3: `/${DB_NAME}`,
    DISABLE_EMAIL_NOTIFICATIONS: 'true'
});

const keyProvider = require('./src/crypto/key-provider');
const archive = require('./src/backup/archive');
const { buildKeyring, openKeyring } = require('./src/backup/keyring');
const { ENCRYPTED_COLUMNS, IGNORED } = require('./src/crypto/encrypted-columns');
const { applyEnvUpdates } = require('./src/maintenance/rotation.service');

const quietLog = { log() {} };
const tmpDir = () => fs.mkdtempSync(path.join(os.tmpdir(), 'rot-'));

// ======================================================================= pruebas puras

test('modo estable: las claves no dependen del día; modo legacy: sí', () => {
    const env = { BASE_SEED: 'b', ENCRYPTION_SEED: 'e', JWT_SEED: 'j', KEY_EPOCH: 'EP1' };
    const hoy = keyProvider.deriveFromEnv(env, { today: '2026-10-20' });
    const manana = keyProvider.deriveFromEnv(env, { today: '2026-10-21' });
    assert.strictEqual(hoy.mode, 'stable');
    assert.strictEqual(hoy.encryption, manana.encryption);
    assert.strictEqual(hoy.jwtSigning, manana.jwtSigning);

    const legacyEnv = { BASE_SEED: 'b', JWT_SEED: 'j' };
    const a = keyProvider.deriveFromEnv(legacyEnv, { today: '2026-10-20' });
    const b = keyProvider.deriveFromEnv(legacyEnv, { today: '2026-10-21' });
    assert.strictEqual(a.mode, 'legacy');
    assert.notStrictEqual(a.encryption, b.encryption);
});

test('modo legacy replica exactamente las fórmulas anteriores (compatibilidad con datos existentes)', () => {
    const date = '2026-10-20';
    const k = keyProvider.deriveLegacyKeySet({ baseSeed: 'semilla', jwtSeed: 'jwt', date });
    assert.strictEqual(k.encryption, crypto.scryptSync(`semilla_enc_${date}`, 'dynamic_salt', 32).toString('hex'));
    assert.strictEqual(k.jwt, crypto.scryptSync(`semilla_jwt_${date}`, 'dynamic_salt', 32).toString('hex'));
    assert.strictEqual(k.jwtSigning, crypto.scryptSync(`semilla_jwt_${date}`, 'jwt_salt', 64).toString('hex'));
});

test('cambiar cualquiera de las variables de claves cambia la clave de cifrado', () => {
    const base = { baseSeed: 'b', encryptionSeed: 'e', jwtSeed: 'j', epoch: 'EP1' };
    const ref = keyProvider.deriveStableKeySet(base).encryption;
    for (const change of [{ baseSeed: 'x' }, { encryptionSeed: 'x' }, { epoch: 'EP2' }]) {
        assert.notStrictEqual(keyProvider.deriveStableKeySet({ ...base, ...change }).encryption, ref);
    }
    assert.throws(() => keyProvider.deriveStableKeySet({ ...base, encryptionSeed: '' }), /ENCRYPTION_SEED/);
    assert.throws(() => keyProvider.deriveStableKeySet({ ...base, epoch: 'a b' }), /KEY_EPOCH/);
});

test('la huella no revela la clave y distingue claves', () => {
    const a = keyProvider.deriveStableKeySet({ baseSeed: 'b', encryptionSeed: 'e', jwtSeed: 'j', epoch: 'EP1' });
    const b = keyProvider.deriveStableKeySet({ baseSeed: 'b', encryptionSeed: 'e', jwtSeed: 'j', epoch: 'EP2' });
    assert.notStrictEqual(a.fingerprint, b.fingerprint);
    assert.ok(!a.encryption.includes(a.fingerprint));
});

test('withKey usa la clave indicada y restaura clave y consola aunque falle', () => {
    const enc = require('./src/crypto/tripleEncryptor');
    const keyA = crypto.randomBytes(32).toString('hex');
    const keyB = crypto.randomBytes(32).toString('hex');

    const cipher = enc.withKey(keyA, () => enc.encrypt('hola'), { quiet: true });
    assert.strictEqual(enc.withKey(keyA, () => enc.decrypt(cipher), { quiet: true }), 'hola');
    assert.throws(() => enc.withKey(keyB, () => enc.decrypt(cipher), { quiet: true }));

    const logBefore = console.log;
    const errorBefore = console.error;
    assert.throws(() => enc.withKey(keyB, () => { throw new Error('x'); }, { quiet: true }));
    assert.strictEqual(console.log, logBefore);
    assert.strictEqual(console.error, errorBefore);

    // Tras withKey, el cifrador vuelve a usar la clave del entorno
    const envCipher = enc.encrypt('entorno');
    assert.strictEqual(enc.decrypt(envCipher), 'entorno');
    assert.throws(() => enc.withKey(keyA, () => enc.decrypt(envCipher), { quiet: true }));
});

test('credential-builder no vuelca valores de variables a los logs', () => {
    const credentialBuilder = require('./src/config/credential-builder');
    const secret = 'valor-super-secreto-123';
    process.env.PRIMARY_EMAIL_PASSWORD = secret;

    const lines = [];
    const original = console.log;
    console.log = (...args) => lines.push(args.join(' '));
    try {
        credentialBuilder.getEnvVariable('PRIMARY_EMAIL_PASSWORD');
        credentialBuilder.getEnvVariable('DB_FRAGMENT_1');
    } finally {
        console.log = original;
        delete process.env.PRIMARY_EMAIL_PASSWORD;
    }
    assert.ok(lines.length === 2);
    assert.ok(!lines.join('\n').includes(secret));
    assert.ok(!lines.join('\n').includes(process.env.DB_FRAGMENT_1));
});

test('registro de columnas cifradas: cubre todas las columnas de texto "encrypted" de schema.sql', () => {
    const schema = fs.readFileSync(path.join(__dirname, 'database/schema.sql'), 'utf8');
    const found = [];

    for (const block of schema.matchAll(/CREATE TABLE `(\w+)` \(([\s\S]*?)\) ENGINE/g)) {
        const [, table, body] = block;
        for (const col of body.matchAll(/^\s*`(\w+)` (\w+)/gm)) {
            const [, name, type] = col;
            if (/encrypted/.test(name)) found.push({ table, name, type: type.toLowerCase() });
        }
    }

    assert.ok(found.length >= 10, 'el parser del esquema debería encontrar las columnas');

    for (const { table, name, type } of found) {
        const key = `${table}.${name}`;
        if (IGNORED[key]) continue;
        assert.ok(['text', 'longtext', 'mediumtext'].includes(type), `${key} es ${type}: añádelo a IGNORED con el motivo`);
        assert.ok(ENCRYPTED_COLUMNS[table]?.columns.includes(name),
            `${key} guarda datos cifrados pero NO está en src/crypto/encrypted-columns.js: la rotación lo dejaría ilegible`);
    }

    // Y al revés: nada registrado que no exista en el esquema
    for (const [table, spec] of Object.entries(ENCRYPTED_COLUMNS)) {
        for (const col of spec.columns) assert.ok(found.some(f => f.table === table && f.name === col), `${table}.${col} no existe en schema.sql`);
    }
});

test('archive: ida y vuelta, compresión real, clave incorrecta y manipulación', () => {
    const snapshot = { rows: Array.from({ length: 2000 }, (_, i) => ({ id: i, texto: `contenido repetitivo número ${i % 50}`, email: `usuario${i}@example.com` })) };
    const raw = JSON.stringify(snapshot).length;
    const key = crypto.randomBytes(32).toString('hex');

    const buf = archive.createArchive(snapshot, { encryptionKeyHex: key, epoch: 'EP1', tables: { t: 2000 } });
    assert.ok(buf.length < raw * 0.2, `debería comprimir al menos 5x: ${buf.length} vs ${raw}`);

    const header = archive.readHeader(buf);
    assert.strictEqual(header.epoch, 'EP1');
    assert.ok(['brotli', 'gzip'].includes(header.compression));
    assert.deepStrictEqual(archive.openArchive(buf, () => key).snapshot, snapshot);

    assert.throws(() => archive.openArchive(buf, () => crypto.randomBytes(32).toString('hex')), /clave incorrecta/);
    assert.throws(() => archive.openArchive(buf, () => null), /No hay clave/);

    // Cambiar un byte de la cabecera (datos autenticados) o del contenido debe fallar
    const headerEnd = 9 + buf.readUInt32BE(5);
    for (const offset of [12, headerEnd + 3]) {
        const tampered = Buffer.from(buf);
        tampered[offset] ^= 0xff;
        assert.throws(() => archive.openArchive(tampered, () => key));
    }
    assert.throws(() => archive.readHeader(Buffer.from('no es un backup')), /firma/);
});

test('archive: compressBest elige el algoritmo que menos ocupa', () => {
    const data = Buffer.from(JSON.stringify(Array.from({ length: 500 }, (_, i) => ({ a: i, b: 'x'.repeat(30) }))));
    const best = archive.compressBest(data);
    const zlib = require('zlib');
    assert.ok(best.data.length <= zlib.gzipSync(data, { level: 9 }).length);
    assert.deepStrictEqual(archive.decompress(best.algo, best.data), data);
});

test('archive: rewrap cambia la clave exterior sin tocar el contenido', () => {
    const keyA = crypto.randomBytes(32).toString('hex');
    const keyB = crypto.randomBytes(32).toString('hex');
    const buf = archive.createArchive({ x: [1, 2, 3] }, { encryptionKeyHex: keyA, epoch: 'A', tables: { t: 3 } });
    const re = archive.rewrapArchive(buf, { fromKeyHex: keyA, toKeyHex: keyB, toEpoch: 'B' });

    assert.strictEqual(archive.readHeader(re).epoch, 'B');
    assert.deepStrictEqual(archive.openArchive(re, () => keyB).snapshot, { x: [1, 2, 3] });
    assert.throws(() => archive.openArchive(re, () => keyA), /clave incorrecta/);
    assert.ok(Math.abs(re.length - buf.length) < 200);
});

test('keyring: abre con la clave de envoltura y rechaza otra', () => {
    const wrap = crypto.randomBytes(32).toString('hex');
    const old = crypto.randomBytes(32).toString('hex');
    const ring = buildKeyring(new Map([['E-old', old]]), { wrapKeyHex: wrap, wrapEpoch: 'E-new' });

    assert.ok(!JSON.stringify(ring).includes(old));
    assert.strictEqual(openKeyring(ring, wrap).get('E-old'), old);
    assert.throws(() => openKeyring(ring, crypto.randomBytes(32).toString('hex')), /keyring/);
});

test('applyEnvUpdates conserva comentarios y orden, reemplaza y añade', () => {
    const before = '# comentario\nPORT=3000\nKEY_EPOCH=old\nOTRA=1\n';
    const after = applyEnvUpdates(before, { KEY_EPOCH: 'nuevo', ENCRYPTION_SEED: 'abc' });
    assert.match(after, /^# comentario\nPORT=3000\nKEY_EPOCH=nuevo\nOTRA=1\n/);
    assert.match(after, /ENCRYPTION_SEED=abc\n$/);
    assert.ok(!after.includes('KEY_EPOCH=old'));
});

test('lock de mantenimiento: exclusivo, y falla cerrado', () => {
    const { Maintenance } = require('./src/maintenance/maintenance');
    const dir = tmpDir();
    const m = new Maintenance({ lockFile: path.join(dir, 'x/maintenance.lock') });

    m.acquire({ operation: 'test', reason: 'a' });
    assert.ok(m.isLocked());
    assert.throws(() => m.acquire({ operation: 'otro', reason: 'b' }), (e) => e.code === 'MAINTENANCE_LOCKED' && /recover/.test(e.message));
    assert.strictEqual(m.read().operation, 'test');

    m.release();
    m.release(); // idempotente
    assert.ok(!m.isLocked());
});

// ======================================================================= integración (BD real)

let db;
let encryptor;
let secureEnv;
let RotationService;
let getPaths;
let MaintenanceGuard;
let Maintenance;
let dbAvailable = false;

const mysql = require('mysql2/promise');

test.before(async () => {
    try {
        const root = await mysql.createConnection({
            host: dbUrl.hostname, port: Number(dbUrl.port) || 3306, user: dbUrl.username, password: dbUrl.password,
            multipleStatements: true, connectTimeout: 3000
        });
        await root.query(`DROP DATABASE IF EXISTS \`${DB_NAME}\`; CREATE DATABASE \`${DB_NAME}\` CHARACTER SET utf8mb4; USE \`${DB_NAME}\`;`);
        await root.query(fs.readFileSync(path.join(__dirname, 'database/schema.sql'), 'utf8'));
        await root.end();
        dbAvailable = true;
    } catch (error) {
        console.log(`ℹ️ Pruebas de integración omitidas: no hay base de datos (${error.code || error.message})`);
        return;
    }

    db = require('./src/config/database');
    encryptor = require('./src/crypto/tripleEncryptor');
    secureEnv = require('./src/config/secure-env');
    ({ RotationService } = require('./src/maintenance/rotation.service'));
    ({ getPaths } = require('./src/maintenance/paths'));
    ({ MaintenanceGuard } = require('./src/maintenance/guard'));
    ({ Maintenance } = require('./src/maintenance/maintenance'));
});

test.after(async () => {
    if (db?.pool) await db.pool.end();
});

const itDb = (name, fn) => test(name, async (t) => {
    if (!dbAvailable) return t.skip('sin base de datos');
    await fn(t);
});

const TABLES = ['known_devices', 'user_sessions', 'user_notes', 'users', 'security_logs', 'server_integrity', 'encryption_keys', 'blocked_ips', 'security_metrics', 'crypto_meta'];

const currentKey = () => secureEnv.getSecret('encryption');
const encCurrent = (text) => encryptor.withKey(currentKey(), () => encryptor.encrypt(text), { quiet: true });
const decWith = (key, text) => encryptor.withKey(key, () => encryptor.decrypt(text), { quiet: true });

function setEnv(vars) {
    for (const [k, v] of Object.entries(vars)) {
        if (v === null) delete process.env[k]; else process.env[k] = v;
    }
    secureEnv.loadRotatingSecrets();
}

function writeEnvFile(file, vars) {
    fs.writeFileSync(file, Object.entries(vars).map(([k, v]) => `${k}=${v}`).join('\n') + '\n', { mode: 0o600 });
}

// Datos de referencia (texto plano) para comprobar que nada se pierde ni cambia
const PLAIN = {
    users: [
        { username: 'ana', email: 'ana@example.com', risk: 'low', meta: { a: 1 } },
        { username: 'luis', email: 'luis@example.com', risk: 'medium', meta: { a: 2 } },
        { username: 'maría ñandú', email: 'maria@example.com', risk: 'high', meta: { texto: 'acentos áéíóú 日本語' } }
    ],
    note: { title: 'Título secreto', content: 'Contenido '.repeat(300) },
    log: '{"evento":"x","ip":"10.0.0.1"}'
};

async function freshWorld({ legacyDates = null } = {}) {
    for (const table of TABLES) {
        await db.query('SET FOREIGN_KEY_CHECKS = 0');
        await db.query(`TRUNCATE TABLE \`${table}\``);
        await db.query('SET FOREIGN_KEY_CHECKS = 1');
    }

    const dir = tmpDir();
    const paths = getPaths({ ROTATION_DATA_DIR: path.join(dir, 'data'), BACKUP_DIR: path.join(dir, 'backups'), ENV_FILE: path.join(dir, '.env') });

    process.env.ENV_FILE = paths.envFile; // secureEnv.reload() y el guardián leen este archivo

    const stable = { ENCRYPTION_SEED: 'enc-seed-inicial', JWT_SEED: 'jwt-seed-inicial', KEY_EPOCH: 'T0-inicial' };
    setEnv(legacyDates ? { ENCRYPTION_SEED: null, KEY_EPOCH: null } : stable);

    const fileVars = { PORT: 3000, BASE_SEED: process.env.BASE_SEED, JWT_SEED: process.env.JWT_SEED, ...(legacyDates ? {} : stable) };
    writeEnvFile(paths.envFile, fileVars);

    // Cifra cada celda con la clave de su fecha (legacy) o con la actual (estable)
    const enc = (text, index) => {
        if (!legacyDates) return encCurrent(text);
        const key = keyProvider.deriveLegacyKeySet({ baseSeed: process.env.BASE_SEED, jwtSeed: process.env.JWT_SEED, date: legacyDates[index % legacyDates.length] }).encryption;
        return encryptor.withKey(key, () => encryptor.encrypt(text), { quiet: true });
    };
    const stamp = (index) => (legacyDates ? legacyDates[index % legacyDates.length] + ' 12:00:00' : null);

    const ids = [];
    for (const [i, u] of PLAIN.users.entries()) {
        const [r] = await db.query(
            `INSERT INTO users (password_hash, username_hash, username_encrypted, email_encrypted, risk_level_encrypted, encrypted_metadata, metadata_encrypted, personal_data_encrypted)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
            [`bcrypt-${i}`, crypto.createHash('sha256').update(u.username + process.env.BASE_SEED).digest('hex'),
                enc(u.username, i), enc(u.email, i), enc(u.risk, i), enc(JSON.stringify(u.meta), i), enc('{"m":1}', i), null]
        );
        ids.push(r.insertId);
        if (stamp(i)) await db.query('UPDATE users SET created_at = ?, updated_at = ? WHERE id = ?', [stamp(i), stamp(i), r.insertId]);
    }
    const [nr] = await db.query('INSERT INTO user_notes (user_id, title_encrypted, content_encrypted) VALUES (?, ?, ?)', [ids[0], enc(PLAIN.note.title, 0), enc(PLAIN.note.content, 0)]);
    if (stamp(0)) await db.query('UPDATE user_notes SET created_at = ?, updated_at = ? WHERE id = ?', [stamp(0), stamp(0), nr.insertId]);
    await db.query('INSERT INTO security_logs (event_type, encrypted_details, encrypted_timestamp) VALUES (?, ?, ?)', ['TEST', enc(PLAIN.log, 1), enc('2026-10-20T10:00:00.000Z', 1)]);
    await db.query('INSERT INTO user_sessions (user_id, jwt_token_hash, expires_at) VALUES (?, ?, DATE_ADD(NOW(), INTERVAL 5 DAY))', [ids[0], 'tokenhash']);

    const service = new RotationService({ db, encryptor, paths, logger: quietLog, sleepFn: async () => {} });
    return { dir, paths, service, ids, env: () => ({ ...process.env }) };
}

// Descifra TODO lo registrado con una clave; devuelve null en las celdas que no se pueden descifrar
async function readAll(key) {
    const out = {};
    for (const [table, spec] of Object.entries(ENCRYPTED_COLUMNS)) {
        const [rows] = await db.query(`SELECT \`${spec.primaryKey}\`, ${spec.columns.map(c => `\`${c}\``).join(', ')} FROM \`${table}\` ORDER BY \`${spec.primaryKey}\``);
        out[table] = rows.map(r => Object.fromEntries(spec.columns.map(c => {
            if (r[c] === null) return [c, null];
            try { return [c, decWith(key, r[c])]; } catch { return [c, null]; }
        })));
    }
    return out;
}

const checksum = async () => {
    const parts = [];
    for (const table of ['users', 'user_notes', 'security_logs']) {
        const [rows] = await db.query(`SELECT * FROM \`${table}\` ORDER BY id`);
        parts.push(JSON.stringify(rows));
    }
    return crypto.createHash('sha256').update(parts.join('|')).digest('hex');
};

function assertPlainData(all) {
    assert.deepStrictEqual(all.users.map(u => u.username_encrypted), PLAIN.users.map(u => u.username));
    assert.deepStrictEqual(all.users.map(u => u.email_encrypted), PLAIN.users.map(u => u.email));
    assert.deepStrictEqual(all.users.map(u => JSON.parse(u.encrypted_metadata)), PLAIN.users.map(u => u.meta));
    assert.strictEqual(all.user_notes[0].title_encrypted, PLAIN.note.title);
    assert.strictEqual(all.user_notes[0].content_encrypted, PLAIN.note.content);
    assert.strictEqual(all.security_logs[0].encrypted_details, PLAIN.log);
    assert.strictEqual(all.security_logs[0].encrypted_timestamp, '2026-10-20T10:00:00.000Z');
}

const newKeyFromFile = (envFile, base = process.env.BASE_SEED) => {
    const vars = require('dotenv').parse(fs.readFileSync(envFile));
    return keyProvider.deriveStableKeySet({ baseSeed: base, encryptionSeed: vars.ENCRYPTION_SEED, jwtSeed: vars.JWT_SEED, epoch: vars.KEY_EPOCH });
};


// ----------------------------------------------------------------------- esquema y auditoría

itDb('auditoría: audit.service guarda los eventos en una BD en modo estricto (regresión de encrypted_timestamp)', async () => {
    await freshWorld();
    const audit = require('./src/services/audit.service');
    const [[{ mode }]] = await db.query('SELECT @@sql_mode AS mode');
    assert.match(mode, /STRICT/, 'esta prueba solo tiene sentido en modo estricto');

    await audit.log('EVENTO_DE_PRUEBA', { dato: 'x' }, { severity: 'medium', riskScore: 7 });

    const [rows] = await db.query("SELECT encrypted_details, encrypted_timestamp, severity FROM security_logs WHERE event_type = 'EVENTO_DE_PRUEBA'");
    assert.strictEqual(rows.length, 1, 'el evento de auditoría se perdió');
    assert.strictEqual(JSON.parse(decWith(currentKey(), rows[0].encrypted_details)).dato, 'x');
    assert.match(decWith(currentKey(), rows[0].encrypted_timestamp), /^\d{4}-\d{2}-\d{2}T/);
});

itDb('la rotación se niega si encrypted_timestamp sigue siendo DATETIME (esquema antiguo) y no cambia nada', async () => {
    const w = await freshWorld();
    await db.query('DELETE FROM security_logs');
    await db.query('ALTER TABLE security_logs MODIFY encrypted_timestamp datetime DEFAULT NULL');
    try {
        const before = await checksum();
        await assert.rejects(() => w.service.run({ env: w.env(), drainSeconds: 0 }), /encrypted_timestamp es DATETIME.*003_security_logs/);
        await assert.rejects(() => w.service.analyze({ env: w.env() }), /DATETIME/);
        assert.strictEqual(await checksum(), before);
        assert.ok(!w.service.maintenance.isLocked());
    } finally {
        await db.query('ALTER TABLE security_logs MODIFY encrypted_timestamp longtext DEFAULT NULL');
    }
});

itDb('migración 003: convierte la columna y deja a NULL los ceros de DATETIME, conservando el texto cifrado', async () => {
    const w = await freshWorld();
    await db.query('DELETE FROM security_logs');
    const conn = await mysql.createConnection({
        host: dbUrl.hostname, port: Number(dbUrl.port) || 3306, user: dbUrl.username, password: dbUrl.password, database: DB_NAME, multipleStatements: true
    });
    try {
        // Estado antiguo: DATETIME con un cero (lo que dejaba un servidor en modo no estricto)
        await conn.query("SET SESSION sql_mode = ''; ALTER TABLE security_logs MODIFY encrypted_timestamp datetime DEFAULT NULL;");
        await conn.query("INSERT INTO security_logs (event_type, encrypted_timestamp) VALUES ('VIEJO', 'texto-invalido')");

        await conn.query(fs.readFileSync(path.join(__dirname, 'database/migrations/003_security_logs_encrypted_timestamp.sql'), 'utf8'));

        const [[col]] = await conn.query("SELECT DATA_TYPE AS t FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'security_logs' AND COLUMN_NAME = 'encrypted_timestamp'");
        assert.strictEqual(col.t, 'longtext');
        const [[viejo]] = await conn.query("SELECT encrypted_timestamp AS v FROM security_logs WHERE event_type = 'VIEJO'");
        assert.strictEqual(viejo.v, null);

        // Y ya admite texto cifrado
        await conn.query("INSERT INTO security_logs (event_type, encrypted_timestamp) VALUES ('NUEVO', ?)", [encCurrent('2026-10-20T00:00:00Z')]);
        const [[nuevo]] = await conn.query("SELECT encrypted_timestamp AS v FROM security_logs WHERE event_type = 'NUEVO'");
        assert.strictEqual(decWith(currentKey(), nuevo.v), '2026-10-20T00:00:00Z');
    } finally {
        await conn.end();
    }
    void w;
});

// ----------------------------------------------------------------------- rotación: camino feliz

itDb('rotación: re-cifra todo con la clave nueva, sin perder ni alterar datos', async () => {
    const w = await freshWorld();
    const oldKey = currentKey();
    const [usersBefore] = await db.query('SELECT username_hash, password_hash FROM users ORDER BY id');
    assertPlainData(await readAll(oldKey));

    const result = await w.service.run({ env: w.env(), drainSeconds: 0 });

    const newSet = newKeyFromFile(w.paths.envFile);
    assert.notStrictEqual(newSet.encryption, oldKey);
    assert.strictEqual(result.cellsReencrypted, 3 * 5 + 2 + 2); // 5 columnas no nulas por usuario + 2 de la nota + 2 del log

    // Con la clave nueva se lee todo, igual que antes; con la antigua, nada
    assertPlainData(await readAll(newSet.encryption));
    const withOld = await readAll(oldKey);
    assert.ok(withOld.users.every(u => u.username_encrypted === null && u.email_encrypted === null));
    assert.strictEqual(withOld.user_notes[0].title_encrypted, null);

    // Lo que NO es cifrado queda intacto (hash de login, contraseñas)
    const [usersAfter] = await db.query('SELECT username_hash, password_hash FROM users ORDER BY id');
    assert.deepStrictEqual(usersAfter, usersBefore);

    // Marcador, sesiones, bloqueo y journal
    const [[meta]] = await db.query('SELECT key_fingerprint, key_epoch FROM crypto_meta WHERE id = 1');
    assert.strictEqual(meta.key_fingerprint, newSet.fingerprint);
    assert.strictEqual(meta.key_epoch, result.newEpoch);
    const [[{ vivas }]] = await db.query('SELECT COUNT(*) AS vivas FROM user_sessions WHERE expires_at > NOW()');
    assert.strictEqual(vivas, 0, 'ninguna sesión debe sobrevivir');
    assert.ok(!w.service.maintenance.isLocked(), 'el servidor debe quedar reabierto');
    assert.strictEqual(w.service.readJournal().phase, 'DONE');

    // .env actualizado conservando lo demás; sin archivos temporales
    const envText = fs.readFileSync(w.paths.envFile, 'utf8');
    assert.match(envText, /PORT=3000/);
    assert.ok(!envText.includes('KEY_EPOCH=T0-inicial'));
    assert.ok(!fs.existsSync(`${w.paths.envFile}.pending`));
    assert.strictEqual(fs.statSync(w.paths.envFile).mode & 0o777, 0o600);
});

itDb('rotación: el texto plano nunca llega a disco ni a los logs', async () => {
    const w = await freshWorld();
    const logs = [];
    const service = new RotationService({ db, encryptor, paths: w.paths, logger: { log: (...a) => logs.push(a.join(' ')) }, sleepFn: async () => {} });

    const captured = [];
    const originals = {};
    for (const m of ['log', 'info', 'warn', 'error']) { originals[m] = console[m]; console[m] = (...a) => captured.push(a.join(' ')); }
    try { await service.run({ env: w.env(), drainSeconds: 0 }); } finally { Object.assign(console, originals); }

    const secrets = ['ana@example.com', 'luis@example.com', 'maría ñandú', 'Título secreto', PLAIN.log, '2026-10-20T10:00:00.000Z'];
    const everything = [...logs, ...captured].join('\n');
    for (const s of secrets) assert.ok(!everything.includes(s), `"${s}" apareció en los logs`);

    // Ningún archivo creado por la rotación contiene texto plano (los backups van comprimidos Y cifrados)
    const files = [];
    const walk = (d) => fs.readdirSync(d, { withFileTypes: true }).forEach(e => (e.isDirectory() ? walk(path.join(d, e.name)) : files.push(path.join(d, e.name))));
    walk(w.dir);
    for (const f of files.filter(f => !f.endsWith('.env'))) {
        const content = fs.readFileSync(f).toString('latin1');
        for (const s of secrets) assert.ok(!content.includes(Buffer.from(s).toString('latin1')), `"${s}" aparece en ${path.basename(f)}`);
    }
});

itDb('backup: contiene toda la información, comprimido y cifrado con la clave anterior', async () => {
    const w = await freshWorld();
    const oldSet = keyProvider.deriveFromEnv(process.env);
    const result = await w.service.run({ env: w.env(), drainSeconds: 0 });

    const files = w.service.listBackupFiles();
    assert.strictEqual(files.length, 1);

    // Se abre con la clave ANTERIOR…
    const { snapshot, header } = archive.openArchive(fs.readFileSync(files[0]), (epoch) => (epoch === oldSet.epoch ? oldSet.encryption : null));
    assert.strictEqual(header.epoch, oldSet.epoch);
    assert.strictEqual(result.backup.encryptedWith, 'clave anterior');

    // …y no con la nueva
    const newSet = newKeyFromFile(w.paths.envFile);
    assert.throws(() => archive.openArchive(fs.readFileSync(files[0]), () => newSet.encryption), /clave incorrecta/);

    // Toda la información, con las columnas cifradas descifradas dentro del archivo
    assert.strictEqual(snapshot.tables.users.rows.length, 3);
    const col = snapshot.tables.users.columns;
    assert.deepStrictEqual(snapshot.tables.users.rows.map(r => r[col.indexOf('username_encrypted')]), PLAIN.users.map(u => u.username));
    assert.strictEqual(snapshot.tables.user_notes.rows[0][snapshot.tables.user_notes.columns.indexOf('content_encrypted')], PLAIN.note.content);
    assert.ok(snapshot.tables.users.createSql.startsWith('CREATE TABLE'));
    assert.ok(Object.keys(snapshot.tables).length >= 9);

    // Compresión real
    assert.ok(header.compressedBytes < header.rawBytes / 3);
});

// ----------------------------------------------------------------------- cadena mensual

itDb('cadena mensual: el backup de cada mes se re-cifra con la clave nueva al mes siguiente', async () => {
    const w = await freshWorld();
    const epochs = [keyProvider.deriveFromEnv(process.env).epoch];

    for (let month = 1; month <= 4; month++) {
        await new Promise(r => setTimeout(r, 1100)); // las épocas llevan marca de segundos
        const result = await w.service.run({ env: w.env(), drainSeconds: 0 });
        epochs.push(result.newEpoch);
        setEnv(require('dotenv').parse(fs.readFileSync(w.paths.envFile))); // el "servidor" recarga el .env

        const backups = w.service.listBackups().sort((a, b) => a.createdAt.localeCompare(b.createdAt));
        assert.strictEqual(backups.length, month);

        // El de ESTE mes sigue con la clave anterior; todos los anteriores ya con la clave nueva
        assert.strictEqual(backups.at(-1).epoch, epochs[month - 1]);
        for (const older of backups.slice(0, -1)) assert.strictEqual(older.epoch, epochs[month], `mes ${month}: un backup antiguo no se re-cifró`);

        // El keyring solo guarda UNA generación anterior, envuelta con la clave actual
        const keyring = JSON.parse(fs.readFileSync(w.paths.keyringFile, 'utf8'));
        assert.deepStrictEqual(keyring.entries.map(e => e.epoch), [epochs[month - 1]]);
        assert.strictEqual(keyring.wrappedUnder, epochs[month]);

        // Con SOLO la clave actual (+ keyring) se abren todos los backups y tienen los datos
        const currentSet = keyProvider.deriveFromEnv(process.env);
        for (const b of backups) {
            const { snapshot } = w.service.openBackup(b.file, currentSet);
            assert.strictEqual(snapshot.tables.users.rows.length, 3);
        }
        assertPlainData(await readAll(currentKey()));
    }
});

itDb('--keep-backups conserva solo los más recientes', async () => {
    const w = await freshWorld();
    for (let i = 0; i < 3; i++) {
        await new Promise(r => setTimeout(r, 1100));
        await w.service.run({ env: w.env(), drainSeconds: 0, keepBackups: 2 });
        setEnv(require('dotenv').parse(fs.readFileSync(w.paths.envFile)));
    }
    assert.strictEqual(w.service.listBackupFiles().length, 2);
});

itDb('--backup-key new: el backup nuevo se cifra con la clave nueva (clave anterior comprometida)', async () => {
    const w = await freshWorld();
    const result = await w.service.run({ env: w.env(), drainSeconds: 0, backupKey: 'new' });
    assert.strictEqual(result.backup.epoch, result.newEpoch);
    assert.ok(!fs.existsSync(w.paths.keyringFile), 'sin backups con clave antigua no hace falta keyring');
});

itDb('rotación dentro del servidor (la del cron mensual): recarga las claves en memoria y se reabre sola', async () => {
    const w = await freshWorld();
    // La fachada usa el servicio compartido: se configura por entorno antes de su primer uso
    const saved = { d: process.env.ROTATION_DATA_DIR, b: process.env.BACKUP_DIR };
    process.env.ROTATION_DATA_DIR = w.paths.dataDir;
    process.env.BACKUP_DIR = w.paths.backupDir;
    try {
        const { guard } = require('./src/maintenance');
        await guard.tick();
        assert.ok(guard.isOpen());
        const before = secureEnv.fingerprint;

        const keyRotator = require('./src/crypto/keyRotator');
        const result = await keyRotator.rotateKeys({ drainSeconds: 0 });

        assert.ok(result.cellsReencrypted > 0);
        assert.notStrictEqual(secureEnv.fingerprint, before, 'las claves en memoria deben ser las nuevas');
        assertPlainData(await readAll(currentKey()));       // currentKey() = la clave que usa ESTE proceso ahora
        assert.ok(guard.isOpen(), 'el guardián debe reabrir');
        assert.ok(!fs.existsSync(w.paths.lockFile));

        // Y lo nuevo que escriba este proceso se cifra con la clave nueva
        await db.query('INSERT INTO security_logs (event_type, encrypted_details) VALUES (?, ?)', ['POST', encCurrent('posterior')]);
        const [[row]] = await db.query("SELECT encrypted_details AS d FROM security_logs WHERE event_type = 'POST'");
        assert.strictEqual(decWith(newKeyFromFile(w.paths.envFile).encryption, row.d), 'posterior');
    } finally {
        process.env.ROTATION_DATA_DIR = saved.d ?? '';
        process.env.BACKUP_DIR = saved.b ?? '';
        if (!saved.d) delete process.env.ROTATION_DATA_DIR;
        if (!saved.b) delete process.env.BACKUP_DIR;
    }
});

// ----------------------------------------------------------------------- modo mantenimiento

itDb('mantenimiento: durante la rotación todo responde 503; después se reabre', async () => {
    const w = await freshWorld();
    const guard = new MaintenanceGuard({ maintenance: w.service.maintenance, db, secureEnv, intervalMs: 1e9 });
    await guard.tick();
    assert.ok(guard.isOpen());

    const respond = () => {
        const res = { headers: {}, setHeader(k, v) { this.headers[k] = v; }, status(c) { this.code = c; return this; }, json(b) { this.body = b; } };
        let passed = false;
        guard.middleware()({}, res, () => { passed = true; });
        return { res, passed };
    };

    let duringLock;
    await w.service.run({
        env: w.env(), drainSeconds: 0,
        hooks: {
            afterLock: async () => { await guard.tick(); duringLock = respond(); },
            beforeRelease: async () => { /* aún bloqueado aquí */ assert.ok(w.service.maintenance.isLocked()); }
        }
    });

    assert.strictEqual(duringLock.passed, false);
    assert.strictEqual(duringLock.res.code, 503);
    assert.strictEqual(duringLock.res.body.code, 'MAINTENANCE');
    assert.strictEqual(duringLock.res.headers['Retry-After'], '300');

    await guard.tick();
    assert.ok(guard.isOpen());
    assert.strictEqual(respond().passed, true);
});

itDb('mantenimiento: otra rotación no puede empezar y NO borra un lock ajeno', async () => {
    const w = await freshWorld();
    w.service.maintenance.acquire({ operation: 'otra-cosa', reason: 'x' });

    await assert.rejects(() => w.service.run({ env: w.env(), drainSeconds: 0 }), (e) => e.code === 'MAINTENANCE_LOCKED');
    assert.ok(w.service.maintenance.isLocked(), 'el lock ajeno debe seguir ahí');
    assert.strictEqual(w.service.maintenance.read().operation, 'otra-cosa');
    w.service.maintenance.release();
});

itDb('guardián: tras una rotación hecha por OTRO proceso recarga las claves del .env y se reabre', async () => {
    const w = await freshWorld();
    const guard = new MaintenanceGuard({ maintenance: w.service.maintenance, db, secureEnv, intervalMs: 1e9 });
    await guard.tick();
    const fingerprintBefore = secureEnv.fingerprint;

    // "Otro proceso" rota: aquí la memoria de secureEnv sigue con la clave antigua
    process.env.ENV_FILE = w.paths.envFile;
    await w.service.run({ env: w.env(), drainSeconds: 0 });
    assert.strictEqual(secureEnv.fingerprint, fingerprintBefore, 'este proceso aún tiene la clave antigua');

    await guard.tick();
    assert.ok(guard.isOpen());
    assert.notStrictEqual(secureEnv.fingerprint, fingerprintBefore, 'el guardián debe haber recargado las claves');
    assertPlainData(await readAll(currentKey()));
});

itDb('guardián: si las claves del entorno no coinciden con la BD, se niega a atender (falla cerrado)', async () => {
    const w = await freshWorld();
    process.env.ENV_FILE = w.paths.envFile;
    const staleEnv = fs.readFileSync(w.paths.envFile, 'utf8'); // .env con las claves ANTIGUAS

    await w.service.run({ env: w.env(), drainSeconds: 0 });
    fs.writeFileSync(w.paths.envFile, staleEnv); // el hosting sigue sirviendo las variables viejas
    setEnv({ ENCRYPTION_SEED: 'enc-seed-inicial', JWT_SEED: 'jwt-seed-inicial', KEY_EPOCH: 'T0-inicial' });

    const guard = new MaintenanceGuard({ maintenance: w.service.maintenance, db, secureEnv, intervalMs: 1e9 });
    await guard.tick();

    assert.strictEqual(guard.isOpen(), false);
    assert.strictEqual(guard.state.outOfSync, true);

    let res;
    guard.middleware()({}, res = { setHeader() {}, status(c) { this.code = c; return this; }, json(b) { this.body = b; } }, () => assert.fail('no debe pasar'));
    assert.strictEqual(res.code, 503);
    assert.strictEqual(res.body.code, 'KEYS_OUT_OF_SYNC');
});

itDb('guardián: otra MÁQUINA (sin archivo de lock local) también se cierra mientras la BD tiene el lock de rotación', async () => {
    const w = await freshWorld();
    const guard = new MaintenanceGuard({ maintenance: w.service.maintenance, db, secureEnv, intervalMs: 1e9 });
    await guard.tick();
    assert.ok(guard.isOpen());

    // "La otra máquina" ejecuta la rotación: toma el lock de la BD pero el archivo de lock está en SU disco
    const holder = await db.getConnection();
    try {
        const [[got]] = await holder.query("SELECT GET_LOCK('secure_server_rotation', 0) AS got");
        assert.strictEqual(got.got, 1);
        assert.ok(!w.service.maintenance.isLocked(), 'aquí no hay archivo de lock');

        await guard.tick();
        assert.strictEqual(guard.state.maintenance, true, 'debe cerrarse por el lock de la BD');
        assert.strictEqual(guard.isOpen(), false);

        await holder.query("SELECT RELEASE_LOCK('secure_server_rotation')");
    } finally {
        holder.release();
    }

    await guard.tick();
    assert.ok(guard.isOpen(), 'al soltar el lock se reabre');
});

itDb('guardián: la primera vez en modo estable registra la huella actual como referencia', async () => {
    const w = await freshWorld();
    const guard = new MaintenanceGuard({ maintenance: w.service.maintenance, db, secureEnv, intervalMs: 1e9 });
    await guard.tick();
    const [[row]] = await db.query('SELECT key_fingerprint FROM crypto_meta WHERE id = 1');
    assert.strictEqual(row.key_fingerprint, secureEnv.fingerprint);
});

// ----------------------------------------------------------------------- fallos y recuperación

itDb('un dato que no se puede descifrar aborta TODO sin cambiar nada y reabre', async () => {
    const w = await freshWorld();
    await db.query("UPDATE users SET email_encrypted = 'basura-no-cifrada' WHERE id = ?", [w.ids[1]]);
    const before = await checksum();
    const envBefore = fs.readFileSync(w.paths.envFile, 'utf8');

    await assert.rejects(() => w.service.run({ env: w.env(), drainSeconds: 0 }), /No se pudo descifrar users\.email_encrypted/);

    assert.strictEqual(await checksum(), before, 'la BD no debe cambiar');
    assert.strictEqual(fs.readFileSync(w.paths.envFile, 'utf8'), envBefore);
    assert.ok(!w.service.maintenance.isLocked(), 'la BD no cambió: se puede reabrir');
    const [[{ n }]] = await db.query('SELECT COUNT(*) AS n FROM crypto_meta');
    assert.strictEqual(n, 0);
    assert.deepStrictEqual(w.service.listBackupFiles(), [], 'no se crea backup de datos corruptos');
});

itDb('un registro ilegible escrito con otra clave aborta y la pista dice qué hacer (regenerable vs. no)', async () => {
    const w = await freshWorld();
    const otraClave = crypto.randomBytes(32).toString('hex');
    const ajeno = encryptor.withKey(otraClave, () => encryptor.encrypt('escrito por un proceso con otro .env'), { quiet: true });

    const [r] = await db.query("INSERT INTO server_integrity (fingerprint_hash, system_data_encrypted) VALUES ('f', ?)", [ajeno]);
    await assert.rejects(() => w.service.run({ env: w.env(), drainSeconds: 0 }),
        new RegExp(`server_integrity\\.system_data_encrypted.*DELETE FROM server_integrity WHERE id = ${r.insertId}`));
    assert.ok(!w.service.maintenance.isLocked());

    // Tras borrarlo (es regenerable) la rotación sigue adelante
    await db.query('DELETE FROM server_integrity WHERE id = ?', [r.insertId]);
    await w.service.run({ env: w.env(), drainSeconds: 0 });

    // En una tabla que NO es regenerable la pista pide restaurar, no borrar
    await db.query("UPDATE users SET email_encrypted = ? WHERE id = ?", [ajeno, w.ids[0]]);
    setEnv(require('dotenv').parse(fs.readFileSync(w.paths.envFile)));
    await assert.rejects(() => w.service.run({ env: w.env(), drainSeconds: 0 }), /users\.email_encrypted.*restaura ese dato desde un backup/);
});

itDb('un fallo durante el re-cifrado hace rollback: BD intacta, temporales borrados, claves antiguas vigentes', async () => {
    const w = await freshWorld();
    const before = await checksum();
    const envBefore = fs.readFileSync(w.paths.envFile, 'utf8');

    // Fallo a mitad: la primera tabla ya se modificó dentro de la transacción
    const original = w.service.reencryptAll.bind(w.service);
    w.service.reencryptAll = async (conn, opts) => {
        await conn.query("UPDATE users SET username_encrypted = 'a-medias' WHERE id = ?", [w.ids[0]]);
        throw new Error('disco lleno a mitad');
    };

    await assert.rejects(() => w.service.run({ env: w.env(), drainSeconds: 0 }), /disco lleno/);
    w.service.reencryptAll = original;

    assert.strictEqual(await checksum(), before, 'el UPDATE parcial debe haberse deshecho');
    assert.strictEqual(fs.readFileSync(w.paths.envFile, 'utf8'), envBefore);
    assert.ok(!fs.existsSync(`${w.paths.envFile}.pending`));
    assert.ok(!fs.existsSync(`${w.paths.keyringFile}.new`));
    assert.ok(!w.service.maintenance.isLocked());
    assert.strictEqual(w.service.readJournal().phase, 'ABORTED');
    assertPlainData(await readAll(currentKey()));

    // Y se puede volver a rotar sin problema
    await w.service.run({ env: w.env(), drainSeconds: 0 });
    assertPlainData(await readAll(newKeyFromFile(w.paths.envFile).encryption));
});

itDb('caída DESPUÉS del commit: sigue cerrado y `recover` termina el trabajo', async () => {
    const w = await freshWorld();
    const oldSet = keyProvider.deriveFromEnv(process.env);
    await w.service.run({ env: w.env(), drainSeconds: 0 }); // una rotación previa para tener backups que re-cifrar
    setEnv(require('dotenv').parse(fs.readFileSync(w.paths.envFile)));
    await new Promise(r => setTimeout(r, 1100));

    const envBefore = fs.readFileSync(w.paths.envFile, 'utf8');
    const finalize = w.service.finalizeFiles.bind(w.service);
    w.service.finalizeFiles = () => { throw new Error('el proceso murió al colocar archivos'); };

    await assert.rejects(() => w.service.run({ env: w.env(), drainSeconds: 0 }), /recover/);

    // Estado intermedio: BD con claves nuevas, .env aún con las antiguas, servidor CERRADO
    assert.ok(w.service.maintenance.isLocked(), 'debe seguir en mantenimiento');
    assert.strictEqual(w.service.readJournal().phase, 'COMMITTED');
    assert.strictEqual(fs.readFileSync(w.paths.envFile, 'utf8'), envBefore);
    assert.ok(fs.existsSync(`${w.paths.envFile}.pending`));

    w.service.finalizeFiles = finalize;
    const outcome = await w.service.recover({ env: w.env() });

    assert.strictEqual(outcome.action, 'finalized');
    assert.ok(!w.service.maintenance.isLocked());
    assert.ok(!fs.existsSync(`${w.paths.envFile}.pending`));
    assert.strictEqual(w.service.readJournal().phase, 'DONE');

    const newSet = newKeyFromFile(w.paths.envFile);
    assertPlainData(await readAll(newSet.encryption));
    setEnv(require('dotenv').parse(fs.readFileSync(w.paths.envFile)));
    for (const b of w.service.listBackups()) assert.ok(w.service.openBackup(b.file, newSet).snapshot.tables.users);
    void oldSet;
});

itDb('COMMIT ambiguo (se pierde la respuesta pero la BD sí confirmó): NO se deshace, se queda cerrado para `recover`', async () => {
    const w = await freshWorld();
    let first = true;
    const flakyDb = {
        getConnection: async () => {
            const conn = await db.getConnection();
            const commit = conn.commit.bind(conn);
            conn.commit = async () => {
                await commit();
                if (first) { first = false; throw new Error('conexión perdida tras el commit'); }
            };
            return conn;
        }
    };
    const service = new RotationService({ db: flakyDb, encryptor, paths: w.paths, logger: quietLog, sleepFn: async () => {} });

    await assert.rejects(() => service.run({ env: w.env(), drainSeconds: 0 }), /ya usa las claves nuevas/);

    assert.ok(service.maintenance.isLocked(), 'debe quedarse cerrado');
    assert.strictEqual(service.readJournal().phase, 'COMMITTED');
    assert.ok(fs.existsSync(`${w.paths.envFile}.pending`), 'el .env pendiente NO debe borrarse');

    await service.recover({ env: w.env() });
    assertPlainData(await readAll(newKeyFromFile(w.paths.envFile).encryption));
});

itDb('recover: una rotación que NO llegó a confirmar se deshace y reabre con las claves antiguas', async () => {
    const w = await freshWorld();
    const tmp = path.join(w.dir, 'temporal.new');
    fs.writeFileSync(tmp, 'x');
    fs.mkdirSync(w.paths.dataDir, { recursive: true });
    w.service.maintenance.acquire({ operation: 'key-rotation', reason: 'simulada' });
    w.service.writeJournal({
        id: 'rot-simulada', phase: 'PREPARED', oldEpoch: 'T0-inicial', newEpoch: 'E-nueva', oldFingerprint: 'a', newFingerprint: 'no-coincide',
        rewraps: [], keyring: { tmp }, env: { tmp: path.join(w.dir, 'nada.pending') }
    });

    const outcome = await w.service.recover({ env: w.env() });

    assert.strictEqual(outcome.action, 'rolled-back');
    assert.ok(!fs.existsSync(tmp));
    assert.ok(!w.service.maintenance.isLocked());
    assert.strictEqual(w.service.readJournal().phase, 'ABORTED');
    assertPlainData(await readAll(currentKey()));
});

// Un pid que seguro NO existe (proceso que ya terminó)
const deadPid = () => {
    const r = spawnSync('node', ['-e', 'process.exit(0)']);
    return r.pid;
};

itDb('recover se niega mientras la rotación sigue VIVA y no toca ni su lock ni sus temporales', async () => {
    const w = await freshWorld();
    const alive = require('child_process').spawn('sleep', ['30']);
    try {
        fs.mkdirSync(w.paths.dataDir, { recursive: true });
        const lockInfo = { operation: 'key-rotation', reason: 'viva', pid: alive.pid, host: os.hostname(), startedAt: new Date().toISOString(), phase: 'PREPARED' };
        fs.writeFileSync(w.paths.lockFile, JSON.stringify(lockInfo));
        const temp = `${w.paths.envFile}.pending`;
        fs.writeFileSync(temp, 'ENCRYPTION_SEED=secreto-de-una-rotacion-viva');
        w.service.writeJournal({ id: 'viva', phase: 'PREPARED', oldEpoch: 'a', newEpoch: 'b', oldFingerprint: 'x', newFingerprint: 'y', rewraps: [], keyring: { tmp: `${w.paths.keyringFile}.new` }, env: { tmp: temp } });

        await assert.rejects(() => w.service.recover({ env: w.env() }), /en curso \(pid \d+\)/);

        assert.ok(fs.existsSync(w.paths.lockFile), 'el lock de la rotación viva no se toca');
        assert.ok(fs.existsSync(temp), 'sus temporales no se tocan');
        assert.strictEqual(w.service.readJournal().phase, 'PREPARED');
    } finally {
        alive.kill();
    }
});

itDb('recover limpia temporales huérfanos (incluido .env.pending con semillas) cuando el proceso murió antes del journal', async () => {
    const w = await freshWorld();
    fs.mkdirSync(w.paths.backupDir, { recursive: true });
    fs.mkdirSync(w.paths.dataDir, { recursive: true });
    const strays = [
        `${w.paths.envFile}.pending`, `${w.paths.keyringFile}.new`,
        path.join(w.paths.backupDir, 'backup-viejo.sbk.new'), path.join(w.paths.dataDir, 'new-env-E123.txt')
    ];
    strays.forEach(f => fs.writeFileSync(f, 'ENCRYPTION_SEED=huerfano'));
    const real = path.join(w.paths.backupDir, 'backup-real.sbk');
    fs.writeFileSync(real, 'un backup legítimo no se toca');

    // Lock de un proceso muerto + journal de una rotación anterior ya terminada
    fs.writeFileSync(w.paths.lockFile, JSON.stringify({ operation: 'key-rotation', pid: deadPid(), host: os.hostname(), startedAt: new Date().toISOString(), phase: 'LOCKED' }));
    w.service.writeJournal({ id: 'anterior', phase: 'DONE', rewraps: [], keyring: {}, env: {} });

    const outcome = await w.service.recover({ env: w.env() });

    assert.strictEqual(outcome.action, 'already-finished');
    assert.strictEqual(outcome.removedTemps.length, 4);
    strays.forEach(f => assert.ok(!fs.existsSync(f), `${path.basename(f)} debería haberse borrado`));
    assert.ok(fs.existsSync(real), 'los backups reales jamás se borran');
    assert.ok(!fs.existsSync(w.paths.lockFile));
});

itDb('recover tras --no-write-env NO reabre: sigue esperando a que se apliquen las variables nuevas', async () => {
    const w = await freshWorld();
    const result = await w.service.run({ env: w.env(), drainSeconds: 0, writeEnv: false });
    assert.ok(w.service.maintenance.isLocked());

    const outcome = await w.service.recover({ env: w.env() });

    assert.strictEqual(outcome.action, 'awaiting-env');
    assert.ok(w.service.maintenance.isLocked(), 'el servidor debe seguir cerrado');
    assert.ok(fs.existsSync(result.manualEnvFile), 'el archivo con las variables nuevas debe conservarse');
});

itDb('--no-write-env: no toca el .env, se queda cerrado y `finish` solo reabre cuando el entorno ya tiene las claves nuevas', async () => {
    const w = await freshWorld();
    const envBefore = fs.readFileSync(w.paths.envFile, 'utf8');
    const result = await w.service.run({ env: w.env(), drainSeconds: 0, writeEnv: false });

    assert.strictEqual(fs.readFileSync(w.paths.envFile, 'utf8'), envBefore);
    assert.strictEqual(result.stillLocked, true);
    assert.ok(w.service.maintenance.isLocked());
    assert.ok(fs.existsSync(result.manualEnvFile));
    assert.strictEqual(fs.statSync(result.manualEnvFile).mode & 0o777, 0o600);

    // Con las variables viejas, finish se niega
    await assert.rejects(() => w.service.finish({ env: w.env() }), /no coinciden/);
    assert.ok(w.service.maintenance.isLocked());

    // El operador aplica las variables nuevas en el panel del hosting…
    const applied = require('dotenv').parse(fs.readFileSync(result.manualEnvFile));
    setEnv(applied);
    const outcome = await w.service.finish({ env: w.env() });

    assert.strictEqual(outcome.released, true);
    assert.ok(!w.service.maintenance.isLocked());
    assert.ok(!fs.existsSync(result.manualEnvFile), 'el archivo con secretos se borra');
    assertPlainData(await readAll(currentKey()));
});

// ----------------------------------------------------------------------- migración desde claves legacy (diarias)

const daysAgo = (n) => new Date(Date.now() - n * 86400000).toISOString().split('T')[0];

itDb('legacy: datos cifrados con las claves de DISTINTOS días se migran a claves estables', async () => {
    const w = await freshWorld({ legacyDates: [daysAgo(0), daysAgo(3), daysAgo(11)] });

    // Sin --legacy-scan-days se niega y explica por qué
    await assert.rejects(() => w.service.run({ env: w.env(), drainSeconds: 0 }), /legacy.*cambian cada día/s);
    assert.ok(!w.service.maintenance.isLocked());

    const report = await w.service.analyze({ env: w.env(), legacyScanDays: 30 });
    assert.strictEqual(report.mode, 'legacy');
    assert.strictEqual(report.ready, true);

    const result = await w.service.run({ env: w.env(), drainSeconds: 0, legacyScanDays: 30 });
    assert.ok(result.legacyDecryptions > 0);

    const newSet = newKeyFromFile(w.paths.envFile);
    assert.strictEqual(newSet.mode, 'stable');
    assertPlainData(await readAll(newSet.encryption));

    // Las claves legacy no tienen una "clave anterior" estable: el backup va con la clave nueva
    assert.strictEqual(result.backup.encryptedWith, 'clave nueva');
    assert.ok(w.service.openBackup(result.backup.file, newSet).snapshot.tables.users.rows.length === 3);
});

itDb('legacy: si una fila usa una clave fuera del rango escaneado, aborta sin cambiar nada', async () => {
    const w = await freshWorld({ legacyDates: [daysAgo(1)] });
    const lejana = keyProvider.deriveLegacyKeySet({ baseSeed: process.env.BASE_SEED, jwtSeed: process.env.JWT_SEED, date: daysAgo(200) }).encryption;
    const cell = encryptor.withKey(lejana, () => encryptor.encrypt('dato antiguo'), { quiet: true });
    await db.query('UPDATE users SET email_encrypted = ? WHERE id = ?', [cell, w.ids[2]]);
    const before = await checksum();

    await assert.rejects(() => w.service.run({ env: w.env(), drainSeconds: 0, legacyScanDays: 30 }), /users\.email_encrypted/);
    assert.strictEqual(await checksum(), before);
    assert.ok(!w.service.maintenance.isLocked());
});

// ----------------------------------------------------------------------- restauración

itDb('restore: devuelve la BD al estado del backup y re-cifra con la clave actual', async () => {
    const w = await freshWorld();
    await w.service.run({ env: w.env(), drainSeconds: 0 });
    setEnv(require('dotenv').parse(fs.readFileSync(w.paths.envFile)));
    const backup = w.service.listBackupFiles()[0];

    // Se estropea la BD después del backup
    await db.query('DELETE FROM user_notes');
    await db.query("UPDATE users SET username_encrypted = ? WHERE id = ?", [encCurrent('INTRUSO'), w.ids[0]]);
    await db.query('DELETE FROM users WHERE id = ?', [w.ids[2]]);

    const outcome = await w.service.restore(backup, { env: w.env() });

    assert.strictEqual(outcome.restored.users, 3);
    assert.ok(outcome.skipped.includes('crypto_meta') && outcome.skipped.includes('user_sessions'));
    assertPlainData(await readAll(currentKey()));      // con la clave ACTUAL, aunque el backup era de la anterior
    assert.ok(!w.service.maintenance.isLocked());
    const [[meta]] = await db.query('SELECT key_fingerprint FROM crypto_meta WHERE id = 1');
    assert.strictEqual(meta.key_fingerprint, secureEnv.fingerprint, 'restaurar no debe tocar el marcador de claves');
});

itDb('restore: --tables solo restaura las tablas indicadas', async () => {
    const w = await freshWorld();
    await w.service.run({ env: w.env(), drainSeconds: 0 });
    setEnv(require('dotenv').parse(fs.readFileSync(w.paths.envFile)));
    await db.query('DELETE FROM user_notes');
    await db.query("UPDATE users SET username_encrypted = ? WHERE id = ?", [encCurrent('CAMBIADO'), w.ids[0]]);

    await w.service.restore(w.service.listBackupFiles()[0], { env: w.env(), only: ['user_notes'] });

    const all = await readAll(currentKey());
    assert.strictEqual(all.user_notes.length, 1);
    assert.strictEqual(all.users[0].username_encrypted, 'CAMBIADO', 'users no debía tocarse');
});

// ----------------------------------------------------------------------- análisis y CLI

itDb('analyze: no modifica nada y detecta datos ilegibles', async () => {
    const w = await freshWorld();
    const before = await checksum();
    const report = await w.service.analyze({ env: w.env() });
    assert.strictEqual(report.tables.users, 3);
    assert.strictEqual(await checksum(), before);
    assert.ok(!w.service.maintenance.isLocked());

    await db.query("UPDATE users SET username_encrypted = 'roto' WHERE id = ?", [w.ids[0]]);
    await assert.rejects(() => w.service.analyze({ env: w.env() }), /users\.username_encrypted/);
});

itDb('CLI: rotate exige --confirm; con --confirm rota, y status/backups/verify funcionan', async () => {
    const w = await freshWorld();
    const cliEnv = {
        PATH: process.env.PATH, ENV_FILE: w.paths.envFile, ROTATION_DATA_DIR: w.paths.dataDir, BACKUP_DIR: w.paths.backupDir,
        DB_FRAGMENT_1: process.env.DB_FRAGMENT_1, DB_FRAGMENT_2: process.env.DB_FRAGMENT_2, DB_FRAGMENT_3: process.env.DB_FRAGMENT_3, NODE_ENV: 'test'
    };
    writeEnvFile(w.paths.envFile, {
        PORT: 3000, NODE_ENV: 'test', DB_FRAGMENT_1: process.env.DB_FRAGMENT_1, DB_FRAGMENT_2: process.env.DB_FRAGMENT_2, DB_FRAGMENT_3: process.env.DB_FRAGMENT_3,
        BASE_SEED: process.env.BASE_SEED, ENCRYPTION_SEED: 'enc-seed-inicial', JWT_SEED: 'jwt-seed-inicial', KEY_EPOCH: 'T0-inicial'
    });
    const cli = (...args) => spawnSync('node', [path.join(__dirname, 'scripts/rotateKeys.js'), ...args], { env: cliEnv, encoding: 'utf8', timeout: 60000 });

    const sinConfirmar = cli('rotate');
    assert.strictEqual(sinConfirmar.status, 2);
    assert.match(sinConfirmar.stderr, /--confirm/);
    assert.ok(!fs.existsSync(w.paths.backupDir), 'sin confirmar no se toca nada');

    assert.strictEqual(cli('analyze').status, 0);

    const rotated = cli('rotate', '--confirm', '--drain', '0', '--no-notify');
    assert.strictEqual(rotated.status, 0, rotated.stdout + rotated.stderr);
    assert.match(rotated.stdout, /Rotación .* completada/);
    assert.match(rotated.stdout, /cifrado con la clave anterior/);

    assertPlainData(await readAll(newKeyFromFile(w.paths.envFile).encryption));

    const status = cli('status');
    assert.match(status.stdout, /modo stable/);
    assert.match(status.stdout, /Backups \(1\)/);

    const file = w.service.listBackupFiles()[0];
    const verified = cli('verify', file);
    assert.strictEqual(verified.status, 0, verified.stdout + verified.stderr);
    assert.match(verified.stdout, /users: 3 filas/);

    const sinConfirmarRestore = cli('restore', file);
    assert.strictEqual(sinConfirmarRestore.status, 2);
});

// ----------------------------------------------------------------------- firewall

test('maintenance-firewall.sh: dry-run, y se niega a aplicar sin IPs de administración', () => {
    const script = path.join(__dirname, 'scripts/maintenance-firewall.sh');
    const dry = execFileSync('bash', [script], { env: { PATH: process.env.PATH, MAINTENANCE_ADMIN_IPS: '203.0.113.10' }, encoding: 'utf8' });
    assert.match(dry, /Dry-run: no se ha modificado nada/);
    assert.match(dry, /-s 203\.0\.113\.10 -j ACCEPT/);
    assert.match(dry, /--ctstate ESTABLISHED,RELATED -j ACCEPT/);

    const apply = spawnSync('bash', [script, '--apply'], { env: { PATH: process.env.PATH }, encoding: 'utf8' });
    assert.notStrictEqual(apply.status, 0);
    assert.match(apply.stderr, /root|MAINTENANCE_ADMIN_IPS/);

    const invalid = spawnSync('bash', [script, '--dry-run'], { env: { PATH: process.env.PATH, MAINTENANCE_ADMIN_IPS: '1.2.3.4; reboot' }, encoding: 'utf8' });
    assert.notStrictEqual(invalid.status, 0);
});
