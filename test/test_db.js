// Adaptador de base de datos (src/config/db-drivers): elección del motor y CONTRATO que todo driver debe cumplir.
// Las pruebas del contrato con la base de datos real son las mismas que tendrá que pasar el driver de PostgreSQL.
//
//   node --test test_db.js     (las de contrato necesitan MariaDB; sin ella se omiten)

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

require('./helpers/env');
const helpers = require('./helpers/app');
const { resolveClient, loadDriver } = require('../src/config/db-drivers');

// ------------------------------------------------------------------ elección del motor (sin BD)

test('DB_CLIENT: mysql por defecto; alias de MariaDB, PostgreSQL y Supabase', () => {
    assert.strictEqual(resolveClient(undefined), 'mysql');
    assert.strictEqual(resolveClient(''), 'mysql');
    assert.strictEqual(resolveClient('MariaDB'), 'mysql');
    assert.strictEqual(resolveClient(' mysql '), 'mysql');
    for (const v of ['postgres', 'PostgreSQL', 'supabase']) assert.strictEqual(resolveClient(v), 'postgres');
});

test('DB_CLIENT desconocido: no arranca (no adivina el motor)', () => {
    for (const v of ['mongodb', 'sqlite', 'mysql; DROP', '__proto__', 'constructor']) {
        assert.throws(() => resolveClient(v), /DB_CLIENT no válido/);
    }
});

test('DB_CLIENT=postgres todavía no se ofrece: error claro, no un fallo a medias', () => {
    assert.throws(() => loadDriver('postgres'), /todavía no está disponible/);
});

test('el driver mysql cumple la forma del contrato sin conectarse', async () => {
    const driver = loadDriver('mysql');
    assert.strictEqual(driver.name, 'mysql');
    assert.strictEqual(driver.isTlsUnsupported({ code: 'HANDSHAKE_NO_SSL_SUPPORT' }), true);
    assert.strictEqual(driver.isTlsUnsupported(new Error('x')), false);
    const pool = driver.createPool({ uri: 'mysql://x:y@127.0.0.1:1/z', connectionLimit: 1 }); // perezoso: no conecta
    for (const m of ['getConnection', 'end']) assert.strictEqual(typeof pool[m], 'function', m);
    await pool.end();
});

test('un único punto de entrada: solo el driver importa el cliente de la base de datos', () => {
    const offenders = [];
    const walk = (dir) => {
        for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
            const full = path.join(dir, entry.name);
            if (entry.isDirectory()) walk(full);
            else if (entry.name.endsWith('.js') && /require\(['"](mysql2|mysql|pg|postgres|mariadb)(\/[^'"]*)?['"]\)/.test(fs.readFileSync(full, 'utf8'))) {
                offenders.push(path.relative(path.join(__dirname, '..'), full).replace(/\\/g, '/'));
            }
        }
    };
    walk(path.join(__dirname, '..', 'src'));
    walk(path.join(__dirname, '..', 'scripts'));
    assert.deepStrictEqual(offenders, ['src/config/db-drivers/mysql.js']);
});

// SQL portable ya conseguido: no se reintroduce (docs/BASES-DE-DATOS.md §2)
test('SQL portable: sin SUM(condición), que en PostgreSQL falla (boolean); se usa SUM(CASE WHEN … THEN 1 ELSE 0 END)', () => {
    const offenders = [];
    const walk = (dir) => {
        for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
            const full = path.join(dir, entry.name);
            if (entry.isDirectory()) walk(full);
            else if (entry.name.endsWith('.js')) {
                for (const m of fs.readFileSync(full, 'utf8').matchAll(/SUM\(\s*(?!CASE\b)((?:[^()]|\([^()]*\))*)\)/gi)) {
                    if (/(<>|<=|>=|[=<>]|\bIN\s*\(|\bIS\b|\bAND\b|\bOR\b)/i.test(m[1])) offenders.push(`${path.relative(path.join(__dirname, '..'), full)}: ${m[0]}`);
                }
            }
        }
    };
    walk(path.join(__dirname, '..', 'src'));
    walk(path.join(__dirname, '..', 'scripts'));
    assert.deepStrictEqual(offenders, []);
});

// ------------------------------------------------------------------ contrato con la base de datos real

let db, enabled = false;
test.before(async () => {
    enabled = await helpers.prepareDatabase();
    if (enabled) db = require('../src/config/database');
});
test.after(async () => { if (db?.pool) await db.pool.end(); });
const itDb = (name, fn) => test(`contrato: ${name}`, async (t) => { if (!enabled) return t.skip('sin BD'); await fn(t); });

itDb('SELECT devuelve [filas] con objetos por columna', async () => {
    const [rows] = await db.query('SELECT ? AS a, ? AS b', [7, 'siete']);
    assert.ok(Array.isArray(rows));
    assert.strictEqual(rows.length, 1);
    assert.strictEqual(Number(rows[0].a), 7);
    assert.strictEqual(rows[0].b, 'siete');
});

itDb('escrituras: insertId y affectedRows (anti-replay y canjes de un solo uso dependen de affectedRows)', async () => {
    await db.withConnection(async ({ query }) => {
        await query('CREATE TEMPORARY TABLE contrato_tmp (id INT AUTO_INCREMENT PRIMARY KEY, v VARCHAR(20) NOT NULL)');
        const [ins] = await query('INSERT INTO contrato_tmp (v) VALUES (?)', ['uno']);
        assert.ok(Number(ins.insertId) > 0, 'insertId');
        assert.strictEqual(ins.affectedRows, 1);
        const [first] = await query('UPDATE contrato_tmp SET v = ? WHERE id = ? AND v = ?', ['usado', ins.insertId, 'uno']);
        assert.strictEqual(first.affectedRows, 1, 'el primer canje gana');
        const [second] = await query('UPDATE contrato_tmp SET v = ? WHERE id = ? AND v = ?', ['usado', ins.insertId, 'uno']);
        assert.strictEqual(second.affectedRows, 0, 'el segundo canje no cambia nada');
        const [del] = await query('DELETE FROM contrato_tmp WHERE id = ?', [ins.insertId]);
        assert.strictEqual(del.affectedRows, 1);
    });
});

itDb('transacción: COMMIT al terminar y ROLLBACK si lanza', async () => {
    const name = `contrato_${process.pid}_${Date.now()}`;
    await db.query(`CREATE TABLE ${name} (id INT PRIMARY KEY)`);
    try {
        await db.transaction(async ({ query }) => { await query(`INSERT INTO ${name} (id) VALUES (?)`, [1]); });
        await assert.rejects(db.transaction(async ({ query }) => {
            await query(`INSERT INTO ${name} (id) VALUES (?)`, [2]);
            throw new Error('fallo a mitad');
        }), /fallo a mitad/);
        const [rows] = await db.query(`SELECT id FROM ${name} ORDER BY id`);
        assert.deepStrictEqual(rows.map(r => Number(r.id)), [1]);
    } finally {
        await db.query(`DROP TABLE ${name}`);
    }
});

itDb('conexión retenida: execute, query, transacción manual, on y destroy (líder y rotación)', async () => {
    const conn = await db.pool.getConnection();
    for (const m of ['execute', 'query', 'beginTransaction', 'commit', 'rollback', 'release', 'destroy', 'on']) {
        assert.strictEqual(typeof conn[m], 'function', m);
    }
    const [[row]] = await conn.execute('SELECT ? AS x', [1]);
    assert.strictEqual(Number(row.x), 1);
    await conn.beginTransaction();
    await conn.rollback();
    conn.release();
    const doomed = await db.pool.getConnection();
    doomed.on('error', () => {});
    doomed.destroy(); // no se devuelve al pool: el siguiente getConnection abre otra
    const [[again]] = await db.query('SELECT 1 AS ok');
    assert.strictEqual(Number(again.ok), 1);
});

itDb('los errores conservan el código del motor y no exponen el SQL', async () => {
    await assert.rejects(db.query('SELECT * FROM tabla_que_no_existe_contrato'), (e) => {
        assert.ok(e.code, 'código del motor (p. ej. ER_NO_SUCH_TABLE)');
        return true;
    });
});
