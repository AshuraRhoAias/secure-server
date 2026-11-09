// Particionado mensual de security_events y réplica de lectura. MariaDB real (cada archivo de pruebas recrea su BD).
//
//   npm run test:partitions

const test = require('node:test');
const assert = require('node:assert');
require('./test_helpers/env');
const helpers = require('./test_helpers/app');

let dbAvailable = false, db, parts, events;
test.before(async () => {
    dbAvailable = await helpers.prepareDatabase();
    if (!dbAvailable) return;
    db = require('./src/config/database');
    parts = require('./src/maintenance/events-partitions');
    events = require('./src/security/security-events.service');
});
test.after(async () => { if (db?.pool) await db.close(); });
const itDb = (name, fn) => test(name, async (t) => { if (!dbAvailable) return t.skip('sin base de datos'); await fn(t); });

const daysAgo = (n) => new Date(Date.now() - n * 86_400_000).toISOString().slice(0, 19).replace('T', ' ');
const insert = (type, when) => db.query('INSERT INTO security_events (event_type, severity, created_at) VALUES (?, ?, ?)', [type, 'medium', when]);
const countType = async (type) => Number((await db.query('SELECT COUNT(*) AS n FROM security_events WHERE event_type = ?', [type]))[0][0].n);

itDb('sin particionar: la purga sigue siendo DELETE por lotes (número de filas)', async () => {
    assert.strictEqual(await parts.isPartitioned(), false);
    await insert('PART_OLD_PLAIN', daysAgo(200));
    assert.strictEqual(typeof await events.purge(90), 'number');
    assert.strictEqual(await countType('PART_OLD_PLAIN'), 0);
});

itDb('activar: p_hist + mes actual + meses por delante + p_future; los datos existentes se conservan y es idempotente', async () => {
    await insert('PART_BEFORE', daysAgo(150));
    await insert('PART_NOW', daysAgo(0));
    const result = await parts.enable();
    assert.strictEqual(result.changed, true);
    const names = result.partitions.map(p => p.name);
    assert.strictEqual(names[0], 'p_hist');
    assert.strictEqual(names.at(-1), 'p_future');
    assert.ok(names.includes(parts.nameFor(new Date())), 'mes actual');
    assert.ok(names.filter(n => /^p\d{6}$/.test(n)).length >= 4, 'mes actual + 3 por delante');
    assert.strictEqual(await countType('PART_BEFORE'), 1);
    assert.strictEqual(await countType('PART_NOW'), 1);
    assert.strictEqual((await parts.enable()).changed, false);

    // id sigue siendo autoincremental y el cursor por id (stream en vivo) funciona igual
    const [[a]] = await db.query('SELECT MAX(id) AS id FROM security_events');
    await insert('PART_AFTER', daysAgo(0));
    const [rows] = await db.query('SELECT event_type FROM security_events WHERE id > ? ORDER BY id', [a.id]);
    assert.deepStrictEqual(rows.map(r => r.event_type), ['PART_AFTER']);
});

itDb('mantenimiento: crea los meses que faltan (idempotente) y la purga quita los meses caducados con DROP PARTITION', async () => {
    const future = new Date(Date.now() + 200 * 86_400_000);
    const ahead = await parts.maintain({ now: future, retentionDays: 3650 });
    assert.ok(ahead.created.length >= 1, 'crea meses por delante');
    assert.deepStrictEqual((await parts.maintain({ now: future, retentionDays: 3650 })).created, [], 'idempotente');

    await insert('PART_EXPIRED', daysAgo(150));   // cae en p_hist
    await insert('PART_KEEP', daysAgo(1));
    const result = await events.purge(30);
    assert.ok(result.partitioned);
    assert.ok(result.dropped.includes('p_hist'), `dropped: ${result.dropped}`);
    assert.strictEqual(await countType('PART_EXPIRED'), 0);
    assert.strictEqual(await countType('PART_KEEP'), 1);
    const names = (await parts.partitions()).map(p => p.name);
    assert.ok(names.includes(parts.nameFor(new Date())), 'el mes actual sigue');
    assert.strictEqual(names.at(-1), 'p_future');

    // El panel y el resumen (por fecha) siguen funcionando sobre la tabla particionada
    const summary = await events.summary({ hours: 24 });
    assert.ok(Array.isArray(summary.byType));
    const list = await events.list({ sinceHours: 48 });
    assert.ok(list.some(e => e.event_type === 'PART_KEEP'));
});

itDb('réplica de lectura: readQuery solo admite SELECT y, sin réplica (o si no responde), usa la principal', async () => {
    await assert.rejects(db.readQuery('DELETE FROM security_events'), /solo admite SELECT/);
    const [[row]] = await db.readQuery('SELECT 1 AS uno');
    assert.strictEqual(row.uno, 1);

    // Réplica caída: el panel no se cae, se lee de la principal
    const mysql = require('mysql2/promise');
    db.readPool = mysql.createPool({ host: '127.0.0.1', port: 1, user: 'x', password: 'x', connectTimeout: 500 });
    try {
        const [[again]] = await db.readQuery('SELECT 2 AS dos');
        assert.strictEqual(again.dos, 2);
    } finally {
        await db.readPool.end().catch(() => {});
        db.readPool = null;
    }
});
