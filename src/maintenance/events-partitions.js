// Particionado MENSUAL de security_events (opcional): `npm run events:partition -- enable`.
//
// Por qué: es la tabla que más crece (cada petición sospechosa, cada login fallido…). Sin particiones, la retención se aplica con
// DELETE … LIMIT 5000 cada 10 minutos: con millones de filas eso son escrituras continuas, huecos y purgas que no dan abasto. Con
// una partición por mes, caducar un mes entero es DROP PARTITION (instantáneo, sin bloquear la tabla ni generar deshacer), y las
// consultas por fecha (panel, resumen) solo leen los meses necesarios.
//
// Qué cambia en la tabla: la clave primaria pasa de (id) a (id, created_at) (MariaDB/MySQL exigen que la columna de partición forme
// parte de toda clave única). id sigue siendo AUTO_INCREMENT y único en la práctica; las consultas por id (stream en vivo) no cambian.
//
//   p_hist      todo lo anterior al mes en que se activó
//   pAAAAMM     un mes cada una (se crean MONTHS_AHEAD por delante; las crea la tarea de limpieza del líder)
//   p_future    red de seguridad para fechas más allá (nunca debería tener filas)
//
// ACTIVARLO reconstruye la tabla (ALTER TABLE): hazlo en una ventana de mantenimiento si ya tiene muchos millones de filas.
// Los nombres y fechas de las particiones los calcula este código (nunca vienen de una petición): por eso el DDL se compone aquí.

const db = require('../config/database');

const TABLE = 'security_events';
const pad = (n) => String(n).padStart(2, '0');
const monthStart = (date) => new Date(Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), 1));
const addMonths = (date, n) => new Date(Date.UTC(date.getUTCFullYear(), date.getUTCMonth() + n, 1));
const ymd = (date) => `${date.getUTCFullYear()}-${pad(date.getUTCMonth() + 1)}-${pad(date.getUTCDate())}`;
const nameFor = (date) => `p${date.getUTCFullYear()}${pad(date.getUTCMonth() + 1)}`;
const monthsAhead = () => Math.min(Math.max(Number(process.env.EVENTS_PARTITION_MONTHS_AHEAD) || 3, 1), 24);

async function partitions() {
    const [rows] = await db.query(
        `SELECT PARTITION_NAME AS name, PARTITION_DESCRIPTION AS bound, TABLE_ROWS AS approxRows
         FROM information_schema.PARTITIONS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND PARTITION_NAME IS NOT NULL
         ORDER BY PARTITION_ORDINAL_POSITION`, [TABLE]);
    return rows.map(r => ({ name: r.name, bound: r.bound === 'MAXVALUE' ? null : Number(r.bound), approxRows: Number(r.approxRows) }));
}

const isPartitioned = async () => (await partitions()).length > 0;

// TO_DAYS(fecha) como lo calcula el servidor (es el límite que guarda information_schema)
async function toDays(date) {
    const [[row]] = await db.query('SELECT TO_DAYS(?) AS d', [ymd(date)]);
    return Number(row.d);
}

async function enable({ now = new Date() } = {}) {
    if (await isPartitioned()) return { changed: false, partitions: await partitions() };
    const first = monthStart(now);
    const parts = [`PARTITION p_hist VALUES LESS THAN (TO_DAYS('${ymd(first)}'))`];
    for (let i = 0; i <= monthsAhead(); i++) {
        parts.push(`PARTITION ${nameFor(addMonths(first, i))} VALUES LESS THAN (TO_DAYS('${ymd(addMonths(first, i + 1))}'))`);
    }
    parts.push('PARTITION p_future VALUES LESS THAN MAXVALUE');
    await db.query(`ALTER TABLE ${TABLE} DROP PRIMARY KEY, ADD PRIMARY KEY (id, created_at) PARTITION BY RANGE (TO_DAYS(created_at)) (${parts.join(', ')})`);
    return { changed: true, partitions: await partitions() };
}

// Crea los meses que falten por delante y borra los que ya caducaron por completo. Idempotente.
async function maintain({ now = new Date(), retentionDays = Number(process.env.SECURITY_EVENTS_RETENTION_DAYS) || 90 } = {}) {
    if (!(await isPartitioned())) return { partitioned: false };
    const created = [];
    const dropped = [];
    let list = await partitions();

    // 1. Meses por delante: se parte p_future (está vacía: es solo el "resto")
    const target = addMonths(monthStart(now), monthsAhead() + 1);
    for (;;) {
        const monthly = list.filter(p => /^p\d{6}$/.test(p.name));
        const lastBound = monthly.length ? monthly.at(-1).bound : (list.find(p => p.name === 'p_hist')?.bound ?? 0);
        if (lastBound >= await toDays(target)) break;
        const lastMonth = monthly.length ? new Date(Date.UTC(Number(monthly.at(-1).name.slice(1, 5)), Number(monthly.at(-1).name.slice(5, 7)) - 1, 1)) : addMonths(monthStart(now), -1);
        const next = addMonths(lastMonth, 1);
        await db.query(`ALTER TABLE ${TABLE} REORGANIZE PARTITION p_future INTO (PARTITION ${nameFor(next)} VALUES LESS THAN (TO_DAYS('${ymd(addMonths(next, 1))}')), PARTITION p_future VALUES LESS THAN MAXVALUE)`);
        created.push(nameFor(next));
        list = await partitions();
    }

    // 2. Meses enteramente caducados: DROP (instantáneo). El mes que caduca A MEDIAS lo limpia el DELETE acotado de la purga.
    const cutoff = await toDays(new Date(now.getTime() - retentionDays * 86_400_000));
    for (const p of list) {
        if (p.name === 'p_future' || p.bound === null || p.bound > cutoff) continue;
        // nunca se deja la tabla sin particiones "normales": siempre queda al menos el mes actual y los de delante
        await db.query(`ALTER TABLE ${TABLE} DROP PARTITION ${p.name}`);
        dropped.push(p.name);
    }
    return { partitioned: true, created, dropped };
}

module.exports = { enable, maintain, partitions, isPartitioned, nameFor };
