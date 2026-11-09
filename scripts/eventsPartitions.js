#!/usr/bin/env node
// Particionado mensual de security_events (ver src/maintenance/events-partitions.js).
//
//   npm run events:partition -- status      particiones actuales (y filas aproximadas)
//   npm run events:partition -- enable      activa el particionado (RECONSTRUYE la tabla: ventana de mantenimiento si es grande)
//   npm run events:partition -- maintain    crea los meses por delante y borra los caducados (lo hace solo la tarea de limpieza)
//
// EVENTS_PARTITION_MONTHS_AHEAD (3) meses por delante; SECURITY_EVENTS_RETENTION_DAYS (90) retención.
require('dotenv').config({ path: process.env.ENV_FILE || require('path').join(__dirname, '../.env') });

const db = require('../src/config/database');
const partitions = require('../src/maintenance/events-partitions');

async function main() {
    const command = process.argv[2] || 'status';
    if (command === 'status') {
        const list = await partitions.partitions();
        if (list.length === 0) console.log('security_events NO está particionada (la retención usa DELETE por lotes). Para activarlo: enable');
        else for (const p of list) console.log(`${p.name.padEnd(10)} ${p.bound === null ? 'MAXVALUE' : `< TO_DAYS ${p.bound}`}  ~${p.approxRows} filas`);
    } else if (command === 'enable') {
        const result = await partitions.enable();
        console.log(result.changed ? `✅ Particionada: ${result.partitions.map(p => p.name).join(', ')}` : 'Ya estaba particionada');
    } else if (command === 'maintain') {
        console.log(JSON.stringify(await partitions.maintain()));
    } else {
        console.error('Uso: status | enable | maintain');
        process.exitCode = 2;
    }
}

main()
    .catch((error) => { console.error('❌', error.code || error.message); process.exitCode = 1; })
    .finally(() => db.close().catch(() => {}));
