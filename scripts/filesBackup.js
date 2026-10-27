#!/usr/bin/env node
// Copias de seguridad de los archivos cifrados (ver src/files/files-backup.js y docs/SEGURIDAD.md).
//
//   npm run files:backup                       copia incremental a FILES_BACKUP_DIR (+ cruza BD y disco)
//   npm run files:verify                       comprueba la integridad de la copia y su cobertura de la BD
//   npm run files:restore [-- --target DIR --force --all]   restaura lo que falte (verificando hashes)
//
// Códigos de salida: 0 todo bien · 2 hay archivos perdidos/truncados/dañados · 1 error.
// Programación sugerida (cron):  17 3 * * *  cd /ruta/app && npm run -s files:backup >> /var/log/files-backup.log

require('dotenv').config({ path: process.env.ENV_FILE || require('path').join(__dirname, '../.env') });

const db = require('../src/config/database');
const filesBackup = require('../src/files/files-backup');

const args = process.argv.slice(2);
const command = args[0];
const option = (name) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : undefined; };

async function main() {
    if (command === 'backup') {
        const report = await filesBackup.backup({ db });
        console.log(JSON.stringify(report, null, 2));
        if (report.missingFiles.length || report.wrongSize.length || report.changedInSource.length || report.errors.length) {
            console.error('⚠️ HAY ARCHIVOS PERDIDOS O TRUNCADOS en el disco de origen: restáuralos con `npm run files:restore`');
            process.exitCode = 2;
        }
    } else if (command === 'verify') {
        const report = await filesBackup.verify({ db });
        console.log(JSON.stringify(report, null, 2));
        if (report.corrupt.length || report.missingInBackup.length) process.exitCode = 2;
        else if (report.notBackedUp.length) console.error(`⚠️ ${report.notBackedUp.length} archivos de la BD todavía no tienen copia: ejecuta files:backup`);
    } else if (command === 'restore') {
        const report = await filesBackup.restore({
            db, target: option('--target') || undefined, force: args.includes('--force'), onlyReferenced: !args.includes('--all')
        });
        console.log(JSON.stringify(report, null, 2));
        if (report.refused.length) process.exitCode = 2;
    } else {
        console.log('Uso: npm run files:backup | files:verify | files:restore [-- --target DIR] [--force] [--all]');
        process.exitCode = command ? 2 : 0;
    }
}

main()
    .catch((error) => { console.error(`❌ ${error.message}`); process.exitCode = 1; })
    .finally(() => db.pool.end());
