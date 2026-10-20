#!/usr/bin/env node
// Rotación de claves de cifrado con migración de datos, backups y modo mantenimiento.
//
//   npm run rotate-keys -- status                  estado de claves, lock, journal y backups
//   npm run rotate-keys -- analyze                 ensayo: comprueba que todo se puede descifrar (no cambia nada)
//   npm run rotate-keys -- rotate --confirm        rotación completa (ver abajo)
//   npm run rotate-keys -- recover                 termina o deshace una rotación interrumpida
//   npm run rotate-keys -- finish                  reabre tras una rotación con --no-write-env
//   npm run rotate-keys -- backups                 lista los backups
//   npm run rotate-keys -- verify <archivo.sbk>    abre un backup con las claves actuales y muestra su contenido
//   npm run rotate-keys -- restore <archivo.sbk> --confirm RESTORE [--tables users,user_notes]
//
// rotate:
//   1. activa el modo mantenimiento (503 a todo, sesiones expiradas, espera a las peticiones en curso)
//   2. backup de toda la BD, comprimido y cifrado con la clave ANTERIOR (verificado)
//   3. re-cifra los backups antiguos con la clave nueva (y guarda la anterior en el keyring)
//   4. re-cifra los datos en una transacción (descifra y cifra en memoria: no se escribe texto plano)
//   5. escribe las claves nuevas en el .env y reabre el servidor
//
// Opciones de rotate:
//   --confirm                 obligatoria (la operación bloquea el servidor)
//   --dry-run                 igual que `analyze`
//   --no-write-env            no toca el .env: deja las variables nuevas en data/rotation/new-env-*.txt
//                             y el servidor cerrado hasta aplicar las variables y ejecutar `finish`
//                             (para claves que viven en el panel del hosting)
//   --backup-key old|new      con qué clave se cifra el backup nuevo (por defecto old; usa new si rotas
//                             porque la clave anterior se ha comprometido)
//   --drain N                 segundos de espera a las peticiones en curso (por defecto 10)
//   --legacy-scan-days N      migra desde las claves legacy (que cambiaban cada día) probando hasta N días atrás
//   --keep-backups N          conserva solo los N backups más recientes (por defecto todos)
//   --lockdown-firewall       además cierra la entrada de red con scripts/maintenance-firewall.sh
//                             (requiere root y MAINTENANCE_ADMIN_IPS; se libera solo con --firewall-ttl)
//   --firewall-ttl N          minutos hasta liberar el firewall automáticamente (por defecto 120)
//   --no-notify               no enviar alertas ni escribir en la auditoría
//   --env-file <ruta>         archivo .env a usar y modificar (por defecto .env del proyecto)

const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

function parseArgs(argv) {
    const [command, ...rest] = argv;
    const flags = {};
    const positional = [];
    const withValue = new Set(['--backup-key', '--drain', '--legacy-scan-days', '--keep-backups', '--firewall-ttl', '--env-file', '--tables', '--confirm']);

    for (let i = 0; i < rest.length; i++) {
        const arg = rest[i];
        if (!arg.startsWith('--')) { positional.push(arg); continue; }
        if (withValue.has(arg) && rest[i + 1] && !rest[i + 1].startsWith('--')) flags[arg] = rest[++i];
        else flags[arg] = true;
    }
    return { command, flags, positional };
}

const { command, flags, positional } = parseArgs(process.argv.slice(2));

const ROOT = path.join(__dirname, '..');
const envFile = path.resolve(flags['--env-file'] || process.env.ENV_FILE || path.join(ROOT, '.env'));
process.env.ENV_FILE = envFile;
require('dotenv').config({ path: envFile });

const intFlag = (name, fallback) => {
    if (flags[name] === undefined) return fallback;
    const n = Number(flags[name]);
    if (!Number.isInteger(n) || n < 0) { console.error(`${name} debe ser un entero >= 0`); process.exit(2); }
    return n;
};

function firewall(action) {
    const script = path.join(__dirname, 'maintenance-firewall.sh');
    const args = action === 'apply' ? ['--apply', '--ttl', String(intFlag('--firewall-ttl', 120))] : ['--remove'];
    execFileSync('bash', [script, ...args], { stdio: 'inherit' });
}

async function notify(type, severity, details, priority = 'normal') {
    if (flags['--no-notify']) return;
    try {
        const audit = require('../src/services/audit.service');
        await audit.log(type, { details }, { severity, riskScore: severity === 'critical' ? 90 : 10 });
        const secureCommunications = require('../src/services/secure-communications.service');
        await secureCommunications.sendSecureAlert({ type, severity, details, timestamp: new Date().toISOString() }, priority);
    } catch (error) {
        console.error('ℹ️ No se pudo enviar la notificación:', error.message);
    }
}

const fmtBytes = (n) => (n > 1048576 ? `${(n / 1048576).toFixed(2)} MB` : `${(n / 1024).toFixed(1)} KB`);

async function main() {
    const { getRotationService } = require('../src/maintenance');
    const service = getRotationService();
    const secureEnv = require('../src/config/secure-env');
    const db = require('../src/config/database');

    try {
        // Igual que el servidor: testConnection() reintenta sin SSL si la BD no lo soporta
        if (!(await db.testConnection())) throw new Error('No se pudo conectar a la base de datos');

        switch (command) {
            case 'status': return await status(service, secureEnv, db);
            case 'analyze': return await analyze(service);
            case 'rotate': return flags['--dry-run'] ? await analyze(service) : await rotate(service, secureEnv);
            case 'recover': return await recover(service, secureEnv);
            case 'finish': return await finish(service, secureEnv);
            case 'backups': return backups(service);
            case 'verify': return verify(service, secureEnv);
            case 'restore': return await restore(service);
            default:
                console.error('Uso: rotate-keys <status|analyze|rotate|recover|finish|backups|verify|restore> [opciones]\nVer la cabecera de scripts/rotateKeys.js');
                process.exitCode = 2;
        }
    } finally {
        await db.pool.end().catch(() => {});
    }
}

async function status(service, secureEnv, db) {
    const info = secureEnv.getKeyInfo();
    console.log(`🔑 Claves en el entorno: modo ${info.mode}, época ${info.epoch}`);
    if (info.mode === 'legacy') console.log('   ⚠️ Modo legacy: las claves cambian cada día. Migra con: rotate --confirm --legacy-scan-days 30');

    try {
        const [rows] = await db.query('SELECT key_epoch, rotated_at, rotation_id FROM crypto_meta WHERE id = 1');
        console.log(rows[0] ? `🗄️ Última rotación registrada en la BD: ${rows[0].key_epoch} (${rows[0].rotated_at})` : '🗄️ La BD aún no tiene marcador de claves');
    } catch {
        console.log('🗄️ crypto_meta no existe (aplica database/migrations/002_crypto_meta.sql)');
    }

    const lock = service.maintenance.read();
    console.log(lock ? `🔒 MANTENIMIENTO ACTIVO: ${lock.operation} desde ${lock.startedAt} (fase ${lock.phase}, pid ${lock.pid})` : '🔓 Sin bloqueo de mantenimiento');

    const journal = service.readJournal();
    if (journal) console.log(`📓 Último journal: ${journal.id} — ${journal.phase} (${journal.oldEpoch} → ${journal.newEpoch})`);
    backups(service);
}

async function analyze(service) {
    const report = await service.analyze({ legacyScanDays: intFlag('--legacy-scan-days', 0) });
    console.log(`🔍 Modo de claves: ${report.mode} (${report.epoch})`);
    for (const [table, rows] of Object.entries(report.tables)) console.log(`   ${table}: ${rows} filas`);
    console.log(`✅ Todos los datos cifrados se pueden descifrar (${report.rows} filas en total). Nada se ha modificado.`);
    if (!report.ready) console.log('⚠️ Estás en modo legacy: para rotar necesitas --legacy-scan-days N');
}

async function rotate(service, secureEnv) {
    if (!flags['--confirm']) {
        console.error([
            '⚠️ La rotación BLOQUEA el servidor (503 a todas las peticiones), cierra las sesiones y reescribe',
            '   todos los datos cifrados y el .env. Antes de empezar:',
            '     - ejecuta `analyze` para comprobar que todo se descifra,',
            '     - asegúrate de tener espacio en disco para el backup,',
            '     - haz una copia del .env y de la base de datos con tus herramientas habituales.',
            '   Para continuar añade --confirm.'
        ].join('\n'));
        process.exitCode = 2;
        return;
    }

    const writeEnv = !flags['--no-write-env'];
    const useFirewall = !!flags['--lockdown-firewall'];
    let firewallOn = false;

    const hooks = {};
    if (useFirewall) {
        hooks.afterLock = () => { firewall('apply'); firewallOn = true; };
        hooks.beforeRelease = () => { firewall('remove'); firewallOn = false; };
    }

    const start = Date.now();
    try {
        const result = await service.run({
            env: process.env,
            writeEnv,
            backupKey: flags['--backup-key'] || 'old',
            drainSeconds: intFlag('--drain', 10),
            legacyScanDays: intFlag('--legacy-scan-days', 0),
            keepBackups: intFlag('--keep-backups', 0),
            // Recarga las claves en ESTE proceso antes de reabrir, para que la auditoría posterior use las nuevas
            reloadInProcess: writeEnv ? async () => { secureEnv.reload(envFile); } : null,
            hooks
        });

        const seconds = ((Date.now() - start) / 1000).toFixed(1);
        console.log(`\n✅ Rotación ${result.rotationId} completada en ${seconds}s`);
        console.log(`   Época: ${result.oldEpoch} → ${result.newEpoch}`);
        console.log(`   Valores re-cifrados: ${result.cellsReencrypted} (barrido final: ${result.sweepRepaired})`);
        console.log(`   Backup: ${path.basename(result.backup.file)} — ${fmtBytes(result.backup.bytes)} (${result.backup.compression}, cifrado con la ${result.backup.encryptedWith})`);
        console.log(`   Backups anteriores re-cifrados con la clave nueva: ${result.rewrappedBackups}`);
        if (result.prunedBackups?.length) console.log(`   Backups eliminados por --keep-backups: ${result.prunedBackups.join(', ')}`);
        if (result.stillLocked) console.log('\n⚠️ El servidor SIGUE EN MANTENIMIENTO hasta que apliques las variables nuevas y ejecutes: npm run rotate-keys -- finish');
        else await notify('KEY_ROTATION_SUCCESS', 'info', `Rotación ${result.rotationId} completada (${result.oldEpoch} → ${result.newEpoch})`);
    } catch (error) {
        console.error(`\n❌ ${error.message}`);
        // Si el servidor sigue en mantenimiento (fallo tras el commit) se deja también el firewall
        // cerrado (se libera solo por TTL); si se reabrió, se quita.
        if (firewallOn && !service.maintenance.isLocked()) { try { firewall('remove'); } catch { /* el TTL lo liberará */ } }
        await notify('KEY_ROTATION_FAILED', 'critical', `La rotación falló en la fase ${error.rotationPhase}: ${error.message}`, 'critical');
        process.exitCode = 1;
    }
}

async function recover(service, secureEnv) {
    const outcome = await service.recover({ env: process.env });
    console.log(`🛠️ ${outcome.message || outcome.action}`);
    if (outcome.action === 'finalized' && !outcome.stillLocked) {
        try { secureEnv.reload(envFile); } catch { /* el servidor recargará por su cuenta */ }
    }
}

async function finish(service, secureEnv) {
    try { secureEnv.reload(envFile); } catch { /* se comprueba abajo */ }
    const outcome = await service.finish({ env: process.env });
    console.log(`🔓 Claves verificadas (época ${outcome.epoch}). Servidor reabierto.`);
}

function backups(service) {
    const list = service.listBackups();
    if (list.length === 0) { console.log('💾 No hay backups'); return; }
    console.log(`💾 Backups (${list.length}):`);
    for (const b of list) {
        const rows = Object.values(b.tables || {}).reduce((a, n) => a + n, 0);
        console.log(`   ${path.basename(b.file)} — ${fmtBytes(b.bytes)} · ${b.compression} · época ${b.epoch} · ${rows} filas · ${b.createdAt}`);
    }
}

function verify(service, secureEnv) {
    const file = positional[0];
    if (!file) { console.error('Uso: rotate-keys verify <archivo.sbk>'); process.exitCode = 2; return; }

    const set = require('../src/crypto/key-provider').deriveFromEnv(process.env);
    const { header, snapshot } = service.openBackup(path.resolve(file), set);
    console.log(`✅ Backup válido (época ${header.epoch}, ${header.createdAt}, ${header.compression}, ${fmtBytes(header.rawBytes)} → ${fmtBytes(header.compressedBytes)})`);
    for (const [table, t] of Object.entries(snapshot.tables)) console.log(`   ${table}: ${t.rows.length} filas`);
    void secureEnv;
}

async function restore(service) {
    const file = positional[0];
    if (!file) { console.error('Uso: rotate-keys restore <archivo.sbk> --confirm RESTORE [--tables a,b]'); process.exitCode = 2; return; }
    if (flags['--confirm'] !== 'RESTORE') {
        console.error('⚠️ Restaurar SUSTITUYE el contenido de las tablas por el del backup. Si estás seguro añade: --confirm RESTORE');
        process.exitCode = 2;
        return;
    }

    const only = typeof flags['--tables'] === 'string' ? flags['--tables'].split(',') : null;
    const outcome = await service.restore(path.resolve(file), { env: process.env, only });
    console.log(`✅ Restaurado el backup de ${outcome.backupCreatedAt} (época ${outcome.backupEpoch})`);
    for (const [table, n] of Object.entries(outcome.restored)) console.log(`   ${table}: ${n} filas`);
    if (outcome.skipped.length) console.log(`   Omitidas: ${outcome.skipped.join(', ')}`);
    console.log('   Las sesiones se han cerrado: los usuarios deben volver a iniciar sesión.');
}

main().catch(error => {
    console.error(`❌ ${error.message}`);
    process.exitCode = 1;
});
