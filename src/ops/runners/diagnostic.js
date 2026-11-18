// Diagnóstico del sistema: comprobaciones REALES y no destructivas dentro del propio proceso. Cada paso anuncia lo que hace y
// emite ✓ / aviso / ✗ con su duración. Lo que escribe (un temporal de almacenamiento) lo borra siempre.
//
// target = 'with-notifications' además envía un aviso de prueba por los canales configurados (por defecto NO se envía nada).

const crypto = require('crypto');
const v8 = require('v8');
const { Readable } = require('stream');
const db = require('../../config/database');

const WITH_NOTIFICATIONS = 'with-notifications';

// EICAR (fichero de prueba estándar de antivirus, inofensivo). Se arma en pedazos para que el propio código fuente no lo detecte.
const EICAR = ['X5O!P%@AP[4\\PZX54(P^)7CC)7}$', 'EICAR-STANDARD-ANTIVIRUS-TEST-FILE!', '$H+H*'].join('');

function validate(target) {
    if (target && target !== WITH_NOTIFICATIONS) {
        const { RunError } = require('../runs.service');
        throw new RunError('INVALID_TARGET', `Destino no válido para el diagnóstico (solo "${WITH_NOTIFICATIONS}")`, 400);
    }
}

function describe() {
    return {
        title: 'Diagnóstico del sistema',
        description: 'Comprueba base de datos, esquema, cifrado, integridad, antivirus, KMS, almacenamiento, canales de alerta, reloj, memoria, rotación y líder. No modifica datos.',
        targets: [{ value: '', label: 'Solo comprobaciones' }, { value: WITH_NOTIFICATIONS, label: 'Con aviso de prueba por los canales' }],
        enabled: true
    };
}

// Tablas clave (consultas fijas: nada viene del exterior)
const TABLE_CHECKS = [
    ['users', 'SELECT 1 FROM users WHERE 1 = 0'],
    ['user_sessions', 'SELECT 1 FROM user_sessions WHERE 1 = 0'],
    ['security_events', 'SELECT 1 FROM security_events WHERE 1 = 0'],
    ['blocked_ips', 'SELECT 1 FROM blocked_ips WHERE 1 = 0'],
    ['admin_approvals', 'SELECT 1 FROM admin_approvals WHERE 1 = 0'],
    ['security_alerts', 'SELECT 1 FROM security_alerts WHERE 1 = 0'],
    ['user_files', 'SELECT 1 FROM user_files WHERE 1 = 0'],
    ['runtime_settings', 'SELECT 1 FROM runtime_settings WHERE 1 = 0'],
    ['ops_runs', 'SELECT 1 FROM ops_runs WHERE 1 = 0'],
    ['ops_run_events', 'SELECT 1 FROM ops_run_events WHERE 1 = 0']
];

const memoryBlob = (buffer) => ({
    size: async () => buffer.length,
    stream: (from, to) => Readable.from([buffer.subarray(from, to + 1)])
});

async function collect(iterable) {
    const parts = [];
    for await (const part of iterable) parts.push(Buffer.from(part));
    return Buffer.concat(parts);
}

async function checkEncryption() {
    const tripleEncryptor = require('../../crypto/tripleEncryptor');
    const fieldHealth = await tripleEncryptor.healthCheck();
    if (!fieldHealth.healthy) return { level: 'fail', message: `Cifrado de campos: ${fieldHealth.message}` };

    // Cifrado de archivos por bloques: ida y vuelta con datos aleatorios que cruzan un límite de bloque
    const { EncryptStream, decryptRange, newDataKey, CHUNK } = require('../../files/file-cipher');
    const plain = crypto.randomBytes(CHUNK + 1234);
    const key = newDataKey();
    const encryptor = new EncryptStream(key);
    const sealed = await collect(Readable.from([plain]).pipe(encryptor));
    const back = await collect(decryptRange({ blob: memoryBlob(sealed), key, plainSize: plain.length }));
    if (!back.equals(plain)) return { level: 'fail', message: 'El cifrado de archivos no devolvió los mismos datos' };

    // Un bloque alterado debe rechazarse
    const tampered = Buffer.from(sealed);
    tampered[10] ^= 0xff;
    let rejected = false;
    try { await collect(decryptRange({ blob: memoryBlob(tampered), key, plainSize: plain.length })); } catch { rejected = true; }
    if (!rejected) return { level: 'fail', message: 'Se aceptó un archivo cifrado alterado' };
    return { message: 'Cifrado de campos (v4) y de archivos: ida y vuelta correcta y alteraciones rechazadas' };
}

async function checkAntivirus() {
    const av = require('../../files/av-scanner');
    if (!av.enabled()) return { level: 'warn', message: 'Antivirus desactivado (FILE_SCAN=off): no se puede comprobar' };
    const clean = await av.scanBuffers([Buffer.from('contenido inofensivo de prueba')]);
    if (clean.status !== 'clean') return { level: 'fail', message: `clamd no respondió «limpio» para un texto normal (${clean.status}${clean.detail ? `: ${clean.detail}` : ''})` };
    const found = await av.scanBuffers([Buffer.from(EICAR)]);
    if (found.status !== 'found') return { level: 'fail', message: `clamd no detectó el fichero de prueba EICAR (${found.status})` };
    return { message: `clamd responde: texto limpio aceptado y EICAR detectado (${found.signature})` };
}

async function checkKms() {
    const provider = process.env.KMS_PROVIDER;
    if (!provider) return { level: 'warn', message: 'KMS no configurado (KMS_PROVIDER vacío): las claves no se envuelven' };
    const kmsKeys = require('../../crypto/kms-data-keys');
    const key = crypto.randomBytes(32);
    const name = `diag-${crypto.randomUUID()}`;
    const stored = await kmsKeys.wrapDataKey(name, key, provider);
    const back = await kmsKeys.unwrapDataKey(name, stored);
    if (!back.equals(key)) return { level: 'fail', message: 'El KMS devolvió una clave distinta al desenvolver' };
    kmsKeys.clearCache();
    return { message: `KMS (${provider}): clave de prueba envuelta y desenvuelta` };
}

async function checkStorage() {
    const storage = require('../../files/storage');
    const { EncryptStream, decryptRange, newDataKey } = require('../../files/file-cipher');
    const name = storage.newStorageName();
    const plain = crypto.randomBytes(4096);
    const key = newDataKey();
    let committed = false;
    try {
        const out = storage.createTempWriteStream(name);
        await new Promise((resolve, reject) => {
            const encryptor = new EncryptStream(key);
            encryptor.on('error', reject);
            out.on('error', reject).on('finish', resolve);
            Readable.from([plain]).pipe(encryptor).pipe(out);
        });
        await storage.commit(name);
        committed = true;
        const back = await collect(decryptRange({ blob: storage.blob(name), key, plainSize: plain.length }));
        if (!back.equals(plain)) return { level: 'fail', message: 'El almacenamiento devolvió datos distintos a los escritos' };
        return { message: `Almacenamiento (${storage.driver()}): escribir, leer y borrar un temporal correcto` };
    } finally {
        await (committed ? storage.removeFinal(name) : storage.removeTemp(name)).catch(() => {});
    }
}

async function checkChannels(withNotifications) {
    const comms = require('../../services/secure-communications.service');
    const names = [...comms.channels.keys()];
    if (comms.emailDisabled) names.push('archivo JSON (correo desactivado)');
    if (!names.length) return { level: 'warn', message: 'Sin canales de alerta configurados' };
    if (!withNotifications) return { message: `Canales configurados: ${names.join(', ')} (sin enviar avisos reales)`, data: { channels: names } };
    const results = await comms.testChannels();
    const bad = results.filter(r => r.status !== 'success');
    if (bad.length) return { level: 'fail', message: `Aviso de prueba fallido en: ${bad.map(r => r.channel).join(', ')}` };
    return { message: `Aviso de prueba enviado por: ${results.map(r => r.channel).join(', ')}` };
}

async function checkClock() {
    const [rows] = await db.query('SELECT NOW() AS now');
    const dbNow = new Date(rows[0].now).getTime();
    const drift = Math.abs(Date.now() - dbNow);
    if (drift > 5000) return { level: 'warn', message: `El reloj de la BD difiere ${Math.round(drift / 1000)} s del del servidor (revisa NTP o el huso horario)`, data: { driftMs: drift } };
    return { message: `Reloj coherente con la BD (desfase ${drift} ms)`, data: { driftMs: drift } };
}

async function eventLoopLag() {
    let worst = 0;
    for (let i = 0; i < 5; i++) {
        const t0 = process.hrtime.bigint();
        await new Promise(resolve => setTimeout(resolve, 20));
        worst = Math.max(worst, Number(process.hrtime.bigint() - t0) / 1e6 - 20);
    }
    return Math.max(0, Math.round(worst));
}

async function checkResources() {
    const mem = process.memoryUsage();
    const limit = v8.getHeapStatistics().heap_size_limit;
    const ratio = mem.heapUsed / limit;
    const lag = await eventLoopLag();
    const mb = (n) => Math.round(n / 1048576);
    const message = `Memoria: heap ${mb(mem.heapUsed)} MB de ${mb(limit)} MB, RSS ${mb(mem.rss)} MB; retraso del event loop ${lag} ms`;
    if (ratio > 0.9) return { level: 'warn', message: `${message} (heap casi lleno)` };
    if (lag > 200) return { level: 'warn', message: `${message} (event loop lento)` };
    return { message, data: { heapMb: mb(mem.heapUsed), rssMb: mb(mem.rss), lagMs: lag } };
}

async function checkRotation() {
    const { guard } = require('../../maintenance');
    const secureEnv = require('../../config/secure-env');
    const info = secureEnv.getKeyInfo();
    const state = guard.state || {};
    const auto = process.env.AUTO_ROTATION_ENABLED === 'true';
    if (state.outOfSync) return { level: 'fail', message: `Claves desincronizadas con los datos: ${state.detail || 'revisa la rotación'}` };
    if (state.maintenance) return { level: 'warn', message: 'Hay una rotación de claves en curso (mantenimiento)' };
    return { message: `Claves en modo ${info.mode}${info.epoch ? ` (época ${info.epoch})` : ''}; rotación automática ${auto ? 'activada' : 'desactivada'}; sin desincronía` };
}

async function checkLeader() {
    const leader = require('../../tasks/leader');
    if (leader.isLeader()) return { message: 'Este proceso es el líder de las tareas periódicas' };
    try {
        const [rows] = await db.query('SELECT IS_USED_LOCK(?) AS holder', [leader.LOCK_NAME]);
        if (rows[0]?.holder !== null && rows[0]?.holder !== undefined) return { message: 'Otra instancia es el líder de las tareas periódicas' };
    } catch {
        return { level: 'warn', message: 'No se pudo consultar quién es el líder (el motor no soporta IS_USED_LOCK)' };
    }
    return { level: 'warn', message: 'Ninguna instancia tiene el liderazgo: las tareas periódicas no se están ejecutando' };
}

async function run(ctx) {
    const withNotifications = ctx.target === WITH_NOTIFICATIONS;
    ctx.setTotal(6 + TABLE_CHECKS.length + (withNotifications ? 1 : 0) + 5);

    await ctx.step('base-de-datos', 'Probando la base de datos (SELECT 1)', async () => {
        const t0 = Date.now();
        await db.query('SELECT 1 AS ok');
        const ms = Date.now() - t0;
        return { level: ms > 500 ? 'warn' : 'pass', message: `Base de datos responde (latencia ${ms} ms)`, data: { latencyMs: ms } };
    });

    for (const [table, sql] of TABLE_CHECKS) {
        await ctx.step(`esquema:${table}`, `Comprobando la tabla ${table}`, async () => {
            await db.query(sql);
            return `Tabla ${table} presente`;
        });
    }

    await ctx.step('cifrado', 'Cifrado ida y vuelta con datos aleatorios', checkEncryption);

    await ctx.step('integridad', 'Huella de los archivos críticos del servidor', async () => {
        const serverCheck = require('../../middleware/serverCheck.middleware');
        const current = serverCheck.calculateServerFingerprint();
        if (!current) return { level: 'fail', message: 'No se pudo calcular la huella del servidor' };
        if (!serverCheck.serverFingerprint) return { level: 'warn', message: 'No hay huella inicial con la que comparar' };
        if (current !== serverCheck.serverFingerprint) return { level: 'fail', message: 'Los archivos críticos cambiaron desde el arranque' };
        return 'Huella idéntica a la del arranque (solo lectura: no se escribe ni se avisa)';
    });

    await ctx.step('antivirus', 'Antivirus (clamd) con texto limpio y EICAR', checkAntivirus);
    await ctx.step('kms', 'KMS: envolver y desenvolver una clave de prueba', checkKms);
    await ctx.step('almacenamiento', 'Almacenamiento: escribir, leer y borrar un temporal', checkStorage);
    await ctx.step('canales', withNotifications ? 'Canales de alerta (con aviso de prueba REAL)' : 'Canales de alerta (solo configuración)', () => checkChannels(withNotifications));
    await ctx.step('reloj', 'Reloj frente a la base de datos', checkClock);
    await ctx.step('recursos', 'Memoria y retraso del event loop', checkResources);
    await ctx.step('rotacion', 'Estado de la rotación de claves', checkRotation);
    await ctx.step('lider', 'Líder del cluster', checkLeader);
    return {};
}

module.exports = { run, validate, describe };
