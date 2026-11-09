const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { pipeline } = require('stream/promises');
const { Transform } = require('stream');
const storage = require('./storage');
const { cipherSize } = require('./file-cipher');

// Copias de seguridad de los ARCHIVOS cifrados (FILES_DIR). Complementan al backup de la base de datos
// (src/backup, `npm run rotate-keys` crea y conserva copias de la BD): para restaurar hacen falta las DOS cosas,
// porque las claves de cada archivo están (envueltas) en la BD y los bytes están en disco.
//
// Cómo funciona:
//   - Los archivos YA están cifrados (AES-256-GCM, clave propia): la copia no necesita volver a cifrar nada y
//     el destino solo ve bytes aleatorios con nombres UUID. El índice (index.json) no contiene nombres reales.
//   - Es INCREMENTAL: solo se copia lo nuevo. Cada copia se verifica con SHA-256 del texto cifrado.
//   - Lo borrado en origen (el usuario borra un archivo) se CONSERVA en la copia FILES_BACKUP_RETENTION_DAYS días
//     (30 por defecto) y después se elimina: protege frente a borrados por error o malintencionados.
//   - Cruza lo que hay en disco con la BD: detecta archivos que la BD cree tener y no existen (pérdida de datos),
//     con tamaño incorrecto (truncados) y huérfanos (sin fila).
//
// Destino: un directorio (disco aparte, NFS, volumen montado, o un bucket montado con rclone/s3fs/gcsfuse). Para una
// copia en otra región/proveedor, sincroniza ese directorio con `rclone sync` (los datos siguen cifrados).

const INDEX = 'index.json';
const UUID_FILE = /^([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\.enc$/;

function backupRoot() {
    const dir = process.env.FILES_BACKUP_DIR;
    if (!dir) throw new Error('Define FILES_BACKUP_DIR (directorio de destino de las copias)');
    const target = path.resolve(dir);
    const source = storage.root();
    if (target === source || target.startsWith(source + path.sep) || source.startsWith(target + path.sep)) {
        throw new Error('FILES_BACKUP_DIR no puede estar dentro de FILES_DIR (ni contenerlo): una copia en el mismo sitio no protege de nada');
    }
    return target;
}

const retentionMs = () => {
    const days = Number(process.env.FILES_BACKUP_RETENTION_DAYS);
    return (Number.isFinite(days) && days >= 0 ? days : 30) * 24 * 3600 * 1000;
};

const sourcePath = (name) => storage.finalPath(name);
const backupPath = (root, name) => path.join(root, 'files', name.slice(0, 2), `${name}.enc`);

function listSource() {
    const base = path.join(storage.root(), 'files');
    const names = [];
    if (!fs.existsSync(base)) return names;
    for (const shard of fs.readdirSync(base, { withFileTypes: true })) {
        if (!shard.isDirectory()) continue;
        for (const entry of fs.readdirSync(path.join(base, shard.name))) {
            const match = UUID_FILE.exec(entry);
            if (match) names.push(match[1]);
        }
    }
    return names;
}

async function sha256File(file) {
    const hash = crypto.createHash('sha256');
    await pipeline(fs.createReadStream(file), hash);
    return hash.digest('hex');
}

function readIndex(root) {
    try {
        return JSON.parse(fs.readFileSync(path.join(root, INDEX), 'utf8'));
    } catch {
        return { version: 1, files: {} };
    }
}

function writeIndex(root, index) {
    fs.mkdirSync(root, { recursive: true, mode: 0o700 });
    const tmp = path.join(root, `${INDEX}.${process.pid}.tmp`);
    fs.writeFileSync(tmp, JSON.stringify(index), { mode: 0o600 });
    fs.renameSync(tmp, path.join(root, INDEX));
}

// Copia con hash en el mismo pase; deja el archivo en su sitio solo si se escribió entero
async function copyWithHash(from, to) {
    fs.mkdirSync(path.dirname(to), { recursive: true, mode: 0o700 });
    const tmp = `${to}.${process.pid}.part`;
    const hash = crypto.createHash('sha256');
    let size = 0;
    const tap = new Transform({ transform(chunk, _e, cb) { hash.update(chunk); size += chunk.length; cb(null, chunk); } });
    try {
        await pipeline(fs.createReadStream(from), tap, fs.createWriteStream(tmp, { flags: 'wx', mode: 0o600 }));
        fs.renameSync(tmp, to);
    } catch (error) {
        fs.rmSync(tmp, { force: true });
        throw error;
    }
    return { size, sha256: hash.digest('hex') };
}

// Filas de user_files: { storage_name, size_bytes } (paginado por id)
async function* dbRows(db) {
    let last = 0;
    for (;;) {
        const [rows] = await db.query(
            'SELECT id, storage_name, size_bytes FROM user_files WHERE id > ? ORDER BY id LIMIT 5000', [last]);
        if (rows.length === 0) return;
        for (const row of rows) yield row;
        last = rows[rows.length - 1].id;
    }
}

// Cruza BD y disco de origen
async function reconcile(db) {
    const onDisk = new Map(listSource().map(name => {
        try { return [name, fs.statSync(sourcePath(name)).size]; } catch { return [name, null]; }
    }));
    const referenced = new Set();
    const missing = [], wrongSize = [];

    for await (const row of dbRows(db)) {
        referenced.add(row.storage_name);
        const size = onDisk.get(row.storage_name);
        if (size === undefined || size === null) missing.push(row.storage_name);
        else if (size !== cipherSize(Number(row.size_bytes))) wrongSize.push(row.storage_name);
    }
    const orphans = [...onDisk.keys()].filter(name => !referenced.has(name));
    return { referenced, missing, wrongSize, orphans };
}

async function backup({ db, log = () => {} } = {}) {
    const root = backupRoot();
    const index = readIndex(root);
    const now = Date.now();
    const report = { copied: 0, bytesCopied: 0, alreadyBackedUp: 0, pruned: 0, missingFiles: [], wrongSize: [], changedInSource: [], orphans: 0, errors: [] };

    const check = await reconcile(db);
    Object.assign(report, { missingFiles: check.missing, wrongSize: check.wrongSize, orphans: check.orphans.length });

    const present = new Set();
    for (const name of listSource()) {
        present.add(name);
        const known = index.files[name];
        try {
            const stat = fs.statSync(sourcePath(name));
            if (known && fs.existsSync(backupPath(root, name))) {
                // Los archivos se escriben UNA vez y nunca cambian. Si el de origen ya no mide lo que midió al copiarlo,
                // está dañado: NO se sobrescribe la copia buena con él (sería convertir una avería en pérdida de datos).
                if (known.size !== stat.size) {
                    report.changedInSource.push(name);
                    continue;
                }
                known.lastSeen = now;
                delete known.missingSince;
                report.alreadyBackedUp++;
                continue;
            }
            const { size, sha256 } = await copyWithHash(sourcePath(name), backupPath(root, name));
            index.files[name] = { size, sha256, firstBackedUp: known?.firstBackedUp || now, lastSeen: now };
            report.copied++;
            report.bytesCopied += size;
            log(`copiado ${name} (${size} bytes)`);
        } catch (error) {
            if (error.code === 'ENOENT') continue; // lo borraron mientras copiábamos
            report.errors.push({ name, error: error.code || error.message });
        }
    }

    // Lo que ya no existe en origen se conserva `retention` y después se elimina
    for (const [name, entry] of Object.entries(index.files)) {
        if (present.has(name)) continue;
        entry.missingSince ??= now;
        if (now - entry.missingSince >= retentionMs()) {
            fs.rmSync(backupPath(root, name), { force: true });
            delete index.files[name];
            report.pruned++;
        }
    }

    index.lastBackupAt = new Date(now).toISOString();
    writeIndex(root, index);
    return report;
}

// Comprueba la copia: integridad de cada archivo y cobertura de la BD
async function verify({ db } = {}) {
    const root = backupRoot();
    const index = readIndex(root);
    const report = { checked: 0, corrupt: [], missingInBackup: [], notBackedUp: [], lastBackupAt: index.lastBackupAt || null };

    for (const [name, entry] of Object.entries(index.files)) {
        const file = backupPath(root, name);
        report.checked++;
        if (!fs.existsSync(file)) { report.missingInBackup.push(name); continue; }
        if (fs.statSync(file).size !== entry.size || (await sha256File(file)) !== entry.sha256) report.corrupt.push(name);
    }
    if (db) {
        for await (const row of dbRows(db)) if (!index.files[row.storage_name]) report.notBackedUp.push(row.storage_name);
    }
    return report;
}

// Restaura en `target` (FILES_DIR por defecto) lo que falte. Nunca pisa un archivo existente salvo con force.
// Cada archivo se verifica contra el hash del índice ANTES de colocarlo: una copia dañada no se restaura.
async function restore({ db, target = storage.root(), force = false, onlyReferenced = true, log = () => {} } = {}) {
    const root = backupRoot();
    const index = readIndex(root);
    const report = { restored: 0, skippedExisting: 0, skippedUnreferenced: 0, refused: [] };

    const referenced = onlyReferenced && db ? new Set() : null;
    if (referenced) for await (const row of dbRows(db)) referenced.add(row.storage_name);

    for (const [name, entry] of Object.entries(index.files)) {
        if (referenced && !referenced.has(name)) { report.skippedUnreferenced++; continue; }
        const destination = path.join(target, 'files', name.slice(0, 2), `${name}.enc`);
        if (fs.existsSync(destination) && !force) { report.skippedExisting++; continue; }

        const from = backupPath(root, name);
        if (!fs.existsSync(from)) { report.refused.push({ name, reason: 'no está en la copia' }); continue; }

        const tmp = `${destination}.${process.pid}.part`;
        try {
            const copied = await copyWithHash(from, tmp);
            if (copied.sha256 !== entry.sha256 || copied.size !== entry.size) {
                fs.rmSync(tmp, { force: true });
                report.refused.push({ name, reason: 'la copia está dañada (hash distinto)' });
                continue;
            }
            fs.mkdirSync(path.dirname(destination), { recursive: true, mode: 0o700 });
            fs.renameSync(tmp, destination);
            report.restored++;
            log(`restaurado ${name}`);
        } catch (error) {
            fs.rmSync(tmp, { force: true });
            report.refused.push({ name, reason: error.code || error.message });
        }
    }
    return report;
}

module.exports = { backup, verify, restore, reconcile, backupRoot, readIndex, writeIndex };
