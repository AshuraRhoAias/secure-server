const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

const keyProvider = require('../crypto/key-provider');
const { ENCRYPTED_COLUMNS } = require('../crypto/encrypted-columns');
const { buildSnapshot, restoreSnapshot, summarize } = require('../backup/snapshot');
const { createArchive, openArchive, readHeader, rewrapArchive } = require('../backup/archive');
const { buildKeyring, openKeyring } = require('../backup/keyring');
const { getPaths } = require('./paths');
const { Maintenance } = require('./maintenance');
const { writeFileAtomic, readJsonIfExists, isPidAlive } = require('./fsutil');

// ROTACIÓN DE CLAVES Y RE-CIFRADO DE DATOS
//
// Orden de operaciones (ver README, "Rotación de claves"):
//
//   1. Bloqueo: lock de mantenimiento (el servidor responde 503 a todo) + lock en la BD +
//      sesiones expiradas + espera a que terminen las peticiones en curso.
//   2. Backup ANTES de re-cifrar: snapshot de toda la BD → comprimido (mejor de brotli/gzip) →
//      cifrado con la clave anterior (AES-256-GCM) → verificado releyéndolo.
//   3. Los backups de meses anteriores se re-cifran con la clave NUEVA; la clave anterior se
//      guarda en el keyring envuelta con la nueva (para poder re-cifrar el backup de este mes
//      el mes que viene).
//   4. Re-cifrado de las columnas registradas en encrypted-columns.js, en UNA transacción:
//      descifra con la clave antigua y cifra con la nueva EN MEMORIA. El texto plano nunca se
//      escribe en disco ni en logs, así que no hay nada que borrar después.
//   5. Confirmación en dos fases: todo lo que debe cambiar de sitio (backups, keyring, .env) se
//      prepara en archivos temporales ANTES del commit y se renombra DESPUÉS. El journal dice en
//      qué fase se cayó el proceso y `recover` termina o deshace el trabajo.
//
// La clave de cifrado de la BD solo se activa cuando el commit de la BD y el nuevo .env están a
// salvo; hasta entonces un fallo deja todo como estaba.

const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));
const sha256 = (text) => crypto.createHash('sha256').update(text).digest('hex');
const nowCompact = () => new Date().toISOString().replace(/[-:]/g, '').replace(/\.\d+Z$/, 'Z'); // 20261101T020000Z
const BATCH = 500;

// Cambia o añade variables en el texto de un .env conservando comentarios y orden.
function applyEnvUpdates(text, updates) {
    const lines = text.split('\n');
    const pending = new Set(Object.keys(updates));

    const out = lines.map(line => {
        const match = /^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=/.exec(line);
        if (match && pending.has(match[1])) {
            pending.delete(match[1]);
            return `${match[1]}=${updates[match[1]]}`;
        }
        return line;
    });

    while (out.length && out[out.length - 1] === '') out.pop();
    if (pending.size) {
        out.push('', '# Claves de cifrado (generadas por la rotación de claves)');
        for (const name of pending) out.push(`${name}=${updates[name]}`);
    }
    return out.join('\n') + '\n';
}

// Descifra con la clave antigua. En modo legacy (claves que dependían de la fecha del día en que
// se cifró cada dato) prueba las fechas candidatas de cada fila: sus propias marcas de tiempo ±1
// día y después, hacia atrás desde hoy, hasta `scanDays` días.
class OldKeyDecryptor {
    constructor({ encryptor, oldSet, env, scanDays, today }) {
        this.encryptor = encryptor;
        this.oldSet = oldSet;
        this.scanDays = scanDays;
        this.legacyHits = 0;
        this.lastGoodDate = null;
        this.today = today;
        this.env = env;
    }

    candidateKeys(row) {
        if (this.oldSet.mode !== 'legacy') return [this.oldSet.encryption];

        const dates = [];
        const add = (d) => { if (d && !dates.includes(d)) dates.push(d); };
        const around = (value) => {
            const t = Date.parse(String(value).replace(' ', 'T') + 'Z');
            if (Number.isNaN(t)) return;
            for (const delta of [0, -1, 1]) add(new Date(t + delta * 86400000).toISOString().split('T')[0]);
        };

        add(this.lastGoodDate);
        for (const col of ['updated_at', 'created_at', 'timestamp', 'last_check']) if (row?.[col]) around(row[col]);
        for (let i = 0; i <= this.scanDays; i++) add(new Date(Date.parse(this.today) - i * 86400000).toISOString().split('T')[0]);

        return dates.map(date => ({ date, key: keyProvider.deriveLegacyKeySet({ baseSeed: this.env.BASE_SEED, jwtSeed: this.env.JWT_SEED, date }).encryption }));
    }

    decrypt(value, row) {
        const candidates = this.candidateKeys(row);

        for (const candidate of candidates) {
            const key = typeof candidate === 'string' ? candidate : candidate.key;
            try {
                const plain = this.encryptor.withKey(key, () => this.encryptor.decrypt(value), { quiet: true });
                if (candidate.date) { this.lastGoodDate = candidate.date; this.legacyHits++; }
                return plain;
            } catch {
                // probar la siguiente
            }
        }
        throw new Error('ninguna clave candidata descifra este valor');
    }
}

class RotationService {
    constructor({ db, encryptor, paths = getPaths(), maintenance = null, logger = console, sleepFn = sleep } = {}) {
        this.db = db;
        this.encryptor = encryptor;
        this.paths = paths;
        this.maintenance = maintenance || new Maintenance(paths);
        this.log = (...args) => logger.log(...args);
        this.sleep = sleepFn;
    }

    // ---------------------------------------------------------------- utilidades

    encryptWith(keyHex, plain) {
        return this.encryptor.withKey(keyHex, () => this.encryptor.encrypt(plain), { quiet: true });
    }

    decryptWith(keyHex, cipher) {
        return this.encryptor.withKey(keyHex, () => this.encryptor.decrypt(cipher), { quiet: true });
    }

    tryDecryptWith(keyHex, cipher) {
        try { return this.decryptWith(keyHex, cipher); } catch { return null; }
    }

    async ensureMetaTable(conn) {
        await conn.query(`CREATE TABLE IF NOT EXISTS crypto_meta (
            id tinyint(4) NOT NULL, key_fingerprint varchar(64) NOT NULL, key_epoch varchar(64) NOT NULL,
            rotation_id varchar(64) DEFAULT NULL,
            rotated_at timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
            PRIMARY KEY (id)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`);
    }

    writeJournal(journal) {
        writeFileAtomic(this.paths.journalFile, JSON.stringify(journal, null, 2));
    }

    readJournal() {
        return readJsonIfExists(this.paths.journalFile);
    }

    listBackupFiles() {
        if (!fs.existsSync(this.paths.backupDir)) return [];
        return fs.readdirSync(this.paths.backupDir).filter(f => f.endsWith('.sbk')).sort().map(f => path.join(this.paths.backupDir, f));
    }

    // Resolver de claves para abrir backups: la época actual + las del keyring
    loadKeyMap(currentSet) {
        const map = new Map([[currentSet.epoch, currentSet.encryption]]);
        const keyring = readJsonIfExists(this.paths.keyringFile);
        if (keyring) {
            for (const [epoch, key] of openKeyring(keyring, currentSet.encryption)) map.set(epoch, key);
        }
        return map;
    }

    // ---------------------------------------------------------------- backups (consulta)

    listBackups() {
        return this.listBackupFiles().map(file => {
            const header = readHeader(fs.readFileSync(file));
            return { file, bytes: fs.statSync(file).size, ...header };
        });
    }

    openBackup(file, currentSet) {
        const keys = this.loadKeyMap(currentSet);
        return openArchive(fs.readFileSync(file), (epoch) => keys.get(epoch));
    }

    // ---------------------------------------------------------------- re-cifrado de tablas

    // Recorre las tablas registradas. Idempotente: una celda que ya se descifra con la clave nueva
    // se deja como está, así que se puede repetir (barrido final, recuperación tras un fallo).
    async reencryptAll(conn, { oldDecryptor, newKey, verifyHashes, collectHashes }) {
        const stats = { cells: 0, alreadyMigrated: 0, tables: {} };

        for (const [table, spec] of Object.entries(ENCRYPTED_COLUMNS)) {
            const cols = spec.columns;
            const pk = spec.primaryKey;
            let lastPk = 0;
            let tableCells = 0;

            for (;;) {
                let rows;
                try {
                    [rows] = await conn.query(
                        `SELECT \`${pk}\`, ${cols.map(c => `\`${c}\``).join(', ')}, ${this.timestampColumns[table].map(c => `CAST(\`${c}\` AS CHAR) AS \`__${c}\``).join(', ') || "NULL AS `__none`"}
                         FROM \`${table}\` WHERE \`${pk}\` > ? ORDER BY \`${pk}\` LIMIT ? FOR UPDATE`,
                        [lastPk, BATCH]
                    );
                } catch (error) {
                    if (error.code === 'ER_NO_SUCH_TABLE') break;
                    throw error;
                }
                if (rows.length === 0) break;

                for (const row of rows) {
                    lastPk = row[pk];
                    const rowDates = Object.fromEntries(this.timestampColumns[table].map(c => [c, row[`__${c}`]]));
                    const changes = {};

                    for (const col of cols) {
                        const value = row[col];
                        if (value === null || value === undefined) continue;

                        if (this.tryDecryptWith(newKey, value) !== null) { stats.alreadyMigrated++; continue; }

                        let plain;
                        try {
                            plain = oldDecryptor.decrypt(value, rowDates);
                        } catch (error) {
                            const hint = spec.regenerable
                                ? ` Es un registro regenerable: puedes borrarlo con "DELETE FROM ${table} WHERE ${pk} = ${row[pk]}" y reintentar.`
                                : ' Si lo escribió un proceso con claves distintas (un script lanzado con otro .env), restaura ese dato desde un backup o corrígelo antes de rotar.';
                            throw new Error(`No se pudo descifrar ${table}.${col} (${pk}=${row[pk]}): ${error.message}. Rotación abortada sin cambios.${hint}`);
                        }

                        const reencrypted = this.encryptWith(newKey, plain);
                        if (this.decryptWith(newKey, reencrypted) !== plain) {
                            throw new Error(`Verificación de ida y vuelta fallida en ${table}.${col} (${pk}=${row[pk]})`);
                        }
                        changes[col] = reencrypted;
                        collectHashes?.set(`${table}:${row[pk]}:${col}`, sha256(plain));
                    }

                    const changed = Object.keys(changes);
                    if (changed.length) {
                        await conn.query(
                            `UPDATE \`${table}\` SET ${changed.map(c => `\`${c}\` = ?`).join(', ')} WHERE \`${pk}\` = ?`,
                            [...changed.map(c => changes[c]), row[pk]]
                        );
                        stats.cells += changed.length;
                        tableCells += changed.length;
                    }
                }
            }
            stats.tables[table] = tableCells;
        }

        // Verificación final dentro de la transacción: todo debe descifrarse con la clave NUEVA
        if (verifyHashes) await this.verifyAll(conn, newKey, verifyHashes);
        return stats;
    }

    async verifyAll(conn, newKey, expectedHashes) {
        for (const [table, spec] of Object.entries(ENCRYPTED_COLUMNS)) {
            let rows;
            try {
                [rows] = await conn.query(`SELECT \`${spec.primaryKey}\`, ${spec.columns.map(c => `\`${c}\``).join(', ')} FROM \`${table}\``);
            } catch (error) {
                if (error.code === 'ER_NO_SUCH_TABLE') continue;
                throw error;
            }
            for (const row of rows) {
                for (const col of spec.columns) {
                    if (row[col] === null) continue;
                    const plain = this.tryDecryptWith(newKey, row[col]);
                    if (plain === null) throw new Error(`Verificación fallida: ${table}.${col} (${spec.primaryKey}=${row[spec.primaryKey]}) no se descifra con la clave nueva`);
                    const expected = expectedHashes.get(`${table}:${row[spec.primaryKey]}:${col}`);
                    if (expected && expected !== sha256(plain)) throw new Error(`Verificación fallida: ${table}.${col} cambió de contenido`);
                }
            }
        }
    }

    // Las columnas registradas deben poder guardar texto cifrado. Si alguna sigue siendo DATETIME
    // (esquema antiguo) los valores cifrados nunca se guardaron bien: hay que migrar antes.
    async assertSchemaReady(conn) {
        const textTypes = ['text', 'mediumtext', 'longtext', 'varchar'];
        for (const [table, spec] of Object.entries(ENCRYPTED_COLUMNS)) {
            const [cols] = await conn.query(
                'SELECT COLUMN_NAME AS name, DATA_TYPE AS type FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ?',
                [table]
            );
            if (cols.length === 0) continue; // tabla inexistente: se omite
            for (const column of spec.columns) {
                const found = cols.find(c => c.name === column);
                if (!found) throw new Error(`Falta la columna ${table}.${column}: aplica las migraciones de database/migrations/`);
                if (!textTypes.includes(found.type.toLowerCase())) {
                    throw new Error(`${table}.${column} es ${found.type.toUpperCase()} y no puede guardar texto cifrado: aplica database/migrations/003_security_logs_encrypted_timestamp.sql antes de rotar`);
                }
            }
        }
    }

    async loadTimestampColumns(conn) {
        this.timestampColumns = {};
        for (const [table, spec] of Object.entries(ENCRYPTED_COLUMNS)) {
            try {
                const [cols] = await conn.query(
                    `SELECT COLUMN_NAME AS name FROM information_schema.COLUMNS
                     WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND COLUMN_NAME IN ('created_at','updated_at','timestamp','last_check')`,
                    [table]
                );
                this.timestampColumns[table] = cols.map(c => c.name);
            } catch {
                this.timestampColumns[table] = [];
            }
            void spec;
        }
    }

    // ---------------------------------------------------------------- análisis y restauración

    // Comprueba, SIN modificar nada ni bloquear el servidor, que todos los datos cifrados se pueden
    // descifrar con las claves actuales. Es el ensayo previo recomendable antes de rotar.
    async analyze({ env = process.env, legacyScanDays = 0 } = {}) {
        const oldSet = keyProvider.deriveFromEnv(env);
        const conn = await this.db.getConnection();
        try {
            await this.assertSchemaReady(conn);
            await this.loadTimestampColumns(conn);
            const decryptor = new OldKeyDecryptor({ encryptor: this.encryptor, oldSet, env, scanDays: legacyScanDays, today: new Date().toISOString().split('T')[0] });
            await conn.query('START TRANSACTION WITH CONSISTENT SNAPSHOT');
            let snapshot;
            try {
                snapshot = await buildSnapshot(conn, { decryptCell: (t, c, v, row) => decryptor.decrypt(v, row) });
            } finally {
                await conn.query('COMMIT');
            }
            const tables = summarize(snapshot);
            snapshot.tables = null;
            return {
                mode: oldSet.mode, epoch: oldSet.epoch, tables,
                rows: Object.values(tables).reduce((a, b) => a + b, 0),
                legacyDecryptions: decryptor.legacyHits,
                ready: oldSet.mode === 'stable' || legacyScanDays > 0
            };
        } finally {
            conn.release();
        }
    }

    // Restaura la BD desde un backup (sustituye el contenido de las tablas). Bloquea el servidor
    // mientras dura y re-cifra con la clave ACTUAL, sea cual sea la época del backup.
    async restore(file, { env = process.env, only = null } = {}) {
        const currentSet = keyProvider.deriveFromEnv(env);
        if (currentSet.mode !== 'stable') throw new Error('Para restaurar hacen falta claves estables (KEY_EPOCH). Rota las claves primero.');

        const { snapshot, header } = this.openBackup(file, currentSet);

        this.maintenance.acquire({ operation: 'restore', reason: path.basename(file) });
        const conn = await this.db.getConnection();
        try {
            const outcome = await restoreSnapshot(conn, snapshot, {
                encryptCell: (table, column, plain) => this.encryptWith(currentSet.encryption, plain),
                only
            });
            await conn.query('UPDATE user_sessions SET expires_at = NOW()');
            return { ...outcome, backupEpoch: header.epoch, backupCreatedAt: header.createdAt };
        } finally {
            conn.release();
            this.maintenance.release();
        }
    }

    // ---------------------------------------------------------------- rotación

    async run(options = {}) {
        const {
            env = process.env,
            writeEnv = true,
            backupKey = 'old',       // 'old' = el backup nuevo se cifra con la clave anterior; 'new' = con la nueva
            drainSeconds = 10,
            legacyScanDays = 0,
            keepBackups = 0,         // 0 = conservar todos
            reloadInProcess = null,  // función a llamar tras activar las claves nuevas (rotación dentro del servidor)
            hooks = {}               // { afterLock, beforeRelease }: el CLI conecta aquí el firewall
        } = options;

        const rotationId = `rot-${nowCompact()}-${crypto.randomBytes(3).toString('hex')}`;
        const result = { rotationId };
        let phase = 'START';
        let lockedMaintenance = false;
        let lockConn = null;
        let conn = null;
        let journal = null;
        const temps = [];

        try {
            // ---- Claves
            const oldSet = keyProvider.deriveFromEnv(env);
            if (oldSet.mode === 'legacy' && !legacyScanDays) {
                throw new Error(
                    'Las claves actuales son de modo legacy (sin KEY_EPOCH): cambian cada día, así que cada dato se cifró con una clave distinta. ' +
                    'Usa --legacy-scan-days N para buscar la clave de cada fila en los últimos N días y migrar todo a claves estables.'
                );
            }
            if (!env.BASE_SEED) throw new Error('Falta BASE_SEED en el entorno');

            const newEpoch = `E${nowCompact()}`;
            const newEncSeed = crypto.randomBytes(32).toString('hex');
            const newJwtSeed = crypto.randomBytes(32).toString('hex');
            const newSet = keyProvider.deriveStableKeySet({ baseSeed: env.BASE_SEED, encryptionSeed: newEncSeed, jwtSeed: newJwtSeed, epoch: newEpoch });
            Object.assign(result, { mode: oldSet.mode, oldEpoch: oldSet.epoch, newEpoch });

            // ---- 1. Bloqueo
            phase = 'LOCK';
            this.maintenance.acquire({ operation: 'key-rotation', reason: rotationId });
            lockedMaintenance = true;
            this.log('🔒 Modo mantenimiento activado: el servidor rechaza todas las peticiones');

            lockConn = await this.db.getConnection();
            const [[lockRow]] = await lockConn.query("SELECT GET_LOCK('secure_server_rotation', 0) AS got");
            if (lockRow.got !== 1) throw new Error('Otra rotación tiene el bloqueo de la base de datos');

            await hooks.afterLock?.();

            conn = await this.db.getConnection();
            await this.ensureMetaTable(conn);
            await this.assertSchemaReady(conn);
            await this.loadTimestampColumns(conn);
            await conn.query('UPDATE user_sessions SET expires_at = NOW()'); // ninguna sesión sobrevive a la rotación
            if (drainSeconds > 0) {
                this.log(`⏳ Esperando ${drainSeconds}s a que terminen las peticiones en curso...`);
                await this.sleep(drainSeconds * 1000);
            }

            // ---- 2. Backup previo (con la clave anterior)
            phase = 'BACKUP';
            const decryptor = new OldKeyDecryptor({ encryptor: this.encryptor, oldSet, env, scanDays: legacyScanDays, today: new Date().toISOString().split('T')[0] });

            await conn.query('START TRANSACTION WITH CONSISTENT SNAPSHOT');
            const snapshot = await buildSnapshot(conn, {
                decryptCell: (table, column, value, row) => decryptor.decrypt(value, row)
            });
            await conn.query('COMMIT');

            const backupUnderOld = backupKey === 'old' && oldSet.mode === 'stable';
            const backupSet = backupUnderOld ? oldSet : newSet;
            const tables = summarize(snapshot);
            const archive = createArchive(snapshot, { encryptionKeyHex: backupSet.encryption, epoch: backupSet.epoch, tables });
            const backupFile = path.join(this.paths.backupDir, `backup-${nowCompact()}-${String(oldSet.epoch).replace(/[^A-Za-z0-9._-]/g, '')}-to-${newEpoch}.sbk`);
            writeFileAtomic(backupFile, archive, 0o600);

            // Releer y comprobar antes de continuar: un backup que no se puede abrir no es un backup
            const verifyKeys = new Map([[backupSet.epoch, backupSet.encryption]]);
            const reopened = openArchive(fs.readFileSync(backupFile), (epoch) => verifyKeys.get(epoch));
            for (const [name, count] of Object.entries(tables)) {
                if (reopened.snapshot.tables[name].rows.length !== count) throw new Error(`Verificación del backup fallida en la tabla ${name}`);
            }
            snapshot.tables = null; // soltar la referencia al texto plano cuanto antes
            Object.assign(result, {
                backup: { file: backupFile, ...readHeader(fs.readFileSync(backupFile)), bytes: archive.length, encryptedWith: backupUnderOld ? 'clave anterior' : 'clave nueva' }
            });
            this.log(`💾 Backup creado: ${path.basename(backupFile)} (${archive.length} bytes, ${reopened.header.compression}, ${(100 * archive.length / reopened.header.rawBytes).toFixed(1)}% del original)`);

            // ---- 3. Preparar backups anteriores, keyring y .env en temporales
            phase = 'PREPARE';
            const knownKeys = oldSet.mode === 'stable' ? this.loadKeyMap(oldSet) : new Map();
            const rewraps = [];
            const stillNeeded = new Map(); // época -> clave, de los backups que seguirán con clave antigua
            if (backupUnderOld) stillNeeded.set(oldSet.epoch, oldSet.encryption);

            for (const file of this.listBackupFiles().filter(f => f !== backupFile)) {
                const buffer = fs.readFileSync(file);
                const header = readHeader(buffer);
                if (header.epoch === newEpoch) continue;

                const fromKey = knownKeys.get(header.epoch);
                if (!fromKey) {
                    this.log(`⚠️ ${path.basename(file)}: no hay clave para la época ${header.epoch}; se deja sin tocar`);
                    (result.untouchedBackups ||= []).push(path.basename(file));
                    continue;
                }

                const rewrapped = rewrapArchive(buffer, { fromKeyHex: fromKey, toKeyHex: newSet.encryption, toEpoch: newEpoch });
                const check = openArchive(rewrapped, (epoch) => (epoch === newEpoch ? newSet.encryption : null));
                if (JSON.stringify(readHeader(rewrapped).tables) !== JSON.stringify(header.tables) || !check.snapshot) {
                    throw new Error(`Verificación del re-cifrado fallida: ${path.basename(file)}`);
                }

                const tmp = `${file}.new`;
                writeFileAtomic(tmp, rewrapped, 0o600);
                temps.push(tmp);
                rewraps.push({ tmp, final: file });
            }
            result.rewrappedBackups = rewraps.length;

            const keyringTmp = `${this.paths.keyringFile}.new`;
            if (stillNeeded.size > 0) {
                writeFileAtomic(keyringTmp, JSON.stringify(buildKeyring(stillNeeded, { wrapKeyHex: newSet.encryption, wrapEpoch: newEpoch }), null, 2), 0o600);
                temps.push(keyringTmp);
            }

            const envUpdates = { ENCRYPTION_SEED: newEncSeed, JWT_SEED: newJwtSeed, KEY_EPOCH: newEpoch };
            const envPending = `${this.paths.envFile}.pending`;
            const manualEnvFile = path.join(this.paths.dataDir, `new-env-${newEpoch}.txt`);
            if (writeEnv) {
                const current = fs.existsSync(this.paths.envFile) ? fs.readFileSync(this.paths.envFile, 'utf8') : '';
                writeFileAtomic(envPending, applyEnvUpdates(current, envUpdates), 0o600);
                temps.push(envPending);
            } else {
                writeFileAtomic(manualEnvFile, Object.entries(envUpdates).map(([k, v]) => `${k}=${v}`).join('\n') + '\n', 0o600);
                result.manualEnvFile = manualEnvFile;
            }

            journal = {
                id: rotationId, phase: 'PREPARED', startedAt: new Date().toISOString(),
                oldEpoch: oldSet.epoch, newEpoch, oldFingerprint: oldSet.fingerprint, newFingerprint: newSet.fingerprint,
                backupFile, rewraps,
                keyring: stillNeeded.size > 0 ? { tmp: keyringTmp, final: this.paths.keyringFile } : { remove: this.paths.keyringFile },
                env: writeEnv ? { tmp: envPending, final: this.paths.envFile } : { manualFile: manualEnvFile }
            };
            this.writeJournal(journal);
            this.maintenance.setPhase('PREPARED');

            // ---- 4. Re-cifrado en una transacción
            phase = 'REENCRYPT';
            const hashes = new Map();
            await conn.query('SET SESSION innodb_lock_wait_timeout = 120');
            await conn.beginTransaction();
            const stats = await this.reencryptAll(conn, { oldDecryptor: decryptor, newKey: newSet.encryption, verifyHashes: hashes, collectHashes: hashes });
            await conn.query(
                `INSERT INTO crypto_meta (id, key_fingerprint, key_epoch, rotation_id) VALUES (1, ?, ?, ?)
                 ON DUPLICATE KEY UPDATE key_fingerprint = VALUES(key_fingerprint), key_epoch = VALUES(key_epoch), rotation_id = VALUES(rotation_id)`,
                [newSet.fingerprint, newEpoch, rotationId]
            );
            hashes.clear();

            // ---- 5. Commit (punto de no retorno)
            phase = 'COMMIT';
            await conn.commit();
            journal.phase = 'COMMITTED';
            this.writeJournal(journal);
            this.maintenance.setPhase('COMMITTED');
            Object.assign(result, { cellsReencrypted: stats.cells, perTable: stats.tables, legacyDecryptions: decryptor.legacyHits });
            this.log(`🔐 Datos re-cifrados con la clave nueva: ${stats.cells} valores`);

            // ---- 6. Finalizar: renombrar temporales (los pasos son idempotentes)
            phase = 'FINALIZE';
            this.finalizeFiles(journal);

            // Barrido: cualquier proceso rezagado que escribiera con la clave antigua entre medias
            if (drainSeconds > 0) await this.sleep(Math.min(drainSeconds, 5) * 1000);
            await conn.beginTransaction();
            const sweep = await this.reencryptAll(conn, { oldDecryptor: decryptor, newKey: newSet.encryption });
            await conn.commit();
            result.sweepRepaired = sweep.cells;
            if (sweep.cells > 0) this.log(`🧹 Barrido final: ${sweep.cells} valores escritos con la clave antigua fueron re-cifrados`);

            journal.phase = 'DONE';
            journal.finishedAt = new Date().toISOString();
            this.writeJournal(journal);

            if (keepBackups > 0) result.prunedBackups = this.pruneBackups(keepBackups);

            // ---- 7. Activar y reabrir
            phase = 'RELEASE';
            if (reloadInProcess) await reloadInProcess();
            await hooks.beforeRelease?.();

            if (writeEnv || reloadInProcess) {
                this.maintenance.release();
                lockedMaintenance = false;
                this.log('🔓 Modo mantenimiento desactivado');
            } else {
                result.stillLocked = true;
                this.log(`⚠️ Las claves nuevas NO están activas en el entorno. Aplica las variables de ${manualEnvFile} y ejecuta: npm run rotate-keys -- finish`);
            }

            await lockConn.query("SELECT RELEASE_LOCK('secure_server_rotation')");
            return result;

        } catch (error) {
            error.rotationPhase = phase;
            let committed = journal?.phase === 'COMMITTED' || ['FINALIZE', 'RELEASE'].includes(phase);

            // Si falló el propio COMMIT no sabemos si la BD llegó a confirmar (p. ej. se perdió la
            // respuesta). Deshacer a ciegas dejaría los datos con la clave nueva y el .env con la
            // antigua, así que se pregunta a la BD con una conexión nueva.
            if (phase === 'COMMIT' && journal) {
                committed = await this.probeCommitted(journal);
                if (committed) { journal.phase = 'COMMITTED'; try { this.writeJournal(journal); } catch { /* sin disco */ } }
            }

            if (committed) {
                // Los datos YA están cifrados con la clave nueva: no se puede deshacer. Se queda
                // cerrado y `recover` terminará de colocar los archivos.
                error.message = `${error.message} [la BD ya usa las claves nuevas; el servidor sigue en mantenimiento: ejecuta "npm run rotate-keys -- recover"]`;
                throw error;
            }

            try { if (conn) await conn.rollback(); } catch { /* ya sin transacción */ }
            for (const tmp of temps) { try { fs.unlinkSync(tmp); } catch { /* ya no existe */ } }
            if (result.manualEnvFile) { try { fs.unlinkSync(result.manualEnvFile); } catch { /* ya no existe */ } }
            if (journal) { journal.phase = 'ABORTED'; journal.error = error.message; try { this.writeJournal(journal); } catch { /* sin disco */ } }
            if (lockedMaintenance) this.maintenance.release(); // la BD no cambió: se puede reabrir con seguridad
            this.log(`❌ Rotación abortada en la fase ${phase}: ${error.message}. No se ha cambiado nada.`);
            throw error;

        } finally {
            try { if (conn) conn.release(); } catch { /* ya liberada */ }
            try { if (lockConn) { await lockConn.query("SELECT RELEASE_LOCK('secure_server_rotation')"); lockConn.release(); } } catch { /* ya liberada */ }
        }
    }

    async probeCommitted(journal) {
        try {
            const probe = await this.db.getConnection();
            try {
                const [rows] = await probe.query('SELECT key_fingerprint FROM crypto_meta WHERE id = 1');
                return rows[0]?.key_fingerprint === journal.newFingerprint;
            } finally {
                probe.release();
            }
        } catch {
            return true; // sin poder comprobarlo, lo seguro es NO deshacer: que decida `recover`
        }
    }

    // Coloca en su sitio lo preparado antes del commit. Idempotente: se puede repetir.
    finalizeFiles(journal) {
        for (const { tmp, final } of journal.rewraps) {
            if (fs.existsSync(tmp)) fs.renameSync(tmp, final);
        }
        if (journal.keyring.tmp && fs.existsSync(journal.keyring.tmp)) fs.renameSync(journal.keyring.tmp, journal.keyring.final);
        if (journal.keyring.remove && fs.existsSync(journal.keyring.remove)) fs.unlinkSync(journal.keyring.remove);
        if (journal.env.tmp && fs.existsSync(journal.env.tmp)) fs.renameSync(journal.env.tmp, journal.env.final);
    }

    pruneBackups(keep) {
        const backups = this.listBackups().sort((a, b) => a.createdAt.localeCompare(b.createdAt));
        const toDelete = backups.slice(0, Math.max(0, backups.length - keep));
        toDelete.forEach(b => fs.unlinkSync(b.file));
        return toDelete.map(b => path.basename(b.file));
    }

    // ---------------------------------------------------------------- recuperación

    // Borra temporales huérfanos (un proceso que muere tras crearlos y antes de escribir su journal
    // los deja ahí; `.env.pending` contiene las semillas nuevas en claro). Solo se llama cuando
    // ninguna rotación está en curso. `keep` son rutas que NO se deben tocar.
    cleanStrayTemps(keep = []) {
        const candidates = [`${this.paths.envFile}.pending`, `${this.paths.keyringFile}.new`];
        for (const dir of [this.paths.backupDir, this.paths.dataDir]) {
            if (!fs.existsSync(dir)) continue;
            for (const f of fs.readdirSync(dir)) {
                if (f.endsWith('.sbk.new') || /^new-env-.*\.txt$/.test(f) || f.includes('.tmp-')) candidates.push(path.join(dir, f));
            }
        }
        const removed = [];
        for (const file of candidates.filter(f => !keep.includes(f))) {
            try { fs.unlinkSync(file); removed.push(path.basename(file)); } catch { /* no existía */ }
        }
        return removed;
    }

    // Termina o deshace una rotación interrumpida, según hasta dónde llegó.
    async recover({ env = process.env, force = false } = {}) {
        const journal = this.readJournal();
        const lock = this.maintenance.read();

        // Si quien tiene el lock sigue vivo, hay una rotación EN CURSO: tocar sus temporales o su
        // lock la rompería a mitad. (En otro host no se puede saber; hace falta `force`.)
        if (lock && lock.pid !== process.pid && !force) {
            if (lock.host === os.hostname() && isPidAlive(lock.pid)) {
                throw new Error(`Hay una ${lock.operation} en curso (pid ${lock.pid}). Espera a que termine. Si está colgada, comprueba primero que ese pid es realmente la rotación (los pids se reutilizan), ciérrala y vuelve a ejecutar recover.`);
            }
            if (lock.host !== os.hostname()) {
                throw new Error(`El lock lo tiene un proceso de otro host (${lock.host}): no se puede saber si sigue vivo. Si estás seguro de que murió, usa --force.`);
            }
        }

        if (!journal) {
            const removed = this.cleanStrayTemps();
            if (lock) return { action: 'lock-without-journal', lock, removedTemps: removed, message: 'Hay un lock pero ningún journal: comprueba que ningún proceso lo use y borra el lock manualmente.' };
            return { action: 'nothing', removedTemps: removed, message: 'No hay nada que recuperar' };
        }

        if (journal.phase === 'DONE' || journal.phase === 'ABORTED') {
            // --no-write-env: la BD ya usa las claves nuevas pero el entorno aún no. NO se reabre.
            if (journal.phase === 'DONE' && journal.env?.manualFile && fs.existsSync(journal.env.manualFile)) {
                return { action: 'awaiting-env', stillLocked: true, message: `Aplica las variables de ${journal.env.manualFile} y ejecuta: npm run rotate-keys -- finish` };
            }
            const removed = this.cleanStrayTemps();
            if (lock) this.maintenance.release();
            return { action: 'already-finished', phase: journal.phase, releasedLock: !!lock, removedTemps: removed };
        }

        // PREPARED o COMMITTED: ¿la BD llegó a confirmar? Lo dice la huella guardada en crypto_meta.
        const conn = await this.db.getConnection();
        let committed = journal.phase === 'COMMITTED';
        try {
            if (!committed) {
                const [rows] = await conn.query('SELECT key_fingerprint FROM crypto_meta WHERE id = 1').catch(() => [[]]);
                committed = rows[0]?.key_fingerprint === journal.newFingerprint;
            }
        } finally {
            conn.release();
        }

        if (committed) {
            this.finalizeFiles(journal);
            journal.phase = 'DONE';
            journal.finishedAt = new Date().toISOString();
            this.writeJournal(journal);

            if (journal.env.manualFile) {
                return { action: 'finalized', stillLocked: true, message: `Aplica las variables de ${journal.env.manualFile} y ejecuta: npm run rotate-keys -- finish` };
            }
            this.maintenance.release();
            return { action: 'finalized', message: 'La rotación se había confirmado en la BD: se han colocado los archivos y se ha reabierto el servidor' };
        }

        // No llegó a confirmar: la BD sigue con la clave antigua. Deshacer.
        for (const tmp of [...journal.rewraps.map(r => r.tmp), journal.keyring.tmp, journal.env.tmp, journal.env.manualFile]) {
            if (tmp) { try { fs.unlinkSync(tmp); } catch { /* ya no existe */ } }
        }
        journal.phase = 'ABORTED';
        this.writeJournal(journal);
        this.maintenance.release();
        void env;
        return { action: 'rolled-back', message: 'La rotación no había confirmado en la BD: se han descartado los temporales y el servidor se reabre con las claves anteriores' };
    }

    // Para rotaciones con --no-write-env: comprueba que el entorno ya tiene las claves nuevas y reabre.
    async finish({ env = process.env } = {}) {
        const conn = await this.db.getConnection();
        try {
            const [rows] = await conn.query('SELECT key_fingerprint, key_epoch FROM crypto_meta WHERE id = 1');
            const set = keyProvider.deriveFromEnv(env);
            if (!rows[0] || rows[0].key_fingerprint !== set.fingerprint) {
                throw new Error('Las claves del entorno no coinciden con las de la base de datos: aplica ENCRYPTION_SEED, JWT_SEED y KEY_EPOCH nuevos y vuelve a intentarlo');
            }
            const journal = this.readJournal();
            if (journal?.env?.manualFile) { try { fs.unlinkSync(journal.env.manualFile); } catch { /* ya borrado */ } }
            this.maintenance.release();
            return { released: true, epoch: rows[0].key_epoch };
        } finally {
            conn.release();
        }
    }
}

module.exports = { RotationService, applyEnvUpdates, OldKeyDecryptor };
