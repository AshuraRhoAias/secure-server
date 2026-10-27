const { ENCRYPTED_COLUMNS, isExternal } = require('../crypto/encrypted-columns');

// Snapshot lógico de toda la base de datos.
//
// Las columnas cifradas se guardan DESCIFRADAS dentro del snapshot (solo en memoria: el snapshot
// se comprime y se cifra por completo antes de tocar el disco, ver archive.js). Así la clave
// exterior del archivo es lo único que protege el contenido, y re-cifrar un backup con claves
// nuevas basta con cambiar esa capa exterior. Si dentro quedara texto cifrado con la clave
// antigua, cada backup seguiría necesitando la clave antigua para siempre.

const FORMAT_VERSION = 1;
const INSERT_BATCH = 200;
// Se omiten al restaurar: las sesiones caducaron y la huella de claves pertenece al entorno actual
const DEFAULT_RESTORE_SKIP = ['crypto_meta', 'user_sessions'];

const q = (identifier) => `\`${String(identifier).replace(/`/g, '``')}\``;

function encodeCell(value) {
    return Buffer.isBuffer(value) ? { $b64: value.toString('base64') } : value;
}

function decodeCell(value) {
    return value && typeof value === 'object' && '$b64' in value ? Buffer.from(value.$b64, 'base64') : value;
}

async function listTables(conn) {
    const [rows] = await conn.query("SHOW FULL TABLES WHERE Table_type = 'BASE TABLE'");
    return rows.map(row => Object.values(row)[0]);
}

// decryptCell(table, column, ciphertext, row) -> texto plano
async function buildSnapshot(conn, { decryptCell }) {
    const snapshot = { formatVersion: FORMAT_VERSION, createdAt: new Date().toISOString(), tables: {} };

    for (const table of await listTables(conn)) {
        const [[createRow]] = await conn.query(`SHOW CREATE TABLE ${q(table)}`);
        const [rows, fields] = await conn.query({ sql: `SELECT * FROM ${q(table)}`, dateStrings: true, rowsAsArray: true });

        const columns = fields.map(f => f.name);
        const encrypted = (ENCRYPTED_COLUMNS[table]?.columns || []).filter(c => columns.includes(c));
        const encryptedIndexes = encrypted.map(c => columns.indexOf(c));
        const pkIndex = columns.indexOf(ENCRYPTED_COLUMNS[table]?.primaryKey || 'id');

        const outRows = rows.map(row => row.map((value, i) => {
            if (value !== null && encryptedIndexes.includes(i) && !isExternal(value)) {
                try {
                    // La fila completa permite al descifrador legacy deducir la clave por fecha
                    const rowObject = Object.fromEntries(columns.map((c, idx) => [c, row[idx]]));
                    return decryptCell(table, columns[i], value, rowObject);
                } catch (error) {
                    // Sin contenido en el mensaje: solo dónde está el problema
                    const pk = columns[pkIndex] || 'id';
                    const hint = ENCRYPTED_COLUMNS[table]?.regenerable
                        ? ` Es un registro regenerable: puedes borrarlo con "DELETE FROM ${table} WHERE ${pk} = ${row[pkIndex]}" y reintentar.`
                        : ' Si lo escribió un proceso con claves distintas (un script lanzado con otro .env), restaura ese dato desde un backup o corrígelo antes de rotar.';
                    throw new Error(`No se pudo descifrar ${table}.${columns[i]} (${pk}=${row[pkIndex]}): ${error.message}.${hint}`);
                }
            }
            return encodeCell(value);
        }));

        snapshot.tables[table] = { createSql: createRow['Create Table'], columns, encrypted, rows: outRows };
    }

    return snapshot;
}

function summarize(snapshot) {
    return Object.fromEntries(Object.entries(snapshot.tables).map(([name, t]) => [name, t.rows.length]));
}

// Sustituye el contenido de las tablas por el del snapshot, re-cifrando las columnas cifradas con
// la clave ACTUAL (encryptCell). Todo en una transacción: o se restaura todo o nada.
async function restoreSnapshot(conn, snapshot, { encryptCell, skip = DEFAULT_RESTORE_SKIP, only = null }) {
    if (snapshot.formatVersion !== FORMAT_VERSION) throw new Error(`Versión de snapshot no soportada: ${snapshot.formatVersion}`);

    const existing = new Set(await listTables(conn));
    const names = Object.keys(snapshot.tables).filter(n => !skip.includes(n) && (!only || only.includes(n)));

    for (const name of names) {
        if (!existing.has(name)) await conn.query(snapshot.tables[name].createSql); // DDL: commit implícito, antes de la transacción
    }

    const restored = {};
    await conn.query('SET FOREIGN_KEY_CHECKS = 0');
    await conn.beginTransaction();
    try {
        for (const name of names) {
            const { columns, encrypted, rows } = snapshot.tables[name];
            const encryptedIndexes = encrypted.map(c => columns.indexOf(c));

            await conn.query(`DELETE FROM ${q(name)}`);

            for (let i = 0; i < rows.length; i += INSERT_BATCH) {
                const batch = rows.slice(i, i + INSERT_BATCH).map(row => row.map((value, idx) =>
                    value !== null && encryptedIndexes.includes(idx) && !isExternal(value) ? encryptCell(name, columns[idx], value) : decodeCell(value)
                ));
                await conn.query(`INSERT INTO ${q(name)} (${columns.map(q).join(', ')}) VALUES ?`, [batch]);
            }
            restored[name] = rows.length;
        }
        await conn.commit();
    } catch (error) {
        await conn.rollback();
        throw error;
    } finally {
        await conn.query('SET FOREIGN_KEY_CHECKS = 1');
    }

    return { restored, skipped: Object.keys(snapshot.tables).filter(n => !names.includes(n)) };
}

module.exports = { buildSnapshot, restoreSnapshot, summarize, DEFAULT_RESTORE_SKIP };
