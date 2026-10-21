#!/usr/bin/env node
// Vuelve a pasar el antivirus por los archivos YA guardados (las firmas de ClamAV se actualizan cada día:
// algo que ayer estaba limpio puede no estarlo hoy; y los archivos anteriores a la activación del antivirus
// nunca se escanearon). Descifra cada archivo en streaming, lo envía a clamd y actualiza `scan_status`.
//
//   npm run rescan-files                       solo los que no están "clean"
//   npm run rescan-files -- --all              todos
//   npm run rescan-files -- --delete-infected  borra (fila y archivo) lo que dé positivo
//   npm run rescan-files -- --limit 500        como máximo N archivos por ejecución
//
// Requiere clamd accesible (CLAMAV_HOST/CLAMAV_PORT o CLAMAV_SOCKET). Código de salida 3 si encuentra malware.

require('dotenv').config({ path: process.env.ENV_FILE || require('path').join(__dirname, '../.env') });

const db = require('../src/config/database');
const tripleEncryptor = require('../src/crypto/tripleEncryptor');
const cipher = require('../src/files/file-cipher');
const storage = require('../src/files/storage');
const av = require('../src/files/av-scanner');
const events = require('../src/security/security-events.service');

const args = process.argv.slice(2);
const all = args.includes('--all');
const deleteInfected = args.includes('--delete-infected');
const limitIndex = args.indexOf('--limit');
const limit = limitIndex >= 0 ? Math.max(1, Number(args[limitIndex + 1]) || 1000) : 1000;

async function main() {
    const [files] = await db.query(
        `SELECT id, user_id, storage_name, key_encrypted, size_bytes, scan_status
         FROM user_files WHERE (? = 1 OR scan_status <> 'clean') ORDER BY id LIMIT ${require('../src/config/sql').sqlInt(limit)}`,
        [all ? 1 : 0]
    );

    const summary = { scanned: 0, clean: 0, infected: [], errors: [], deleted: 0 };
    for (const file of files) {
        const key = Buffer.from(tripleEncryptor.decrypt(file.key_encrypted), 'hex');
        const verdict = await av.scanBuffers(cipher.decryptRange({
            filePath: storage.finalPath(file.storage_name), key, plainSize: Number(file.size_bytes)
        }));
        summary.scanned++;

        if (verdict.status === 'clean') {
            summary.clean++;
            await db.query("UPDATE user_files SET scan_status = 'clean' WHERE id = ?", [file.id]);
        } else if (verdict.status === 'found') {
            summary.infected.push({ id: Number(file.id), userId: file.user_id, signature: verdict.signature });
            await events.record({
                type: 'FILE_REJECTED', rule: `MALWARE_${verdict.signature}`.slice(0, 64), severity: 'critical', riskScore: 90,
                userId: file.user_id, details: { fileId: Number(file.id), source: 'rescan', deleted: deleteInfected }, ip: '127.0.0.1'
            });
            if (deleteInfected) {
                await db.query('DELETE FROM user_files WHERE id = ?', [file.id]);
                await storage.removeFinal(file.storage_name);
                summary.deleted++;
            }
        } else {
            summary.errors.push({ id: Number(file.id), detail: verdict.detail });
        }
    }

    console.log(JSON.stringify(summary, null, 2));
    if (summary.infected.length > 0) process.exitCode = 3;
    else if (summary.errors.length > 0) process.exitCode = 1;
}

main()
    .catch((error) => { console.error(`❌ ${error.message}`); process.exitCode = 1; })
    .finally(() => db.pool.end());
