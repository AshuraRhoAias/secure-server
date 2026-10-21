const { pipeline } = require('stream');
const db = require('../../config/database');
const { sqlInt } = require('../../config/sql');
const tripleEncryptor = require('../../crypto/tripleEncryptor');
const audit = require('../../services/audit.service');
const events = require('../../security/security-events.service');
const anomalyDetection = require('../../security/anomaly-detection.service');
const cipher = require('../../files/file-cipher');
const storage = require('../../files/storage');
const { receiveUpload, UploadError } = require('../../files/upload');
const { contentDisposition } = require('../../files/file-types');

const INLINE_CATEGORIES = new Set(['image', 'audio', 'video']); // PDF y texto SIEMPRE como descarga

// Los bytes de cada archivo viven cifrados en disco (ver src/files/file-cipher.js); aquí solo hay
// metadatos. Todas las consultas filtran por user_id: nadie puede ver, bajar ni borrar archivos ajenos.
class FilesController {
    constructor() {
        Object.getOwnPropertyNames(FilesController.prototype)
            .filter(name => name !== 'constructor')
            .forEach(name => { this[name] = this[name].bind(this); });
    }

    serialize(row) {
        return {
            id: Number(row.id),
            name: tripleEncryptor.decrypt(row.filename_encrypted),
            mimeType: row.mime_type,
            category: row.category,
            size: Number(row.size_bytes),
            sha256: row.sha256,
            createdAt: row.created_at
        };
    }

    // Respuesta de error de subida + evento en la tabla de análisis (y strike si es un intento hostil)
    async rejectUpload(req, res, error) {
        const known = error instanceof UploadError;
        const status = known ? error.status : 500;
        const code = known ? error.code : 'UPLOAD_FAILED';

        if (known) {
            await events.record({
                type: 'FILE_REJECTED', rule: error.rule, severity: error.severity,
                riskScore: error.severity === 'high' ? 70 : error.severity === 'medium' ? 40 : 10,
                action: 'rejected', req, status, details: { code }
            });
            if (error.severity === 'high') await anomalyDetection.strike(req.ip, 'upload', { threshold: 5 });
        } else {
            console.error('❌ Error en subida de archivo:', error.code || error.message);
        }

        return res.status(status).json({
            success: false,
            message: known ? error.message : 'No se pudo procesar la subida',
            code
        });
    }

    async usage(userId) {
        const [rows] = await db.query(
            'SELECT COUNT(*) AS files, COALESCE(SUM(size_bytes), 0) AS bytes FROM user_files WHERE user_id = ?',
            [userId]
        );
        return { files: Number(rows[0].files), bytes: Number(rows[0].bytes) };
    }

    async upload(req, res) {
        const limits = storage.limits();
        let upload;

        try {
            // Rechazo temprano por cuota con lo que se sabe antes de leer el cuerpo
            const used = await this.usage(req.user.id);
            const declared = Number(req.headers['content-length']) || 0;
            if (used.files >= limits.maxFilesPerUser || used.bytes + declared > limits.userQuotaBytes + 1024 * 1024) {
                throw new UploadError(413, 'QUOTA_EXCEEDED', 'Has alcanzado tu cuota de almacenamiento');
            }

            upload = await receiveUpload(req);

            const row = await db.transaction(async (tx) => {
                // Se bloquea la fila del usuario: dos subidas simultáneas no pueden saltarse la cuota
                await tx.query('SELECT id FROM users WHERE id = ? FOR UPDATE', [req.user.id]);
                const [usage] = await tx.query(
                    'SELECT COUNT(*) AS files, COALESCE(SUM(size_bytes), 0) AS bytes FROM user_files WHERE user_id = ?',
                    [req.user.id]
                );
                if (Number(usage[0].files) >= limits.maxFilesPerUser || Number(usage[0].bytes) + upload.size > limits.userQuotaBytes) {
                    throw new UploadError(413, 'QUOTA_EXCEEDED', 'Has alcanzado tu cuota de almacenamiento');
                }

                const [result] = await tx.query(
                    `INSERT INTO user_files
                        (user_id, storage_name, filename_encrypted, key_encrypted, mime_type, category, size_bytes, sha256)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
                    [
                        req.user.id,
                        upload.storageName,
                        tripleEncryptor.encrypt(upload.filename),
                        tripleEncryptor.encrypt(upload.dataKey.toString('hex')),   // clave del archivo, envuelta con la maestra
                        upload.mime,
                        upload.category,
                        upload.size,
                        upload.sha256
                    ]
                );

                // El archivo pasa de temporal a definitivo DENTRO de la transacción: si falla, no queda fila
                await storage.commit(upload.storageName);
                return { id: result.insertId };
            });

            await audit.log('FILE_UPLOADED', { fileId: row.id, size: upload.size, mime: upload.mime }, { req });

            res.status(201).json({
                success: true,
                file: {
                    id: Number(row.id), name: upload.filename, mimeType: upload.mime, category: upload.category,
                    size: upload.size, sha256: upload.sha256
                }
            });
        } catch (error) {
            // Nada a medias: ni temporal ni definitivo
            if (upload) {
                await storage.removeTemp(upload.storageName).catch(() => {});
                await storage.removeFinal(upload.storageName).catch(() => {});
            }
            return this.rejectUpload(req, res, error);
        }
    }

    async list(req, res) {
        const { limit, before, category } = req.validated.query;
        const [rows] = await db.query(
            `SELECT id, filename_encrypted, mime_type, category, size_bytes, sha256, created_at
             FROM user_files
             WHERE user_id = ? AND (? IS NULL OR category = ?) AND (? IS NULL OR id < ?)
             ORDER BY id DESC
             LIMIT ${sqlInt(limit)}`,
            [req.user.id, category ?? null, category ?? null, before ?? null, before ?? null]
        );

        const files = rows.map(row => this.serialize(row));
        res.json({
            success: true,
            files,
            // Paginación por cursor: pasa `before=<nextBefore>` para la página siguiente
            nextBefore: files.length === limit ? files[files.length - 1].id : null
        });
    }

    async findOwned(req) {
        const [rows] = await db.query(
            `SELECT id, storage_name, filename_encrypted, key_encrypted, mime_type, category, size_bytes, sha256, created_at
             FROM user_files WHERE id = ? AND user_id = ?`,
            [req.params.id, req.user.id]
        );
        return rows[0] || null;
    }

    notFound(res) {
        return res.status(404).json({ success: false, message: 'Archivo no encontrado', code: 'NOT_FOUND' });
    }

    async getOne(req, res) {
        const row = await this.findOwned(req);
        if (!row) return this.notFound(res);
        res.json({ success: true, file: this.serialize(row) });
    }

    async download(req, res) {
        const row = await this.findOwned(req);
        if (!row) return this.notFound(res);

        const size = Number(row.size_bytes);
        const range = cipher.parseRange(req.headers.range, size);

        if (range === 'unsatisfiable') {
            res.set('Content-Range', `bytes */${size}`);
            return res.status(416).json({ success: false, message: 'Rango no satisfacible', code: 'RANGE_NOT_SATISFIABLE' });
        }

        const name = tripleEncryptor.decrypt(row.filename_encrypted);
        const key = Buffer.from(tripleEncryptor.decrypt(row.key_encrypted), 'hex');
        const start = range ? range.start : 0;
        const end = range ? range.end : size - 1;
        const inline = req.validated?.query?.inline === true && INLINE_CATEGORIES.has(row.category);

        res.status(range ? 206 : 200);
        res.set({
            // El tipo lo fija el servidor a partir del CONTENIDO verificado al subir, no el cliente
            'Content-Type': row.mime_type === 'text/plain' ? 'text/plain; charset=utf-8' : row.mime_type,
            'Content-Length': String(size === 0 ? 0 : end - start + 1),
            'Content-Disposition': contentDisposition(name, inline ? 'inline' : 'attachment'),
            'Accept-Ranges': 'bytes',
            ...(range && { 'Content-Range': `bytes ${start}-${end}/${size}` }),
            // Aunque se muestre en línea, el navegador no puede ejecutar nada de este contenido
            'X-Content-Type-Options': 'nosniff',
            'Content-Security-Policy': "default-src 'none'; sandbox",
            'Cache-Control': 'private, no-store, no-transform',
            'X-Content-SHA256': row.sha256
        });

        // Se audita la descarga completa o el primer rango (un vídeo en streaming pide muchos rangos)
        if (start === 0) await audit.log('FILE_DOWNLOADED', { fileId: Number(row.id), ranged: Boolean(range) }, { req });

        if (req.method === 'HEAD' || size === 0) return res.end();

        const stream = cipher.createDecryptStream({
            filePath: storage.finalPath(row.storage_name), key, plainSize: size, start, end
        });
        pipeline(stream, res, (error) => {
            if (!error) return;
            // El archivo en disco no coincide con lo que se subió (alterado, truncado o perdido)
            console.error(`❌ Archivo ${row.id} ilegible o alterado: ${error.message}`);
            events.record({
                type: 'FILE_INTEGRITY_FAILURE', rule: 'FILE_CORRUPT', severity: 'critical', riskScore: 90,
                req, userId: req.user.id, details: { fileId: Number(row.id) }
            });
            if (!res.headersSent) {
                // Aún no salió ningún byte: se puede responder con un error normal
                for (const header of ['Content-Length', 'Content-Range', 'Content-Disposition', 'Content-Type', 'X-Content-SHA256']) res.removeHeader(header);
                return res.status(500).json({ success: false, message: 'El archivo no se pudo leer', code: 'FILE_CORRUPT' });
            }
            res.destroy(); // los bytes ya enviados eran auténticos, pero la respuesta queda truncada a propósito
        });
    }

    async remove(req, res) {
        const row = await this.findOwned(req);
        if (!row) return this.notFound(res);

        const [result] = await db.query('DELETE FROM user_files WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
        if (result.affectedRows === 0) return this.notFound(res);

        await storage.removeFinal(row.storage_name).catch((error) => {
            console.error(`❌ No se pudo borrar el archivo ${row.storage_name} del disco:`, error.code || error.message);
        });
        await audit.log('FILE_DELETED', { fileId: Number(row.id) }, { req, severity: 'medium', riskScore: 10 });

        res.json({ success: true, message: 'Archivo eliminado' });
    }

    async quota(req, res) {
        const limits = storage.limits();
        const used = await this.usage(req.user.id);
        res.json({
            success: true,
            quota: {
                usedBytes: used.bytes, usedFiles: used.files,
                maxBytes: limits.userQuotaBytes, maxFiles: limits.maxFilesPerUser,
                maxFileBytesByCategory: limits.perCategory
            }
        });
    }
}

module.exports = new FilesController();
