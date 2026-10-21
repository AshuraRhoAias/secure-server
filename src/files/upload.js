const Busboy = require('busboy');
const { pipeline, Transform } = require('stream');
const types = require('./file-types');
const cipher = require('./file-cipher');
const storage = require('./storage');
const { scanText } = require('../security/injection-detector');
const av = require('./av-scanner');

// Recibe una subida multipart/form-data EN STREAMING (nunca se carga el archivo entero en memoria) y la
// deja cifrada en un archivo temporal. Cadena por la que pasa cada byte:
//
//   petición → busboy → [SniffGate: tipo real + límite de tamaño] → [EncryptStream: AES-256-GCM por bloques] → disco
//
// Se rechaza (y se borra lo escrito) cuando:
//   - no es multipart, o trae más de un archivo / un campo de archivo que no se llama "file"
//   - el nombre trae patrones de ataque (../, <script>, SQL...) o una extensión prohibida (.php, .exe, .svg, .html...)
//   - el CONTENIDO real no es un tipo permitido, o no coincide con la extensión del nombre
//   - es ejecutable, comprimido, o texto con HTML/scripts incrustados
//   - supera el tamaño máximo de su categoría

const SNIFF_BYTES = 4096;

class UploadError extends Error {
    constructor(status, code, message, { severity = 'low', rule = null, detail = null } = {}) {
        super(message);
        this.status = status;
        this.code = code;
        this.severity = severity;
        this.rule = rule || code;
        this.detail = detail;
    }
}

function decideType(head, filename) {
    const ext = types.extensionOf(filename);
    let detected = types.detectType(head);

    if (detected?.rejected) {
        throw new UploadError(415, detected.rejected, 'Tipo de archivo no permitido', {
            severity: detected.rejected === 'EXECUTABLE_CONTENT' ? 'high' : 'medium'
        });
    }

    if (!detected) {
        // Sin firma binaria: solo se admite texto plano, con extensión de texto y contenido que lo parezca
        if (types.TYPES['text/plain'].ext.includes(ext) && types.looksLikeText(head)) {
            if (types.hasActiveContent(head)) {
                throw new UploadError(415, 'ACTIVE_CONTENT', 'El texto contiene HTML, scripts o código ejecutable', { severity: 'high' });
            }
            detected = { mime: 'text/plain' };
        } else {
            throw new UploadError(415, 'UNSUPPORTED_TYPE', 'Tipo de archivo no soportado');
        }
    }

    const info = types.TYPES[detected.mime];
    // La extensión que se ve debe corresponder a lo que el archivo ES
    if (ext && !info.ext.includes(ext)) {
        throw new UploadError(415, 'EXTENSION_MISMATCH', 'La extensión no coincide con el contenido del archivo', { severity: 'medium' });
    }
    return { mime: detected.mime, category: info.category };
}

// Primeros bytes → decide el tipo; después deja pasar el resto vigilando tamaño (y UTF-8 si es texto)
class SniffGate extends Transform {
    constructor({ filename, limits }) {
        super();
        this.filename = filename;
        this.limits = limits;
        this.headChunks = [];
        this.headLength = 0;
        this.total = 0;
        this.decided = false;
        this.mime = null;
        this.category = null;
    }

    _decide(callback) {
        try {
            const head = Buffer.concat(this.headChunks);
            const { mime, category } = decideType(head, this.filename);
            this.mime = mime;
            this.category = category;
            this.maxBytes = this.limits.perCategory[category];
            this.decided = true;
            this.headChunks = [];

            if (category === 'text') this.decoder = new TextDecoder('utf-8', { fatal: true });
            this._forward(head, callback);
        } catch (error) {
            callback(error);
        }
    }

    _forward(chunk, callback) {
        if (this.total > this.maxBytes) {
            return callback(new UploadError(413, 'FILE_TOO_LARGE', `El archivo supera el máximo de ${Math.floor(this.maxBytes / 1048576)} MB para su tipo`));
        }
        if (this.decoder) {
            try {
                if (chunk.includes(0)) throw new Error('NUL');
                this.decoder.decode(chunk, { stream: true });
            } catch {
                return callback(new UploadError(415, 'INVALID_TEXT', 'El archivo de texto no es UTF-8 válido'));
            }
        }
        this.push(chunk);
        callback();
    }

    _transform(chunk, _encoding, callback) {
        this.total += chunk.length;
        if (this.decided) return this._forward(chunk, callback);

        this.headChunks.push(chunk);
        this.headLength += chunk.length;
        if (this.headLength < SNIFF_BYTES) return callback();
        this._decide(callback);
    }

    _flush(callback) {
        const finish = (error) => {
            if (error) return callback(error);
            if (this.decoder) {
                try { this.decoder.decode(); } catch { return callback(new UploadError(415, 'INVALID_TEXT', 'El archivo de texto no es UTF-8 válido')); }
            }
            callback();
        };
        if (this.decided) return finish();
        this._decide(finish); // archivo más corto que SNIFF_BYTES
    }
}

function receiveUpload(req) {
    const limits = storage.limits();

    return new Promise((resolve, reject) => {
        if (!req.is('multipart/form-data')) {
            return reject(new UploadError(415, 'EXPECTED_MULTIPART', 'La subida debe ser multipart/form-data con el archivo en el campo "file"'));
        }

        const declared = Number(req.headers['content-length']);
        if (Number.isFinite(declared) && declared > limits.maxAny + 1024 * 1024) {
            return reject(new UploadError(413, 'FILE_TOO_LARGE', 'La petición supera el tamaño máximo permitido'));
        }

        const storageName = storage.newStorageName();
        const dataKey = cipher.newDataKey();
        const streams = [];
        let settled = false;
        let filePromise = null;
        let filesSeen = 0;
        let filename = null;

        let bb;
        try {
            bb = Busboy({
                headers: req.headers,
                limits: { files: 1, fields: 5, fieldSize: 4096, fileSize: limits.maxAny, parts: 8, headerPairs: 20 },
                preservePath: true,        // se recibe el nombre tal cual, para detectar y registrar "../../"
                defParamCharset: 'utf8'
            });
        } catch {
            return reject(new UploadError(400, 'BAD_MULTIPART', 'Petición multipart inválida'));
        }

        const fail = (error) => {
            if (settled) return;
            settled = true;

            streams.forEach(stream => stream.destroy());
            req.unpipe(bb);
            // Se descarta (con tope) lo que falte por llegar, para que el cliente reciba nuestra respuesta
            let drained = 0;
            req.on('data', (chunk) => { drained += chunk.length; if (drained > limits.maxAny) req.destroy(); });
            req.resume();
            storage.removeTemp(storageName).catch(() => {});

            // Errores del sistema (ENOSPC, EACCES, ENOTDIR...) son del SERVIDOR (500); el resto, de la petición (400)
            const serverSide = /^E[A-Z]+$/.test(error?.code || '');
            reject(error instanceof UploadError ? error : new UploadError(serverSide ? 500 : 400, 'UPLOAD_FAILED', 'No se pudo procesar la subida'));
        };

        bb.on('file', (field, stream, info) => {
            try {
                handleFile(field, stream, info);
            } catch (error) {
                // Cualquier fallo síncrono aquí (p. ej. disco no escribible) sería una excepción no capturada
                // que tumba el proceso: se convierte en un rechazo normal de la subida
                console.error('❌ Error preparando la subida:', error.code || error.message);
                stream.resume();
                fail(error);
            }
        });

        const handleFile = (field, stream, info) => {
            filesSeen++;
            if (field !== 'file' || filesSeen > 1) {
                stream.resume();
                return fail(new UploadError(400, 'UNEXPECTED_FILE_FIELD', 'Se espera un único archivo en el campo "file"'));
            }

            const rawName = info.filename;
            if (!rawName) {
                stream.resume();
                return fail(new UploadError(400, 'MISSING_FILENAME', 'El archivo debe tener nombre'));
            }

            // El nombre en bruto se inspecciona ANTES de limpiarlo: si trae "../../etc/passwd" o
            // "' OR 1=1--.jpg" queremos saberlo (evento de seguridad), no limitarnos a limpiarlo.
            const attack = scanText(rawName, { location: 'body', field: 'filename' }).find(f => f.severity === 'high');
            if (attack) {
                stream.resume();
                return fail(new UploadError(400, 'FORBIDDEN_FILENAME', 'El nombre del archivo contiene contenido no permitido', { severity: 'high', rule: attack.rule }));
            }

            filename = types.sanitizeFilename(rawName);
            if (types.hasForbiddenExtension(filename)) {
                stream.resume();
                return fail(new UploadError(415, 'FORBIDDEN_FILENAME', 'Extensión de archivo no permitida', { severity: 'medium', rule: 'FORBIDDEN_EXTENSION' }));
            }

            const gate = new SniffGate({ filename, limits });
            const encrypt = new cipher.EncryptStream(dataKey);
            const out = storage.createTempWriteStream(storageName);
            // Antivirus (si está activo): entre la decisión de tipo y el cifrado, para que el archivo en claro nunca se guarde
            const scan = av.enabled() ? new av.ScanTee(UploadError) : null;
            streams.push(gate, ...(scan ? [scan] : []), encrypt, out);

            stream.on('limit', () => fail(new UploadError(413, 'FILE_TOO_LARGE', 'El archivo supera el tamaño máximo permitido')));

            filePromise = new Promise((done, failed) => {
                const stages = scan ? [stream, gate, scan, encrypt, out] : [stream, gate, encrypt, out];
                pipeline(...stages, (error) => {
                    if (error) return failed(error);
                    done({
                        size: encrypt.plainBytes, sha256: encrypt.sha256(), mime: gate.mime, category: gate.category,
                        scanStatus: scan ? scan.scanStatus : 'unscanned', scannerError: scan?.scannerError || null
                    });
                });
            });
            filePromise.catch(fail);
        };

        bb.on('filesLimit', () => fail(new UploadError(400, 'TOO_MANY_FILES', 'Solo se admite un archivo por petición')));
        bb.on('partsLimit', () => fail(new UploadError(400, 'TOO_MANY_PARTS', 'Demasiadas partes en la petición')));
        bb.on('fieldsLimit', () => fail(new UploadError(400, 'TOO_MANY_PARTS', 'Demasiados campos en la petición')));
        bb.on('error', () => fail(new UploadError(400, 'BAD_MULTIPART', 'Petición multipart inválida')));

        bb.on('close', async () => {
            try {
                if (!filePromise) throw new UploadError(400, 'NO_FILE', 'No se recibió ningún archivo en el campo "file"');
                const result = await filePromise;
                if (settled) return;
                settled = true;
                resolve({ storageName, dataKey, filename, ...result });
            } catch (error) {
                fail(error);
            }
        });

        req.on('aborted', () => fail(new UploadError(400, 'UPLOAD_ABORTED', 'La subida se interrumpió')));
        req.on('error', () => fail(new UploadError(400, 'UPLOAD_ABORTED', 'La subida se interrumpió')));
        req.pipe(bb);
    });
}

module.exports = { receiveUpload, UploadError, decideType, SniffGate };
