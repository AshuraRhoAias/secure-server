const { Transform } = require('stream');
const zlib = require('zlib');

// Saneamiento del contenido, DESPUÉS de saber qué es el archivo y ANTES de antivirus y cifrado:
//
//   imágenes (jpeg, png, gif, webp, avif)  se DECODIFICAN y se vuelven a CODIFICAR con sharp/libvips.
//        Lo que no sea píxeles desaparece: EXIF (GPS, cámara), XMP, ICC, comentarios, datos tras el final del archivo y los
//        "polyglots" (un JPEG válido que además es un script/ZIP). Un archivo que no decodifica se rechaza.
//   PDF  se INSPECCIONA (no se reescribe): se rechaza si lleva JavaScript, acciones de lanzar programas, archivos
//        adjuntos, formularios XFA, multimedia embebida o cifrado (porque entonces no se puede mirar dentro).
//
// Variables:  IMAGE_SANITIZE=on|off (on)   IMAGE_SANITIZE_PASSTHROUGH=heic,...  (tipos sin saneador que se aceptan tal cual)
//             IMAGE_JPEG_QUALITY=90        IMAGE_MAX_PIXELS=100000000
//             PDF_ACTIVE_CONTENT=reject|allow (reject)
//             SANITIZE_MAX_CONCURRENT=4    (cuántos archivos se procesan a la vez: cada uno se tiene entero en memoria)
//
// Límites honestos (también en docs/SEGURIDAD.md §5):
//  - La decodificación de imágenes ocurre DENTRO del proceso (libvips es C/C++). Un fallo de memoria en un decodificador
//    afectaría al servidor: mantén sharp actualizado (Dependabot) o aísla este paso en un servicio aparte.
//  - La inspección de PDF busca capacidades peligrosas, no es un motor de PDF: no detecta un fallo desconocido del
//    visor (fuentes/imágenes malformadas). Lo que no sabe inspeccionar (filtros raros, cifrado) lo RECHAZA.

const MB = 1024 * 1024;
const intEnv = (name, fallback) => {
    const n = Number(process.env[name]);
    return Number.isInteger(n) && n > 0 ? n : fallback;
};

// ------------------------------------------------------------------ cola de concurrencia (acota la memoria)
class Semaphore {
    constructor() { this.active = 0; this.waiting = []; }
    async acquire(limit) {
        if (this.active < limit) { this.active++; return; }
        await new Promise(resolve => this.waiting.push(resolve));
        this.active++;
    }
    release() {
        this.active--;
        const next = this.waiting.shift();
        if (next) next();
    }
}
const semaphore = new Semaphore();

// ------------------------------------------------------------------ imágenes
const SHARP_FORMAT = {
    'image/jpeg': 'jpeg',
    'image/png': 'png',
    'image/gif': 'gif',
    'image/webp': 'webp',
    'image/avif': 'heif'      // sharp llama "heif" al contenedor AVIF
};

const imageSanitizing = () => (process.env.IMAGE_SANITIZE || 'on') !== 'off';
const passthrough = () => (process.env.IMAGE_SANITIZE_PASSTHROUGH || '').split(',').map(s => s.trim().toLowerCase()).filter(Boolean);

function planFor(mime, category) {
    if (category === 'image' && imageSanitizing()) {
        if (SHARP_FORMAT[mime]) return 'image';
        // HEIC: el binario de sharp no decodifica HEVC. Por defecto se rechaza; el operador puede aceptarlo sin sanear.
        const ext = mime.split('/')[1];
        if (passthrough().includes(ext)) return 'pass';
        return 'unsanitizable';
    }
    if (mime === 'application/pdf' && (process.env.PDF_ACTIVE_CONTENT || 'reject') !== 'allow') return 'pdf';
    return 'pass';
}

async function sanitizeImage(buffer, mime, UploadError) {
    const sharp = require('sharp');
    const maxPixels = intEnv('IMAGE_MAX_PIXELS', 100_000_000);
    const expected = SHARP_FORMAT[mime];
    const invalid = (why) => new UploadError(422, 'IMAGE_INVALID', 'La imagen no es válida o está dañada', { severity: 'medium', rule: 'IMAGE_INVALID', detail: why });

    try {
        const options = { failOn: 'error', limitInputPixels: maxPixels, animated: true, sequentialRead: true };
        const meta = await sharp(buffer, options).metadata();
        if (meta.format !== expected) throw invalid(`formato ${meta.format}`);
        const frames = meta.pages || 1;
        if (!meta.width || !meta.height || meta.width * (meta.pageHeight || meta.height) * frames > maxPixels * 4 || frames > 2000) {
            throw invalid('dimensiones o fotogramas excesivos');
        }

        // Sin .withMetadata(): sharp descarta EXIF, XMP, IPTC, ICC y comentarios. .rotate() aplica antes la orientación EXIF
        // (si no, quitarla dejaría la foto girada).
        let pipeline = sharp(buffer, options).rotate();
        switch (expected) {
            case 'jpeg': pipeline = pipeline.jpeg({ quality: intEnv('IMAGE_JPEG_QUALITY', 90), mozjpeg: false }); break;
            case 'png': pipeline = pipeline.png({ compressionLevel: 9 }); break;
            case 'gif': pipeline = pipeline.gif(); break;
            case 'webp': pipeline = pipeline.webp({ quality: 90 }); break;
            case 'heif': pipeline = pipeline.avif({ quality: 60 }); break;
            default: throw invalid('formato sin saneador');
        }
        const out = await pipeline.toBuffer();
        if (out.length === 0) throw invalid('salida vacía');
        return out;
    } catch (error) {
        if (error instanceof UploadError) throw error;
        throw invalid(String(error.message).split('\n')[0].slice(0, 120));
    }
}

// ------------------------------------------------------------------ PDF
// Nombres PDF que dan capacidades peligrosas (o impiden inspeccionar). Se comparan sin distinguir mayúsculas.
const PDF_DANGEROUS = new Set([
    'javascript', 'js', 'launch', 'embeddedfile', 'embeddedfiles', 'ef', 'fileattachment',
    'richmedia', 'richmediacontent', 'xfa', 'submitform', 'importdata', 'gotor', 'gotoe', 'rendition', 'movie', 'sound',
    'encrypt'
]);
const NAME = /\/([^\s/<>[\]()%{}]+)/g;

// Los nombres pueden escribirse con #xx: "/J#61vaScript" ES "/JavaScript". Hay que decodificarlos antes de comparar.
const decodeName = (name) => name.replace(/#([0-9a-fA-F]{2})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)));

function dangerousNames(text) {
    const found = new Set();
    for (const [, raw] of text.matchAll(NAME)) {
        const name = decodeName(raw).toLowerCase();
        if (PDF_DANGEROUS.has(name)) found.add(name);
    }
    return found;
}

function inspectPdf(buffer, UploadError) {
    const reject = (code, message, detail) => new UploadError(415, code, message, { severity: 'high', rule: code, detail });
    const raw = buffer.toString('latin1');
    const found = dangerousNames(raw);

    // Contenido comprimido: las definiciones (acciones, adjuntos) suelen ir dentro de "object streams" con Flate.
    const budget = { left: intEnv('PDF_MAX_INFLATED_MB', 64) * MB };
    for (const match of raw.matchAll(/stream\r?\n/g)) {
        const start = match.index + match[0].length;
        const end = raw.indexOf('endstream', start);
        if (end < 0) continue;
        const dict = raw.slice(Math.max(0, match.index - 1500), match.index);
        const dictStart = dict.lastIndexOf('obj');
        const header = dictStart >= 0 ? dict.slice(dictStart) : dict;
        const isObjectStream = /\/ObjStm\b/.test(header) || /\/Type\s*\/XRef\b/.test(header);
        const filters = [...header.matchAll(/\/(FlateDecode|Fl|ASCII85Decode|A85|ASCIIHexDecode|AHx|LZWDecode|LZW|RunLengthDecode|RL|Crypt)\b/g)].map(m => m[1]);

        const cannotLook = (why) => reject('PDF_UNINSPECTABLE', 'No se puede inspeccionar el contenido del PDF', why);
        if (filters.includes('Crypt')) throw cannotLook('stream cifrado');
        if (!filters.length) continue;                       // sin filtro: ya lo vio el análisis del texto
        const flateOnly = filters.every(f => f === 'FlateDecode' || f === 'Fl');
        if (!flateOnly) {
            if (isObjectStream) throw cannotLook(`filtros ${filters.join('+')} en un object stream`);
            continue;                                         // imágenes/fuentes con otros filtros: no contienen definiciones
        }
        if (isObjectStream && /\/Predictor\s*(?:[2-9]|\d{2,})/.test(header)) throw cannotLook('object stream con predictor');

        let data = Buffer.from(raw.slice(start, end), 'latin1');
        // Los datos comprimidos no tienen por qué terminar en salto de línea; inflate admite basura final
        let inflated;
        try {
            inflated = zlib.inflateSync(data, { maxOutputLength: Math.max(1, Math.min(budget.left, 32 * MB)), finishFlush: zlib.constants.Z_SYNC_FLUSH });
        } catch (error) {
            if (isObjectStream) throw cannotLook('no se pudo descomprimir un object stream');
            if (error.code === 'ERR_BUFFER_TOO_LARGE') throw cannotLook('contenido comprimido desproporcionado');
            continue;                                         // un stream de imagen/fuente roto no es definición de acciones
        }
        budget.left -= inflated.length;
        if (budget.left < 0) throw cannotLook('contenido comprimido desproporcionado');
        if (isObjectStream) for (const name of dangerousNames(inflated.toString('latin1'))) found.add(name);
        data = null;
    }

    if (found.size > 0) {
        const names = [...found].sort();
        const code = names.includes('encrypt') ? 'PDF_ENCRYPTED' : 'PDF_ACTIVE_CONTENT';
        throw reject(code, code === 'PDF_ENCRYPTED' ? 'No se admiten PDF cifrados (no se pueden inspeccionar)' : 'El PDF contiene contenido activo (JavaScript, archivos adjuntos, acciones)', names.join(','));
    }
}

// ------------------------------------------------------------------ etapa del pipeline
// Deja pasar tal cual lo que no necesita saneamiento; imágenes y PDF se acumulan (ya acotadas por el límite de tamaño
// de su categoría), se procesan al final y se emiten.
class SanitizeStage extends Transform {
    constructor({ gate, UploadError }) {
        super();
        this.gate = gate;
        this.UploadError = UploadError;
        this.plan = null;
        this.chunks = [];
        this.sanitizeStatus = 'none';
        this.sanitizeDetail = null;
    }

    _transform(chunk, _encoding, callback) {
        if (!this.plan) {
            this.plan = planFor(this.gate.mime, this.gate.category);
            if (this.plan === 'unsanitizable') {
                return callback(new this.UploadError(415, 'IMAGE_NOT_SANITIZABLE', 'Este formato de imagen no se puede sanear y no está permitido', { severity: 'low', rule: 'IMAGE_NOT_SANITIZABLE' }));
            }
        }
        if (this.plan === 'pass') { this.push(chunk); return callback(); }
        this.chunks.push(chunk);
        callback();
    }

    _flush(callback) {
        if (this.plan !== 'image' && this.plan !== 'pdf') return callback();
        const limit = intEnv('SANITIZE_MAX_CONCURRENT', 4);
        semaphore.acquire(limit).then(async () => {
            try {
                const input = Buffer.concat(this.chunks);
                this.chunks = [];
                if (this.plan === 'image') {
                    this.push(await sanitizeImage(input, this.gate.mime, this.UploadError));
                    this.sanitizeStatus = 'reencoded';
                } else {
                    inspectPdf(input, this.UploadError);
                    this.push(input);
                    this.sanitizeStatus = 'inspected';
                }
                callback();
            } catch (error) {
                callback(error);
            } finally {
                semaphore.release();
            }
        });
    }
}

module.exports = { SanitizeStage, sanitizeImage, inspectPdf, dangerousNames, planFor, decodeName };
