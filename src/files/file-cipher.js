const crypto = require('crypto');
const fs = require('fs');
const { Transform, Readable } = require('stream');

// Cifrado de archivos grandes en bloques (formato "f1").
//
//   - El archivo se parte en bloques de 64 KiB de texto claro; cada bloque se cifra con AES-256-GCM
//     y lleva su propia etiqueta de autenticación de 16 bytes. Disco = N × (64 KiB + 16 B).
//   - Cada archivo tiene su PROPIA clave aleatoria de 256 bits, así que el nonce (el contador de
//     bloque) no puede repetirse jamás con la misma clave.
//   - Cada bloque se autentica ANTES de entregar ni un byte de él: un bit alterado en disco se detecta.
//   - AAD = formato + "¿es el último bloque?". Quitar bloques del final, o reordenarlos, hace fallar
//     la autenticación (un atacante con acceso al disco no puede truncar un archivo en silencio).
//   - Acceso aleatorio: el bloque i está en el desplazamiento i × (64 KiB + 16), lo que permite
//     servir cabeceras HTTP Range (saltar en un vídeo/audio) descifrando solo los bloques necesarios.

const CHUNK = 64 * 1024;
const TAG = 16;
const KEY_BYTES = 32;

const nonceFor = (index) => {
    const nonce = Buffer.alloc(12);
    nonce.writeBigUInt64BE(BigInt(index), 4);
    return nonce;
};
const aadFor = (isLast) => Buffer.from([0x66, 0x31, isLast ? 1 : 0]); // "f1" + marca de último

const newDataKey = () => crypto.randomBytes(KEY_BYTES);
const chunkCount = (plainSize) => Math.max(1, Math.ceil(plainSize / CHUNK));
const cipherSize = (plainSize) => plainSize + chunkCount(plainSize) * TAG;

class EncryptStream extends Transform {
    constructor(key) {
        super();
        this.key = key;
        this.pending = Buffer.alloc(0);
        this.index = 0;
        this.plainBytes = 0;
        this.hash = crypto.createHash('sha256');
    }

    _seal(plain, isLast) {
        const cipher = crypto.createCipheriv('aes-256-gcm', this.key, nonceFor(this.index++), { authTagLength: TAG });
        cipher.setAAD(aadFor(isLast));
        const body = Buffer.concat([cipher.update(plain), cipher.final()]);
        return Buffer.concat([body, cipher.getAuthTag()]);
    }

    _transform(chunk, _encoding, callback) {
        try {
            this.plainBytes += chunk.length;
            this.hash.update(chunk);
            this.pending = this.pending.length ? Buffer.concat([this.pending, chunk]) : chunk;

            // Se retiene siempre el último bloque (hasta saber que lo es) para poder marcarlo
            while (this.pending.length > CHUNK) {
                this.push(this._seal(this.pending.subarray(0, CHUNK), false));
                this.pending = this.pending.subarray(CHUNK);
            }
            callback();
        } catch (error) {
            callback(error);
        }
    }

    _flush(callback) {
        try {
            this.push(this._seal(this.pending, true)); // un archivo vacío también deja un bloque (vacío) final
            callback();
        } catch (error) {
            callback(error);
        }
    }

    sha256() {
        return this.hash.copy().digest('hex');
    }
}

// Fuente de bytes cifrados de un archivo en disco local. El almacenamiento S3 (storage.js) ofrece la misma forma:
//   { size(): Promise<number>, stream(from, to): AsyncIterable<Buffer> }   (from/to inclusivos, en bytes del archivo CIFRADO)
// Leer el tramo necesario como UN stream (y no bloque a bloque) importa en S3: una descarga es una petición, no una por bloque.
const localBlob = (filePath) => ({
    size: async () => (await fs.promises.stat(filePath)).size,
    stream: (from, to) => fs.createReadStream(filePath, { start: from, end: to, highWaterMark: CHUNK + TAG })
});

// Descifra los bytes [start, end] (inclusive) del texto claro. `filePath` (disco) o `blob` (cualquier fuente con size/stream).
async function* decryptRange({ filePath, blob, key, plainSize, start = 0, end = plainSize - 1 }) {
    const source = blob || localBlob(filePath);
    if ((await source.size()) !== cipherSize(plainSize)) throw new Error('FILE_CORRUPT'); // truncado o ampliado

    if (plainSize === 0) return;
    const lastChunk = chunkCount(plainSize) - 1;
    const firstWanted = Math.floor(start / CHUNK);
    const lastWanted = Math.floor(end / CHUNK);
    const sealedLength = (i) => (i === lastChunk ? plainSize - i * CHUNK : CHUNK) + TAG;
    const from = firstWanted * (CHUNK + TAG);
    const to = lastWanted * (CHUNK + TAG) + sealedLength(lastWanted) - 1;

    let pending = Buffer.alloc(0);
    let i = firstWanted;
    for await (const piece of source.stream(from, to)) {
        pending = pending.length ? Buffer.concat([pending, piece]) : Buffer.from(piece);
        while (i <= lastWanted && pending.length >= sealedLength(i)) {
            const length = sealedLength(i);
            const plainLength = length - TAG;
            const sealed = pending.subarray(0, length);
            pending = pending.subarray(length);

            const decipher = crypto.createDecipheriv('aes-256-gcm', key, nonceFor(i), { authTagLength: TAG });
            decipher.setAAD(aadFor(i === lastChunk));
            decipher.setAuthTag(sealed.subarray(plainLength));
            let plain;
            try {
                plain = Buffer.concat([decipher.update(sealed.subarray(0, plainLength)), decipher.final()]);
            } catch {
                throw new Error('FILE_CORRUPT'); // la autenticación del bloque falló
            }

            const sliceFrom = i === firstWanted ? start - i * CHUNK : 0;
            const sliceTo = i === lastWanted ? end - i * CHUNK + 1 : plain.length;
            yield plain.subarray(sliceFrom, sliceTo);
            i++;
        }
    }
    if (i <= lastWanted) throw new Error('FILE_CORRUPT'); // la fuente entregó menos bytes de los que dice su tamaño
}

const createDecryptStream = (options) => Readable.from(decryptRange(options), { objectMode: false });

// Cabecera Range (solo un rango; varios se ignoran y se sirve el archivo entero).
//   → null (sin rango válido de tipo bytes) | { start, end } | 'unsatisfiable'
function parseRange(header, size) {
    if (!header || typeof header !== 'string') return null;
    const match = /^bytes=(\d*)-(\d*)$/.exec(header.trim());
    if (!match || (match[1] === '' && match[2] === '')) return null;

    let start, end;
    if (match[1] === '') {                 // sufijo: los últimos N bytes
        const suffix = Number(match[2]);
        if (suffix === 0) return 'unsatisfiable';
        start = Math.max(0, size - suffix);
        end = size - 1;
    } else {
        start = Number(match[1]);
        end = match[2] === '' ? size - 1 : Math.min(Number(match[2]), size - 1);
    }
    if (!Number.isSafeInteger(start) || start >= size || end < start) return 'unsatisfiable';
    return { start, end };
}

module.exports = { CHUNK, TAG, EncryptStream, createDecryptStream, decryptRange, newDataKey, cipherSize, chunkCount, parseRange };
