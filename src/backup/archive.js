const crypto = require('crypto');
const zlib = require('zlib');

// Formato de archivo de backup (.sbk):
//
//   "SSBK" | versión (1 byte) | longitud de cabecera (uint32 BE) | cabecera JSON | texto cifrado | tag GCM (16)
//
//   - La carga es el snapshot JSON COMPRIMIDO con el mejor de brotli (calidad 11) y gzip (nivel 9).
//   - Se cifra con AES-256-GCM (binario). La cabecera completa va como datos autenticados (AAD):
//     si alguien la modifica, el descifrado falla.
//   - La clave se deriva con HKDF de la clave de cifrado de la ÉPOCA indicada en la cabecera.
//
// Por qué una sola capa AES-GCM binaria y no tripleEncryptor: tripleEncryptor devuelve texto hex y
// cada nivel vuelve a pasar a hex el resultado del anterior (la salida llega a ocupar ~8 veces la
// entrada). Para un archivo de backup, cuyo objetivo es ocupar lo mínimo, eso es inaceptable.
//
// Por qué se comprime ANTES de cifrar: el texto cifrado no se comprime (parece aleatorio).

const MAGIC = Buffer.from('SSBK');
const VERSION = 1;
const GCM_TAG_BYTES = 16;

function deriveArchiveKey(encryptionKeyHex) {
    return Buffer.from(crypto.hkdfSync('sha256', Buffer.from(encryptionKeyHex, 'hex'), Buffer.alloc(0), 'secure-server/backup/v1', 32));
}

// Comprime con varios algoritmos y devuelve el que menos ocupa.
// (RAR es un formato propietario sin soporte en Node; brotli suele ganar a zip/deflate.)
function compressBest(buffer) {
    const candidates = [
        {
            algo: 'brotli',
            data: zlib.brotliCompressSync(buffer, {
                params: {
                    [zlib.constants.BROTLI_PARAM_QUALITY]: 11,
                    [zlib.constants.BROTLI_PARAM_LGWIN]: 24,
                    [zlib.constants.BROTLI_PARAM_MODE]: zlib.constants.BROTLI_MODE_TEXT,
                    [zlib.constants.BROTLI_PARAM_SIZE_HINT]: buffer.length
                }
            })
        },
        { algo: 'gzip', data: zlib.gzipSync(buffer, { level: 9 }) }
    ];
    return candidates.reduce((best, c) => (c.data.length < best.data.length ? c : best));
}

function decompress(algo, data) {
    if (algo === 'brotli') return zlib.brotliDecompressSync(data);
    if (algo === 'gzip') return zlib.gunzipSync(data);
    throw new Error(`Algoritmo de compresión desconocido: ${algo}`);
}

function encode(header, compressed, encryptionKeyHex) {
    const iv = crypto.randomBytes(12);
    const fullHeader = { ...header, iv: iv.toString('base64') };
    const headerBytes = Buffer.from(JSON.stringify(fullHeader), 'utf8');
    const prefix = Buffer.alloc(MAGIC.length + 1 + 4);
    MAGIC.copy(prefix, 0);
    prefix[MAGIC.length] = VERSION;
    prefix.writeUInt32BE(headerBytes.length, MAGIC.length + 1);
    const aad = Buffer.concat([prefix, headerBytes]);

    const cipher = crypto.createCipheriv('aes-256-gcm', deriveArchiveKey(encryptionKeyHex), iv);
    cipher.setAAD(aad);
    const ciphertext = Buffer.concat([cipher.update(compressed), cipher.final()]);

    return Buffer.concat([aad, ciphertext, cipher.getAuthTag()]);
}

function parse(buffer) {
    const minimum = MAGIC.length + 1 + 4 + GCM_TAG_BYTES;
    if (buffer.length < minimum || !buffer.subarray(0, MAGIC.length).equals(MAGIC)) {
        throw new Error('No es un archivo de backup válido (firma incorrecta)');
    }
    if (buffer[MAGIC.length] !== VERSION) {
        throw new Error(`Versión de backup no soportada: ${buffer[MAGIC.length]}`);
    }

    const headerLength = buffer.readUInt32BE(MAGIC.length + 1);
    const headerStart = MAGIC.length + 1 + 4;
    const headerEnd = headerStart + headerLength;
    if (headerEnd + GCM_TAG_BYTES > buffer.length) throw new Error('Backup truncado o corrupto');

    return {
        header: JSON.parse(buffer.subarray(headerStart, headerEnd).toString('utf8')),
        aad: buffer.subarray(0, headerEnd),
        ciphertext: buffer.subarray(headerEnd, buffer.length - GCM_TAG_BYTES),
        tag: buffer.subarray(buffer.length - GCM_TAG_BYTES)
    };
}

// Solo la cabecera (sin clave): época, fecha, tamaños, tablas y nº de filas.
function readHeader(buffer) {
    const { header } = parse(buffer);
    const { iv, ...publicHeader } = header;
    return publicHeader;
}

function decryptPayload(buffer, encryptionKeyHex) {
    const { header, aad, ciphertext, tag } = parse(buffer);
    const decipher = crypto.createDecipheriv('aes-256-gcm', deriveArchiveKey(encryptionKeyHex), Buffer.from(header.iv, 'base64'));
    decipher.setAAD(aad);
    decipher.setAuthTag(tag);

    try {
        return { header, compressed: Buffer.concat([decipher.update(ciphertext), decipher.final()]) };
    } catch {
        throw new Error('No se pudo descifrar el backup: clave incorrecta o archivo alterado');
    }
}

// snapshot: objeto serializable. meta.tables: { tabla: nº de filas }
function createArchive(snapshot, { encryptionKeyHex, epoch, tables = {} }) {
    const raw = Buffer.from(JSON.stringify(snapshot), 'utf8');
    const { algo, data } = compressBest(raw);

    const header = {
        format: 'secure-server-backup',
        epoch,
        createdAt: new Date().toISOString(),
        compression: algo,
        rawBytes: raw.length,
        compressedBytes: data.length,
        tables
    };
    return encode(header, data, encryptionKeyHex);
}

// resolveKey(epoch) -> clave hex de esa época (la actual, o una anterior del keyring)
function openArchive(buffer, resolveKey) {
    const { header } = parse(buffer);
    const key = resolveKey(header.epoch);
    if (!key) throw new Error(`No hay clave disponible para la época ${header.epoch}`);

    const { compressed } = decryptPayload(buffer, key);
    const snapshot = JSON.parse(decompress(header.compression, compressed).toString('utf8'));
    return { header: readHeader(buffer), snapshot };
}

// Cambia la clave exterior del archivo SIN descomprimir ni tocar el contenido.
function rewrapArchive(buffer, { fromKeyHex, toKeyHex, toEpoch }) {
    const { header, compressed } = decryptPayload(buffer, fromKeyHex);
    const { iv, ...rest } = header;
    return encode({ ...rest, epoch: toEpoch, rewrappedAt: new Date().toISOString() }, compressed, toKeyHex);
}

module.exports = { createArchive, openArchive, readHeader, rewrapArchive, compressBest, decompress };
