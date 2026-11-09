// Almacenamiento de los archivos CIFRADOS en S3 (o compatible: MinIO, Ceph RGW, Cloudflare R2, Backblaze B2…).
// Se activa con FILES_STORAGE=s3. Ver storage.js y docs/SEGURIDAD.md §13 y §23.
//
// Por qué: con varias máquinas, FILES_DIR (disco local) obliga a un volumen compartido (NFS/EFS). Con S3 todas las instancias ven
// los mismos objetos sin compartir disco. Lo que NO cambia:
//   - Los bytes que llegan al bucket YA van cifrados por archivo (AES-256-GCM por bloques, clave propia envuelta con la clave
//     maestra o con el KMS): el proveedor del bucket nunca ve el contenido. El cifrado del lado del servidor de S3 (S3_SSE) es una
//     capa ADICIONAL, no la protección principal.
//   - El nombre del objeto es el UUID del servidor: nada del usuario forma parte de la clave.
//   - La subida se sigue cifrando en streaming a un temporal LOCAL (FILES_DIR/tmp) y solo al confirmarla se sube el objeto
//     completo (PutObject con tamaño conocido; límite de S3 por objeto en una sola subida: 5 GB, muy por encima de los límites de
//     subida). Si la subida al bucket falla, la fila de la BD no se confirma (files.controller deshace).
//   - Lectura por rangos (HTTP Range / vídeo): UNA petición GetObject con Range por descarga, y cada bloque se autentica igual.
//
// Configuración:
//   S3_BUCKET (obligatoria) · S3_REGION (o AWS_REGION; us-east-1) · S3_ENDPOINT (compatibles) · S3_FORCE_PATH_STYLE=true (MinIO)
//   S3_PREFIX (p. ej. "prod/") · S3_SSE = AES256 (por defecto) | aws:kms | none · S3_SSE_KMS_KEY_ID
//   Credenciales: la cadena estándar de AWS (variables AWS_*, perfil, rol de la instancia/tarea). Nunca en el código.

const fs = require('fs');
const { S3Client, PutObjectCommand, GetObjectCommand, HeadObjectCommand, DeleteObjectCommand } = require('@aws-sdk/client-s3');

function config() {
    const bucket = process.env.S3_BUCKET;
    if (!bucket) throw new Error('FILES_STORAGE=s3 exige S3_BUCKET');
    const endpoint = process.env.S3_ENDPOINT || undefined;
    if (endpoint && !endpoint.startsWith('https://') && process.env.NODE_ENV === 'production' && process.env.S3_ALLOW_HTTP !== 'true') {
        throw new Error('S3_ENDPOINT debe ser https:// en producción (S3_ALLOW_HTTP=true solo en redes internas de confianza)');
    }
    const sse = (process.env.S3_SSE || 'AES256').trim();
    if (!['AES256', 'aws:kms', 'none'].includes(sse)) throw new Error('S3_SSE debe ser AES256, aws:kms o none');
    let prefix = (process.env.S3_PREFIX || '').trim().replace(/^\/+/, '');
    if (prefix && !prefix.endsWith('/')) prefix += '/';
    if (/\.\.|\/\//.test(prefix)) throw new Error('S3_PREFIX no válido');
    return {
        bucket, endpoint, prefix, sse, kmsKeyId: process.env.S3_SSE_KMS_KEY_ID || undefined,
        region: process.env.S3_REGION || process.env.AWS_REGION || 'us-east-1',
        forcePathStyle: process.env.S3_FORCE_PATH_STYLE === 'true'
    };
}

let cached = { fingerprint: null, client: null };
function client(c) {
    const fingerprint = JSON.stringify([c.region, c.endpoint, c.forcePathStyle]);
    if (cached.fingerprint !== fingerprint) {
        // Checksums de cuerpo SOLO cuando la operación los exige: los automáticos del SDK (desde 2025) rompen varios almacenamientos
        // compatibles con S3, y la integridad del contenido ya la garantiza el GCM de cada bloque (cualquier byte alterado se detecta).
        cached = {
            fingerprint,
            client: new S3Client({
                region: c.region, endpoint: c.endpoint, forcePathStyle: c.forcePathStyle,
                requestChecksumCalculation: 'WHEN_REQUIRED', responseChecksumValidation: 'WHEN_REQUIRED'
            })
        };
    }
    return cached.client;
}

// `name` ya viene validado como UUID por storage.js
const objectKey = (c, name) => `${c.prefix}files/${name.slice(0, 2)}/${name}.enc`;

const isNotFound = (error) => error?.name === 'NotFound' || error?.name === 'NoSuchKey' || error?.$metadata?.httpStatusCode === 404;

async function put(name, filePath) {
    const c = config();
    const size = (await fs.promises.stat(filePath)).size;
    await client(c).send(new PutObjectCommand({
        Bucket: c.bucket, Key: objectKey(c, name), Body: fs.createReadStream(filePath), ContentLength: size,
        ContentType: 'application/octet-stream',
        ...(c.sse !== 'none' && { ServerSideEncryption: c.sse }),
        ...(c.sse === 'aws:kms' && c.kmsKeyId && { SSEKMSKeyId: c.kmsKeyId })
    }));
    return size;
}

async function remove(name) {
    const c = config();
    await client(c).send(new DeleteObjectCommand({ Bucket: c.bucket, Key: objectKey(c, name) }));
}

async function size(name) {
    const c = config();
    try {
        const head = await client(c).send(new HeadObjectCommand({ Bucket: c.bucket, Key: objectKey(c, name) }));
        return Number(head.ContentLength);
    } catch (error) {
        if (isNotFound(error)) throw new Error('FILE_MISSING');
        throw error;
    }
}

// Fuente de bytes para file-cipher.decryptRange: { size(), stream(from, to) } (from/to inclusivos)
function blob(name) {
    return {
        size: () => size(name),
        stream: (from, to) => (async function* () {
            const c = config();
            let response;
            try {
                response = await client(c).send(new GetObjectCommand({ Bucket: c.bucket, Key: objectKey(c, name), Range: `bytes=${from}-${to}` }));
            } catch (error) {
                if (isNotFound(error)) throw new Error('FILE_MISSING');
                throw error;
            }
            // Un servidor que ignore Range devolvería el objeto entero desde el byte 0: no se acepta (se descifraría mal el rango)
            const range = /^bytes (\d+)-(\d+)\//.exec(response.ContentRange || '');
            if (!range || Number(range[1]) !== from || Number(range[2]) !== to) {
                response.Body?.destroy?.();
                throw new Error('FILE_CORRUPT');
            }
            for await (const piece of response.Body) yield piece;
        })()
    };
}

module.exports = { put, remove, size, blob, objectKey: (name) => objectKey(config(), name), config };
