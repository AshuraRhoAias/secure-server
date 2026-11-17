// S3 SIMULADO para las pruebas (estilo de ruta: /<bucket>/<clave>). Lo justo de la API real que usa src/files/s3-store.js:
// PutObject, GetObject (con Range → 206 + Content-Range), HeadObject y DeleteObject. Exige una firma SigV4 en cada petición
// (no la verifica criptográficamente: comprueba que el SDK firma), entiende cuerpos aws-chunked y permite inyectar fallos.

const http = require('http');

function decodeAwsChunked(buffer) {
    // <tamaño hex>[;chunk-signature=…]\r\n<datos>\r\n … 0\r\n[trailers]\r\n\r\n
    const parts = [];
    let offset = 0;
    for (;;) {
        const lineEnd = buffer.indexOf('\r\n', offset);
        if (lineEnd < 0) break;
        const size = parseInt(buffer.subarray(offset, lineEnd).toString().split(';')[0], 16);
        if (!Number.isFinite(size) || size === 0) break;
        parts.push(buffer.subarray(lineEnd + 2, lineEnd + 2 + size));
        offset = lineEnd + 2 + size + 2;
    }
    return Buffer.concat(parts);
}

async function createMockS3({ bucket = 'secure-server-test' } = {}) {
    const objects = new Map();          // clave → { body, headers }
    const log = [];                     // { method, key, range, sse, authorized }
    const behaviors = { failPut: false, ignoreRange: false };

    const server = http.createServer((req, res) => {
        const chunks = [];
        req.on('data', c => chunks.push(c));
        req.on('end', () => {
            const url = new URL(req.url, 'http://x');
            const [, bucketName, ...rest] = url.pathname.split('/');
            const key = decodeURIComponent(rest.join('/'));
            const authorized = /^AWS4-HMAC-SHA256 Credential=[^/]+\/\d{8}\/[a-z0-9-]+\/s3\/aws4_request/.test(req.headers.authorization || '');
            log.push({ method: req.method, key, range: req.headers.range || null, sse: req.headers['x-amz-server-side-encryption'] || null, kmsKeyId: req.headers['x-amz-server-side-encryption-aws-kms-key-id'] || null, authorized });

            const xmlError = (status, code) => {
                res.writeHead(status, { 'Content-Type': 'application/xml' });
                res.end(req.method === 'HEAD' ? undefined : `<?xml version="1.0" encoding="UTF-8"?><Error><Code>${code}</Code><Message>${code}</Message></Error>`);
            };
            if (!authorized) return xmlError(403, 'AccessDenied');
            if (bucketName !== bucket) return xmlError(404, 'NoSuchBucket');

            if (req.method === 'PUT') {
                if (behaviors.failPut) return xmlError(500, 'InternalError');
                let body = Buffer.concat(chunks);
                const encoding = String(req.headers['content-encoding'] || '');
                if (encoding.includes('aws-chunked') || /^STREAMING-/.test(String(req.headers['x-amz-content-sha256'] || ''))) body = decodeAwsChunked(body);
                objects.set(key, { body, sse: req.headers['x-amz-server-side-encryption'] || null });
                res.writeHead(200, { ETag: '"mock"' });
                return res.end();
            }
            const object = objects.get(key);
            if (req.method === 'DELETE') { objects.delete(key); res.writeHead(204); return res.end(); }
            if (!object) return xmlError(404, req.method === 'HEAD' ? 'NotFound' : 'NoSuchKey');

            if (req.method === 'HEAD') {
                res.writeHead(200, { 'Content-Length': object.body.length, 'Content-Type': 'application/octet-stream' });
                return res.end();
            }
            if (req.method === 'GET') {
                const match = /^bytes=(\d+)-(\d+)$/.exec(req.headers.range || '');
                if (match && !behaviors.ignoreRange) {
                    const start = Number(match[1]);
                    const end = Math.min(Number(match[2]), object.body.length - 1);
                    if (start >= object.body.length) return xmlError(416, 'InvalidRange');
                    res.writeHead(206, { 'Content-Length': end - start + 1, 'Content-Range': `bytes ${start}-${end}/${object.body.length}` });
                    return res.end(object.body.subarray(start, end + 1));
                }
                res.writeHead(200, { 'Content-Length': object.body.length });
                return res.end(object.body);
            }
            return xmlError(405, 'MethodNotAllowed');
        });
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    return {
        bucket, objects, log, behaviors,
        endpoint: `http://127.0.0.1:${server.address().port}`,
        close: () => new Promise(resolve => server.close(resolve))
    };
}

module.exports = { createMockS3 };
