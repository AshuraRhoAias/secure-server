// Servidores simulados de Vault (Transit) y de AWS KMS para las pruebas. Se ejecutan en OTRO PROCESO: kms.js
// hace sus llamadas de forma síncrona (bloquea el proceso que las pide), así que un servidor en el mismo
// proceso se quedaría sin atender.
//
//   node mock-kms-server.js vault|aws
//
// Imprime "PORT <n>". GET /__last devuelve la última petición recibida (cabeceras y cuerpo).

const http = require('http');
const crypto = require('crypto');

const kind = process.argv[2];
const MASTER = crypto.randomBytes(32);
let last = null;

const seal = (plain, aad = '') => {
    const iv = crypto.randomBytes(12);
    const c = crypto.createCipheriv('aes-256-gcm', MASTER, iv);
    c.setAAD(Buffer.from(aad));
    const data = Buffer.concat([c.update(plain), c.final()]);
    return Buffer.concat([iv, c.getAuthTag(), data]);
};
const open = (blob, aad = '') => {
    const d = crypto.createDecipheriv('aes-256-gcm', MASTER, blob.subarray(0, 12));
    d.setAAD(Buffer.from(aad));
    d.setAuthTag(blob.subarray(12, 28));
    return Buffer.concat([d.update(blob.subarray(28)), d.final()]);
};

http.createServer(async (req, res) => {
    let raw = '';
    for await (const chunk of req) raw += chunk;
    const reply = (status, body, type = 'application/json') => { res.writeHead(status, { 'Content-Type': type }); res.end(JSON.stringify(body)); };

    if (req.url === '/__last') return reply(200, last);
    last = { method: req.method, url: req.url, headers: req.headers, body: raw };
    const body = raw ? JSON.parse(raw) : {};

    if (kind === 'vault') {
        if (req.headers['x-vault-token'] !== 's.token-valido') return reply(403, { errors: ['permission denied'] });
        const m = /^\/v1\/(\w+)\/(encrypt|decrypt)\/([\w-]+)$/.exec(req.url);
        if (!m) return reply(404, { errors: ['no handler'] });
        if (m[2] === 'encrypt') return reply(200, { data: { ciphertext: 'vault:v1:' + seal(Buffer.from(body.plaintext, 'base64'), m[3]).toString('base64') } });
        try {
            const blob = Buffer.from(body.ciphertext.replace(/^vault:v1:/, ''), 'base64');
            return reply(200, { data: { plaintext: open(blob, m[3]).toString('base64') } });
        } catch { return reply(400, { errors: ['cipher: message authentication failed'] }); }
    }

    // AWS KMS (protocolo JSON 1.1)
    const target = req.headers['x-amz-target'];
    if (!String(req.headers.authorization || '').startsWith('AWS4-HMAC-SHA256')) return reply(400, { __type: 'MissingAuthenticationTokenException' }, 'application/x-amz-json-1.1');
    const context = JSON.stringify(Object.entries(body.EncryptionContext || {}).sort());
    if (target === 'TrentService.Encrypt') {
        return reply(200, { CiphertextBlob: seal(Buffer.from(body.Plaintext, 'base64'), context + body.KeyId).toString('base64'), KeyId: body.KeyId }, 'application/x-amz-json-1.1');
    }
    if (target === 'TrentService.Decrypt') {
        try {
            const blob = Buffer.from(body.CiphertextBlob, 'base64');
            return reply(200, { Plaintext: open(blob, context + body.KeyId).toString('base64'), KeyId: body.KeyId }, 'application/x-amz-json-1.1');
        } catch { return reply(400, { __type: 'InvalidCiphertextException' }, 'application/x-amz-json-1.1'); }
    }
    reply(400, { __type: 'UnknownOperationException' }, 'application/x-amz-json-1.1');
}).listen(0, '127.0.0.1', function () { console.log(`PORT ${this.address().port}`); });
