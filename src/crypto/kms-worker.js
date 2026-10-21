// Proceso hijo de kms.js: hace las llamadas (posiblemente de red) al KMS y devuelve el resultado por stdout.
// Entrada (stdin, JSON): { op: 'wrap'|'unwrap', items: [{name, value}], provider? }
// Salida (stdout, JSON): { ok: true, items: [{value}] } | { ok: false, error }
//
// Cada valor se envuelve junto con SU NOMBRE ("ENCRYPTION_SEED\n<valor>"): un blob de una variable no se puede
// copiar a otra (por ejemplo, pegar el blob de JWT_SEED como ENCRYPTION_SEED) sin que el descifrado lo detecte.

const crypto = require('crypto');
const fs = require('fs');

const PREFIX = 'kms:';
const SEP = '\n';

const fail = (message) => { process.stdout.write(JSON.stringify({ ok: false, error: message })); process.exit(0); };
const b64u = (buffer) => Buffer.from(buffer).toString('base64url');

const bind = (name, value) => Buffer.from(`${name}${SEP}${value}`, 'utf8');
function unbind(name, buffer) {
    const text = buffer.toString('utf8');
    const i = text.indexOf(SEP);
    if (i < 0 || text.slice(0, i) !== name) throw new Error(`el valor no pertenece a la variable ${name}`);
    return text.slice(i + 1);
}

// ------------------------------------------------------------------ file: KEK en un archivo
function loadKek() {
    const file = process.env.KMS_KEK_FILE;
    if (!file) throw new Error('falta KMS_KEK_FILE');
    const stat = fs.statSync(file);
    if ((stat.mode & 0o077) !== 0 && process.env.KMS_KEK_ALLOW_LOOSE_PERMS !== 'true') {
        throw new Error(`${file} es legible por otros usuarios (permisos ${(stat.mode & 0o777).toString(8)}): usa chmod 400`);
    }
    const text = fs.readFileSync(file, 'utf8').trim();
    const key = /^[0-9a-fA-F]{64}$/.test(text) ? Buffer.from(text, 'hex') : Buffer.from(text, 'base64');
    if (key.length !== 32) throw new Error('la KEK debe ser de 32 bytes (64 caracteres hex o base64)');
    return key;
}

const file = {
    async wrap(name, value) {
        const iv = crypto.randomBytes(12);
        const cipher = crypto.createCipheriv('aes-256-gcm', loadKek(), iv);
        cipher.setAAD(Buffer.from('secure-server/kms/file'));
        const data = Buffer.concat([cipher.update(bind(name, value)), cipher.final()]);
        return b64u(Buffer.concat([iv, cipher.getAuthTag(), data]));
    },
    async unwrap(name, payload) {
        const raw = Buffer.from(payload, 'base64url');
        const decipher = crypto.createDecipheriv('aes-256-gcm', loadKek(), raw.subarray(0, 12));
        decipher.setAAD(Buffer.from('secure-server/kms/file'));
        decipher.setAuthTag(raw.subarray(12, 28));
        return unbind(name, Buffer.concat([decipher.update(raw.subarray(28)), decipher.final()]));
    }
};

// ------------------------------------------------------------------ vault: motor Transit
function vaultRequest(pathname, body) {
    const addr = (process.env.VAULT_ADDR || '').replace(/\/$/, '');
    if (!addr) throw new Error('falta VAULT_ADDR');
    if (!addr.startsWith('https://') && process.env.NODE_ENV === 'production' && process.env.VAULT_ALLOW_HTTP !== 'true') {
        throw new Error('VAULT_ADDR debe ser https:// en producción');
    }
    const token = process.env.VAULT_TOKEN || (process.env.VAULT_TOKEN_FILE ? fs.readFileSync(process.env.VAULT_TOKEN_FILE, 'utf8').trim() : '');
    if (!token) throw new Error('falta VAULT_TOKEN (o VAULT_TOKEN_FILE)');

    const mount = process.env.VAULT_TRANSIT_MOUNT || 'transit';
    const key = process.env.VAULT_TRANSIT_KEY || 'secure-server';
    return fetch(`${addr}/v1/${mount}/${pathname}/${key}`, {
        method: 'POST',
        headers: { 'X-Vault-Token': token, 'Content-Type': 'application/json', ...(process.env.VAULT_NAMESPACE && { 'X-Vault-Namespace': process.env.VAULT_NAMESPACE }) },
        body: JSON.stringify(body),
        redirect: 'error',
        signal: AbortSignal.timeout(15_000)
    }).then(async (res) => {
        const json = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(`Vault respondió ${res.status}${json.errors?.length ? `: ${json.errors.join('; ')}` : ''}`);
        return json.data;
    });
}

const vault = {
    async wrap(name, value) {
        const data = await vaultRequest('encrypt', { plaintext: bind(name, value).toString('base64') });
        return b64u(data.ciphertext); // "vault:v1:..." codificado, para no tener ':' extra en el valor
    },
    async unwrap(name, payload) {
        const data = await vaultRequest('decrypt', { ciphertext: Buffer.from(payload, 'base64url').toString('utf8') });
        return unbind(name, Buffer.from(data.plaintext, 'base64'));
    }
};

// ------------------------------------------------------------------ aws: AWS KMS
function awsClient() {
    const { KMSClient } = require('@aws-sdk/client-kms'); // carga perezosa: solo si se usa AWS
    const keyId = process.env.KMS_KEY_ID;
    if (!keyId) throw new Error('falta KMS_KEY_ID');
    return { client: new KMSClient({ ...(process.env.KMS_ENDPOINT && { endpoint: process.env.KMS_ENDPOINT }) }), keyId };
}

const aws = {
    async wrap(name, value) {
        const { EncryptCommand } = require('@aws-sdk/client-kms');
        const { client, keyId } = awsClient();
        const out = await client.send(new EncryptCommand({
            KeyId: keyId, Plaintext: bind(name, value), EncryptionContext: { app: 'secure-server', variable: name }
        }));
        return b64u(out.CiphertextBlob);
    },
    async unwrap(name, payload) {
        const { DecryptCommand } = require('@aws-sdk/client-kms');
        const { client, keyId } = awsClient();
        const out = await client.send(new DecryptCommand({
            KeyId: keyId, CiphertextBlob: Buffer.from(payload, 'base64url'), EncryptionContext: { app: 'secure-server', variable: name }
        }));
        return unbind(name, Buffer.from(out.Plaintext));
    }
};

const providers = { file, vault, aws };

async function main() {
    let input = '';
    for await (const chunk of process.stdin) input += chunk;
    const { op, items, provider } = JSON.parse(input);

    const out = [];
    for (const { name, value } of items) {
        if (op === 'wrap') {
            const impl = providers[provider];
            if (!impl) fail(`proveedor desconocido: ${provider} (file | vault | aws)`);
            out.push({ value: `${PREFIX}${provider}:${await impl.wrap(name, value)}` });
        } else {
            const [, providerName, ...rest] = value.split(':');
            const impl = providers[providerName];
            if (!impl) fail(`proveedor desconocido en el valor de ${name}: ${providerName}`);
            out.push({ value: await impl.unwrap(name, rest.join(':')) });
        }
    }
    process.stdout.write(JSON.stringify({ ok: true, items: out }));
}

main().catch(error => fail(`${error.name === 'Error' ? '' : error.name + ': '}${error.message}`));
