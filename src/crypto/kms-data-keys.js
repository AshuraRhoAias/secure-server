// CLAVES DE ARCHIVO ENVUELTAS POR EL KMS/HSM.
//
// Por defecto la clave de cada archivo (user_files.key_encrypted) se envuelve con la clave maestra del servidor. Con
// KMS_DATA_KEYS=true se envuelve DIRECTAMENTE con el KMS: quien robe la base de datos y las semillas del servidor sigue
// sin poder abrir los archivos, porque la clave que los protege nunca sale del KMS/HSM y cada descifrado queda en su
// registro de auditoría.
//
//   formato:  kms1:<proveedor>:<blob>     (el blob va ligado a "file:<storage_name>": copiarlo a otra fila falla)
//
// Una fila protegida así NO la toca la rotación de la clave maestra (no depende de ella) ni el snapshot de backup
// (se guarda tal cual: restaurar exige acceso al mismo KMS). Se pasa de un modo a otro con
// `npm run kms -- migrate-files | unmigrate-files | rewrap-files`.

const { providers } = require('./kms-providers');

const PREFIX = 'kms1:';
const MAX_CACHE = 500;
const cache = new Map(); // valor guardado -> { key, expires }

const isKmsKey = (value) => typeof value === 'string' && value.startsWith(PREFIX);
const enabled = () => process.env.KMS_DATA_KEYS === 'true' && Boolean(process.env.KMS_PROVIDER);
const nameFor = (storageName) => `file:${storageName}`;
const ttlMs = () => Math.max(0, Number(process.env.KMS_DATA_KEY_CACHE_SECONDS ?? 300)) * 1000;

function remember(stored, key) {
    const ttl = ttlMs();
    if (ttl === 0) return;
    if (cache.size >= MAX_CACHE) cache.delete(cache.keys().next().value);
    cache.set(stored, { key: Buffer.from(key), expires: Date.now() + ttl });
}

async function wrapDataKey(storageName, key, provider = process.env.KMS_PROVIDER) {
    const impl = providers[provider];
    if (!impl) throw new Error(`KMS: proveedor desconocido o sin definir (${provider || 'KMS_PROVIDER'})`);
    const stored = `${PREFIX}${provider}:${await impl.wrap(nameFor(storageName), key.toString('hex'))}`;
    remember(stored, key);
    return stored;
}

async function unwrapDataKey(storageName, stored) {
    const hit = cache.get(stored);
    if (hit && hit.expires > Date.now()) return Buffer.from(hit.key);
    cache.delete(stored);

    const [, provider, ...rest] = stored.split(':');
    const impl = providers[provider];
    if (!impl) throw new Error(`KMS: proveedor desconocido en la clave del archivo (${provider})`);
    const key = Buffer.from(await impl.unwrap(nameFor(storageName), rest.join(':')), 'hex');
    if (key.length !== 32) throw new Error('KMS: la clave del archivo no tiene 32 bytes');
    remember(stored, key);
    return key;
}

const clearCache = () => cache.clear();

module.exports = { PREFIX, isKmsKey, enabled, wrapDataKey, unwrapDataKey, clearCache };
