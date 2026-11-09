const { execFileSync } = require('child_process');
const path = require('path');

// Envoltura de secretos con un KMS/HSM: los valores sensibles del .env (semillas de las claves, contraseñas...)
// pueden guardarse CIFRADOS por un servicio externo en lugar de en claro:
//
//     ENCRYPTION_SEED=kms:aws:AQICAHj...        (en vez del valor en claro)
//
// Qué protege:   el robo del archivo .env, de un backup, del repositorio o de un volcado de la configuración
//                ya no revela las claves: sin acceso al KMS (y a su política de permisos) no se pueden usar.
// Qué NO protege: a quien ejecute código DENTRO del proceso en marcha (necesita la clave para cifrar y la
//                tiene en memoria). Eso solo lo evita hacer cada operación de cifrado en el HSM, que no es
//                viable a esta escala. Ver docs/SEGURIDAD.md.
//
// Proveedores (variable KMS_PROVIDER, solo para ENVOLVER; al leer manda el que figura en cada valor):
//   file    clave de envoltura (KEK) en un archivo con permisos 0400 (secreto montado, systemd-creds, volumen
//           aparte...). Es la opción sin dependencias externas; la seguridad es la del lugar donde esté la KEK.
//   vault   HashiCorp Vault, motor Transit.
//   aws     AWS KMS (clave simétrica; con CloudHSM/clave en HSM si así se configura en AWS).
//
// Las llamadas de red las hace un proceso hijo (kms-worker.js) para que todo el arranque siga siendo
// SÍNCRONO (las claves se derivan al cargar el módulo). El texto claro vuelve por una tubería, no por
// argumentos ni variables de entorno.

const PREFIX = 'kms:';
const WORKER = path.join(__dirname, 'kms-worker.js');
const cache = new Map(); // "NOMBRE\0kms:..." -> texto claro (solo en memoria de este proceso)

const isWrapped = (value) => typeof value === 'string' && value.startsWith(PREFIX);
const enabled = () => Boolean(process.env.KMS_PROVIDER);

function callWorker(op, items, provider) {
    let output;
    try {
        output = execFileSync(process.execPath, [WORKER], {
            input: JSON.stringify({ op, items, provider }),
            env: process.env,
            timeout: Number(process.env.KMS_TIMEOUT_MS) || 30_000,
            maxBuffer: 10 * 1024 * 1024,
            stdio: ['pipe', 'pipe', 'pipe']
        });
    } catch (error) {
        const detail = (error.stderr?.toString() || error.message).trim().split('\n').pop();
        throw new Error(`KMS: no se pudo ${op === 'wrap' ? 'cifrar' : 'descifrar'} (${detail})`);
    }
    const result = JSON.parse(output.toString('utf8'));
    if (!result.ok) throw new Error(`KMS: ${result.error}`);
    return result.items;
}

// Descifra un valor envuelto (o devuelve el valor tal cual si no lo está)
function resolveValue(name, value) {
    if (!isWrapped(value)) return value;
    const key = `${name}\0${value}`;
    if (!cache.has(key)) cache.set(key, callWorker('unwrap', [{ name, value }])[0].value);
    return cache.get(key);
}

// Descifra varios de una vez (una sola ejecución del proceso hijo)
function resolveMany(entries) {
    const missing = entries.filter(([name, value]) => isWrapped(value) && !cache.has(`${name}\0${value}`));
    if (missing.length > 0) {
        const results = callWorker('unwrap', missing.map(([name, value]) => ({ name, value })));
        missing.forEach(([name, value], i) => cache.set(`${name}\0${value}`, results[i].value));
    }
    return entries.map(([name, value]) => resolveValue(name, value));
}

// Sustituye en process.env todos los valores envueltos por su texto claro (se llama al cargar secure-env).
// Si el KMS no responde, lanza: el servidor NO arranca con claves que no puede descifrar.
function resolveProcessEnv(env = process.env) {
    const entries = Object.entries(env).filter(([, value]) => isWrapped(value));
    if (entries.length === 0) return 0;
    const plain = resolveMany(entries);
    entries.forEach(([name], i) => { env[name] = plain[i]; });
    return entries.length;
}

// Copia de `env` con los valores envueltos resueltos (para derivar claves de un entorno ajeno, como hace la rotación)
function resolveEnvCopy(env) {
    if (!Object.values(env).some(isWrapped)) return env;
    const copy = { ...env };
    const entries = Object.entries(copy).filter(([, value]) => isWrapped(value));
    const plain = resolveMany(entries);
    entries.forEach(([name], i) => { copy[name] = plain[i]; });
    return copy;
}

function wrapMany(entries, provider = process.env.KMS_PROVIDER) {
    if (!provider) throw new Error('KMS: define KMS_PROVIDER (file | vault | aws)');
    const results = callWorker('wrap', entries.map(([name, value]) => ({ name, value })), provider);
    results.forEach((result, i) => cache.set(`${entries[i][0]}\0${result.value}`, entries[i][1]));
    return results.map(result => result.value);
}

const wrapValue = (name, value, provider) => wrapMany([[name, value]], provider)[0];

// Para la rotación: envuelve SOLO lo que se escribe a disco; en memoria sigue en claro. Sin KMS_PROVIDER no toca nada.
function wrapUpdates(updates, names) {
    if (!enabled()) return updates;
    const toWrap = Object.entries(updates).filter(([name]) => names.includes(name));
    const wrapped = wrapMany(toWrap);
    const out = { ...updates };
    toWrap.forEach(([name], i) => { out[name] = wrapped[i]; });
    return out;
}

const clearCache = () => cache.clear();

module.exports = { clearCache, PREFIX, isWrapped, enabled, resolveValue, resolveMany, resolveProcessEnv, resolveEnvCopy, wrapValue, wrapMany, wrapUpdates };
