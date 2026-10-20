const crypto = require('crypto');

// Derivación de claves a partir de variables de entorno. Módulo puro (sin estado global),
// así el servidor y la herramienta de rotación pueden derivar a la vez el juego de claves
// ANTIGUO y el NUEVO sin tocar process.env.
//
// Dos modos:
//
//   estable (recomendado)  KEY_EPOCH definido. Las claves dependen de BASE_SEED, ENCRYPTION_SEED,
//                          JWT_SEED y KEY_EPOCH, y NO cambian hasta que se rote. Rotar = cambiar
//                          ENCRYPTION_SEED, JWT_SEED y KEY_EPOCH y re-cifrar los datos.
//
//   legacy (por defecto)   KEY_EPOCH sin definir. Las claves dependen de BASE_SEED y de la FECHA
//                          UTC de hoy: cambian cada día, así que lo cifrado un día no se puede
//                          descifrar al siguiente. Se conserva solo para poder migrar datos
//                          antiguos (scripts/rotateKeys.js --legacy-scan-days).

const EPOCH_RE = /^[A-Za-z0-9._-]{3,64}$/;
const cache = new Map();

function scrypt(input, salt, length) {
    const key = `${salt}:${length}:${input}`;
    if (!cache.has(key)) {
        if (cache.size > 500) cache.clear(); // el modo legacy escaneando fechas puede generar muchas
        cache.set(key, crypto.scryptSync(input, salt, length).toString('hex'));
    }
    return cache.get(key);
}

function requireValue(name, value) {
    if (!value) throw new Error(`Falta la variable de entorno ${name}`);
    return value;
}

function validateEpoch(epoch) {
    if (!EPOCH_RE.test(epoch || '')) {
        throw new Error('KEY_EPOCH inválido: usa 3-64 caracteres entre letras, números, ".", "_" y "-"');
    }
    return epoch;
}

// Huella pública de una clave (HMAC de una constante): sirve para comparar claves sin revelarlas.
function fingerprint(encryptionKeyHex) {
    return crypto.createHmac('sha256', Buffer.from(encryptionKeyHex, 'hex'))
        .update('secure-server/key-fingerprint/v1')
        .digest('hex')
        .slice(0, 32);
}

function deriveStableKeySet({ baseSeed, encryptionSeed, jwtSeed, epoch }) {
    requireValue('BASE_SEED', baseSeed);
    requireValue('ENCRYPTION_SEED', encryptionSeed);
    requireValue('JWT_SEED', jwtSeed);
    validateEpoch(epoch);

    const encryption = scrypt(`${baseSeed}_${encryptionSeed}_enc_${epoch}`, 'dynamic_salt', 32);
    return {
        mode: 'stable',
        epoch,
        encryption,
        session: scrypt(`${baseSeed}_${encryptionSeed}_sess_${epoch}`, 'dynamic_salt', 32),
        email: scrypt(`${baseSeed}_${encryptionSeed}_email_${epoch}`, 'dynamic_salt', 32),
        jwt: scrypt(`${baseSeed}_${jwtSeed}_jwt_${epoch}`, 'dynamic_salt', 32),
        jwtSigning: scrypt(`${baseSeed}_${jwtSeed}_${epoch}`, 'jwt_salt', 64),
        fingerprint: fingerprint(encryption)
    };
}

// Réplica exacta de las fórmulas que usaban secure-env.js y credential-builder.js
function deriveLegacyKeySet({ baseSeed, jwtSeed, date }) {
    const base = baseSeed || 'default_seed_change_this';
    const encryption = scrypt(`${base}_enc_${date}`, 'dynamic_salt', 32);
    return {
        mode: 'legacy',
        epoch: `legacy-${date}`,
        encryption,
        session: scrypt(`${base}_sess_${date}`, 'dynamic_salt', 32),
        email: scrypt(`${base}_email_${date}`, 'dynamic_salt', 32),
        jwt: scrypt(`${base}_jwt_${date}`, 'dynamic_salt', 32),
        jwtSigning: scrypt(`${baseSeed || 'default'}_${jwtSeed || 'jwt_default'}_${date}`, 'jwt_salt', 64),
        fingerprint: fingerprint(encryption)
    };
}

const todayUTC = () => new Date().toISOString().split('T')[0];

function deriveFromEnv(env = process.env, { today = todayUTC() } = {}) {
    if (env.KEY_EPOCH) {
        return deriveStableKeySet({
            baseSeed: env.BASE_SEED,
            encryptionSeed: env.ENCRYPTION_SEED,
            jwtSeed: env.JWT_SEED,
            epoch: env.KEY_EPOCH
        });
    }
    return deriveLegacyKeySet({ baseSeed: env.BASE_SEED, jwtSeed: env.JWT_SEED, date: today });
}

module.exports = { deriveFromEnv, deriveStableKeySet, deriveLegacyKeySet, fingerprint, validateEpoch, EPOCH_RE };
