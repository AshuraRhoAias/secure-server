const crypto = require('crypto');

// Keyring: guarda las claves de las épocas ANTERIORES, cifradas con la clave ACTUAL.
//
// Cada mes el backup nuevo se cifra con la clave vigente (que al rotar pasa a ser "la anterior").
// Para poder re-cifrarlo con la clave nueva el mes siguiente hace falta conservar esa clave
// anterior, pero no en claro: se guarda aquí envuelta con la clave actual. Así con la clave
// actual se puede abrir todo (los backups con épocas viejas pasan por el keyring), y no hay
// ninguna clave antigua suelta en disco.

const FORMAT_VERSION = 1;

function wrapKey(wrapKeyHex) {
    return Buffer.from(crypto.hkdfSync('sha256', Buffer.from(wrapKeyHex, 'hex'), Buffer.alloc(0), 'secure-server/keyring/v1', 32));
}

// entries: Map(epoch -> encryptionKeyHex)
function buildKeyring(entries, { wrapKeyHex, wrapEpoch }) {
    const key = wrapKey(wrapKeyHex);
    return {
        formatVersion: FORMAT_VERSION,
        wrappedUnder: wrapEpoch,
        updatedAt: new Date().toISOString(),
        entries: [...entries].map(([epoch, keyHex]) => {
            const iv = crypto.randomBytes(12);
            const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
            cipher.setAAD(Buffer.from(`${epoch}|${wrapEpoch}`));
            const data = Buffer.concat([cipher.update(keyHex, 'utf8'), cipher.final()]);
            return {
                epoch,
                iv: iv.toString('base64'),
                tag: cipher.getAuthTag().toString('base64'),
                data: data.toString('base64')
            };
        })
    };
}

// Devuelve Map(epoch -> encryptionKeyHex). Lanza si la clave de envoltura no es la correcta.
function openKeyring(keyring, wrapKeyHex) {
    if (!keyring || keyring.formatVersion !== FORMAT_VERSION) throw new Error('Keyring con formato desconocido');

    const key = wrapKey(wrapKeyHex);
    const result = new Map();

    for (const entry of keyring.entries) {
        const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(entry.iv, 'base64'));
        decipher.setAAD(Buffer.from(`${entry.epoch}|${keyring.wrappedUnder}`));
        decipher.setAuthTag(Buffer.from(entry.tag, 'base64'));
        try {
            const keyHex = Buffer.concat([decipher.update(Buffer.from(entry.data, 'base64')), decipher.final()]).toString('utf8');
            result.set(entry.epoch, keyHex);
        } catch {
            throw new Error(`El keyring no se puede abrir con la clave de la época actual (entrada ${entry.epoch})`);
        }
    }
    return result;
}

module.exports = { buildKeyring, openKeyring };
