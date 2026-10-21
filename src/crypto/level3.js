const crypto = require('crypto');
const secureEnv = require('../config/secure-env');

// FORMATO HEREDADO (solo lectura de datos antiguos): ver level1.js.
// Antes este módulo volcaba a consola el hash de la clave, el IV, el auth tag y fragmentos del
// texto cifrado en cada operación (y más aún al fallar). Eso se eliminó: no se registra nada.
class Level3Encryption {
    constructor() {
        this.algorithm = 'chacha20-poly1305';
        this.getKey = () => secureEnv.getSecret('encryption');
    }

    _key() {
        const raw = this.getKey();
        if (typeof raw !== 'string' || !/^[0-9a-fA-F]{64}$/.test(raw)) {
            throw new Error('Clave de cifrado inválida: se esperan 64 caracteres hex');
        }
        return Buffer.from(raw, 'hex');
    }

    encrypt(text) {
        if (!text || typeof text !== 'string') throw new Error('Texto a cifrar inválido o vacío');

        const iv = crypto.randomBytes(12);
        const cipher = crypto.createCipheriv(this.algorithm, this._key(), iv, { authTagLength: 16 });

        let encrypted = cipher.update(text, 'utf8', 'hex');
        encrypted += cipher.final('hex');

        return iv.toString('hex') + ':' + cipher.getAuthTag().toString('hex') + ':' + encrypted;
    }

    decrypt(encryptedText) {
        if (!encryptedText || typeof encryptedText !== 'string') throw new Error('Texto cifrado inválido o vacío');

        const parts = encryptedText.split(':');
        if (parts.length !== 3) throw new Error('Formato de texto cifrado inválido (L3)');

        const [ivHex, tagHex, dataHex] = parts;
        if (ivHex.length !== 24 || tagHex.length !== 32 || dataHex.length % 2 !== 0) {
            throw new Error('Formato de texto cifrado inválido (L3)');
        }

        const decipher = crypto.createDecipheriv(this.algorithm, this._key(), Buffer.from(ivHex, 'hex'), { authTagLength: 16 });
        decipher.setAuthTag(Buffer.from(tagHex, 'hex'));

        let decrypted = decipher.update(dataHex, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return decrypted;
    }
}

module.exports = new Level3Encryption();
