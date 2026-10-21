const crypto = require('crypto');
const secureEnv = require('../config/secure-env');

// FORMATO HEREDADO (solo lectura de datos antiguos): ver level1.js.
class Level2Encryption {
    constructor() {
        this.algorithm = 'aes-256-gcm';
        this.getKey = () => secureEnv.getSecret('encryption');
    }

    encrypt(text) {
        const key = Buffer.from(this.getKey(), 'hex');
        const iv = crypto.randomBytes(12);
        const cipher = crypto.createCipheriv(this.algorithm, key, iv);

        let encrypted = cipher.update(text, 'utf8', 'hex');
        encrypted += cipher.final('hex');

        return iv.toString('hex') + ':' + cipher.getAuthTag().toString('hex') + ':' + encrypted;
    }

    decrypt(encryptedText) {
        const parts = String(encryptedText).split(':');
        if (parts.length !== 3) throw new Error('Formato de texto cifrado inválido (L2)');

        const key = Buffer.from(this.getKey(), 'hex');
        const decipher = crypto.createDecipheriv(this.algorithm, key, Buffer.from(parts[0], 'hex'));
        decipher.setAuthTag(Buffer.from(parts[1], 'hex'));

        let decrypted = decipher.update(parts[2], 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return decrypted;
    }
}

module.exports = new Level2Encryption();
