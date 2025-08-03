const crypto = require('crypto');
const secureEnv = require('../config/secure-env');

class Level2Encryption {
    constructor() {
        this.algorithm = 'aes-256-gcm';
        this.getKey = () => secureEnv.getSecret('encryption');
    }

    encrypt(text) {
        try {
            const key = Buffer.from(this.getKey(), 'hex');
            const iv = crypto.randomBytes(12); // 12 bytes para GCM
            const cipher = crypto.createCipheriv(this.algorithm, key, iv);

            let encrypted = cipher.update(text, 'utf8', 'hex');
            encrypted += cipher.final('hex');

            const authTag = cipher.getAuthTag();

            return iv.toString('hex') + ':' + authTag.toString('hex') + ':' + encrypted;
        } catch (error) {
            console.error('❌ Error en cifrado Level 2:', error);
            throw new Error('Error en cifrado Level 2');
        }
    }

    decrypt(encryptedText) {
        try {
            const parts = encryptedText.split(':');
            if (parts.length !== 3) {
                throw new Error('Formato de texto cifrado inválido');
            }

            const iv = Buffer.from(parts[0], 'hex');
            const authTag = Buffer.from(parts[1], 'hex');
            const encryptedData = parts[2];
            const key = Buffer.from(this.getKey(), 'hex');

            const decipher = crypto.createDecipheriv(this.algorithm, key, iv);
            decipher.setAuthTag(authTag);

            let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
            decrypted += decipher.final('utf8');

            return decrypted;
        } catch (error) {
            console.error('❌ Error en descifrado Level 2:', error);
            throw new Error('Error en descifrado Level 2');
        }
    }
}

module.exports = new Level2Encryption();
