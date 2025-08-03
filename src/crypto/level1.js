const crypto = require('crypto');
const secureEnv = require('../config/secure-env');

class Level1Encryption {
    constructor() {
        this.algorithm = 'aes-256-cbc';
        this.getKey = () => secureEnv.getSecret('encryption');
    }

    encrypt(text) {
        try {
            const key = Buffer.from(this.getKey(), 'hex');
            const iv = crypto.randomBytes(16);
            const cipher = crypto.createCipheriv(this.algorithm, key, iv);

            let encrypted = cipher.update(text, 'utf8', 'hex');
            encrypted += cipher.final('hex');

            return iv.toString('hex') + ':' + encrypted;
        } catch (error) {
            console.error('❌ Error en cifrado Level 1:', error);
            throw new Error('Error en cifrado Level 1');
        }
    }

    decrypt(encryptedText) {
        try {
            const parts = encryptedText.split(':');
            if (parts.length !== 2) {
                throw new Error('Formato de texto cifrado inválido');
            }

            const iv = Buffer.from(parts[0], 'hex');
            const encryptedData = parts[1];
            const key = Buffer.from(this.getKey(), 'hex');

            const decipher = crypto.createDecipheriv(this.algorithm, key, iv);

            let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
            decrypted += decipher.final('utf8');

            return decrypted;
        } catch (error) {
            console.error('❌ Error en descifrado Level 1:', error);
            throw new Error('Error en descifrado Level 1');
        }
    }
}

module.exports = new Level1Encryption();
