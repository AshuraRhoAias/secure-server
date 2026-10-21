const crypto = require('crypto');
const secureEnv = require('../config/secure-env');

// FORMATO HEREDADO (solo lectura de datos antiguos). Desde la v4 el cifrado nuevo es un único
// AES-256-GCM (ver tripleEncryptor.js). Los tres niveles originales usaban LA MISMA clave, así que
// apilarlos no añadía seguridad; se conservan únicamente para poder descifrar (y migrar) datos
// cifrados con el formato anterior. Este módulo no escribe nada en consola: ni claves, ni IV, ni
// fragmentos de texto cifrado.
class Level1Encryption {
    constructor() {
        this.algorithm = 'aes-256-cbc';
        this.getKey = () => secureEnv.getSecret('encryption');
    }

    encrypt(text) {
        const key = Buffer.from(this.getKey(), 'hex');
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv(this.algorithm, key, iv);

        let encrypted = cipher.update(text, 'utf8', 'hex');
        encrypted += cipher.final('hex');

        return iv.toString('hex') + ':' + encrypted;
    }

    decrypt(encryptedText) {
        const parts = String(encryptedText).split(':');
        if (parts.length !== 2) throw new Error('Formato de texto cifrado inválido (L1)');

        const iv = Buffer.from(parts[0], 'hex');
        const key = Buffer.from(this.getKey(), 'hex');
        const decipher = crypto.createDecipheriv(this.algorithm, key, iv);

        let decrypted = decipher.update(parts[1], 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return decrypted;
    }
}

module.exports = new Level1Encryption();
