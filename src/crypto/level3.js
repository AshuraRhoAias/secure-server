const crypto = require('crypto');
const secureEnv = require('../config/secure-env');

class Level3Encryption {
    constructor() {
        this.algorithm = 'chacha20-poly1305';
        this.getKey = () => secureEnv.getSecret('encryption');
    }

    encrypt(text) {
        try {
            const key = Buffer.from(this.getKey(), 'hex');
            const iv = crypto.randomBytes(12); // nonce para chacha20-poly1305
            const cipher = crypto.createCipheriv(this.algorithm, key, iv, { authTagLength: 16 });

            let encrypted = cipher.update(text, 'utf8', 'hex');
            encrypted += cipher.final('hex');

            const authTag = cipher.getAuthTag();

            const result = iv.toString('hex') + ':' + authTag.toString('hex') + ':' + encrypted;

            // Validación de integridad
            console.log(`🔐 Level 3 encrypt - IV: ${iv.toString('hex').length}, AuthTag: ${authTag.toString('hex').length}, Data: ${encrypted.length}`);

            return result;
        } catch (error) {
            console.error('❌ Error en cifrado Level 3:', error);
            throw new Error('Error en cifrado Level 3');
        }
    }

    decrypt(encryptedText) {
        try {
            // Validación inicial
            if (!encryptedText || typeof encryptedText !== 'string') {
                throw new Error('Texto cifrado inválido o vacío');
            }

            const parts = encryptedText.split(':');
            if (parts.length !== 3) {
                throw new Error(`Formato de texto cifrado inválido. Esperado 3 partes, recibido ${parts.length}`);
            }

            const [ivHex, authTagHex, encryptedDataHex] = parts;

            // Validación de longitudes hexadecimales (deben ser pares)
            if (ivHex.length % 2 !== 0) {
                throw new Error(`IV hex corruptos: longitud ${ivHex.length} (debe ser par)`);
            }

            if (authTagHex.length % 2 !== 0) {
                throw new Error(`AuthTag hex corruptos: longitud ${authTagHex.length} (debe ser par)`);
            }

            if (encryptedDataHex.length % 2 !== 0) {
                throw new Error(`Datos hex corruptos: longitud ${encryptedDataHex.length} (debe ser par). Datos recibidos: "${encryptedDataHex}"`);
            }

            // Validación de longitudes esperadas
            if (ivHex.length !== 24) { // 12 bytes = 24 hex chars
                throw new Error(`IV incorrecto: esperado 24 caracteres, recibido ${ivHex.length}`);
            }

            if (authTagHex.length !== 32) { // 16 bytes = 32 hex chars
                throw new Error(`AuthTag incorrecto: esperado 32 caracteres, recibido ${authTagHex.length}`);
            }

            console.log(`🔍 Level 3 decrypt - IV: ${ivHex.length}, AuthTag: ${authTagHex.length}, Data: ${encryptedDataHex.length}`);

            const iv = Buffer.from(ivHex, 'hex');
            const authTag = Buffer.from(authTagHex, 'hex');
            const key = Buffer.from(this.getKey(), 'hex');

            const decipher = crypto.createDecipheriv(this.algorithm, key, iv, { authTagLength: 16 });
            decipher.setAuthTag(authTag);

            let decrypted = decipher.update(encryptedDataHex, 'hex', 'utf8');
            decrypted += decipher.final('utf8');

            return decrypted;
        } catch (error) {
            console.error('❌ Error en descifrado Level 3:', error);
            console.error('❌ Datos problemáticos:', {
                original: encryptedText,
                length: encryptedText?.length,
                parts: encryptedText?.split(':').map((part, i) => ({
                    index: i,
                    length: part.length,
                    isEven: part.length % 2 === 0,
                    content: part.substring(0, 50) + (part.length > 50 ? '...' : '')
                }))
            });
            throw new Error('Error en descifrado Level 3');
        }
    }

    // Método auxiliar para validar la integridad de datos cifrados
    validateEncryptedData(encryptedText) {
        try {
            if (!encryptedText || typeof encryptedText !== 'string') {
                return { valid: false, error: 'Texto cifrado inválido o vacío' };
            }

            const parts = encryptedText.split(':');
            if (parts.length !== 3) {
                return { valid: false, error: `Formato inválido: ${parts.length} partes en lugar de 3` };
            }

            const [iv, authTag, data] = parts;

            const validations = [
                { name: 'IV', value: iv, expectedLength: 24 },
                { name: 'AuthTag', value: authTag, expectedLength: 32 },
                { name: 'Data', value: data, expectedLength: null }
            ];

            for (const validation of validations) {
                if (validation.value.length % 2 !== 0) {
                    return {
                        valid: false,
                        error: `${validation.name} longitud impar: ${validation.value.length}`
                    };
                }

                if (validation.expectedLength && validation.value.length !== validation.expectedLength) {
                    return {
                        valid: false,
                        error: `${validation.name} longitud incorrecta: ${validation.value.length}, esperado: ${validation.expectedLength}`
                    };
                }
            }

            return { valid: true };
        } catch (error) {
            return { valid: false, error: error.message };
        }
    }
}

module.exports = new Level3Encryption();