const crypto = require('crypto');
const secureEnv = require('../config/secure-env');

class Level3Encryption {
    constructor() {
        this.algorithm = 'chacha20-poly1305';
        this.getKey = () => secureEnv.getSecret('encryption');
    }

    /**
     * Método auxiliar para generar hash de clave para debugging (seguro)
     */
    _getKeyHash(key) {
        return crypto.createHash('sha256').update(key).digest('hex').substring(0, 8);
    }

    /**
     * Validar que la clave sea válida para ChaCha20
     */
    _validateKey(key) {
        if (!key) {
            throw new Error('Clave de cifrado no encontrada');
        }
        
        if (typeof key !== 'string') {
            throw new Error('Clave debe ser string hex');
        }
        
        if (key.length !== 64) { // 32 bytes = 64 hex chars
            throw new Error(`Clave incorrecta: esperado 64 caracteres hex, recibido ${key.length}`);
        }
        
        if (!/^[0-9a-fA-F]+$/.test(key)) {
            throw new Error('Clave contiene caracteres no-hexadecimales');
        }
        
        return true;
    }

    encrypt(text) {
        try {
            if (!text || typeof text !== 'string') {
                throw new Error('Texto a cifrar inválido o vacío');
            }

            const rawKey = this.getKey();
            this._validateKey(rawKey);
            
            const key = Buffer.from(rawKey, 'hex');
            const keyHash = this._getKeyHash(key);
            
            console.log(`🔑 Encrypt Key Hash: ${keyHash}...`);
            console.log(`🔐 Cifrando texto de ${text.length} caracteres`);

            const iv = crypto.randomBytes(12); // nonce para chacha20-poly1305
            const cipher = crypto.createCipheriv(this.algorithm, key, iv, { authTagLength: 16 });

            let encrypted = cipher.update(text, 'utf8', 'hex');
            encrypted += cipher.final('hex');

            const authTag = cipher.getAuthTag();
            const result = iv.toString('hex') + ':' + authTag.toString('hex') + ':' + encrypted;

            // Validación de integridad del resultado
            console.log(`🔐 Level 3 encrypt - IV: ${iv.toString('hex').length}, AuthTag: ${authTag.toString('hex').length}, Data: ${encrypted.length}`);
            console.log(`✅ Cifrado exitoso - Resultado: ${result.length} caracteres`);

            // Test inmediato de descifrado para validar
            try {
                this._testDecryption(result, text, keyHash);
            } catch (testError) {
                console.warn(`⚠️ Test de descifrado falló: ${testError.message}`);
            }

            return result;
        } catch (error) {
            console.error('❌ Error en cifrado Level 3:', error.message);
            throw new Error(`Error en cifrado Level 3: ${error.message}`);
        }
    }

    decrypt(encryptedText) {
        try {
            // Validación inicial
            if (!encryptedText || typeof encryptedText !== 'string') {
                throw new Error('Texto cifrado inválido o vacío');
            }

            console.log(`🔍 Iniciando descifrado de ${encryptedText.length} caracteres`);

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
                throw new Error(`Datos hex corruptos: longitud ${encryptedDataHex.length} (debe ser par)`);
            }

            // Validación de longitudes esperadas
            if (ivHex.length !== 24) { // 12 bytes = 24 hex chars
                throw new Error(`IV incorrecto: esperado 24 caracteres, recibido ${ivHex.length}`);
            }

            if (authTagHex.length !== 32) { // 16 bytes = 32 hex chars
                throw new Error(`AuthTag incorrecto: esperado 32 caracteres, recibido ${authTagHex.length}`);
            }

            console.log(`🔍 Level 3 decrypt - IV: ${ivHex.length}, AuthTag: ${authTagHex.length}, Data: ${encryptedDataHex.length}`);

            // Validar y obtener clave
            const rawKey = this.getKey();
            this._validateKey(rawKey);
            
            const key = Buffer.from(rawKey, 'hex');
            const keyHash = this._getKeyHash(key);
            
            console.log(`🔑 Decrypt Key Hash: ${keyHash}...`);

            // Convertir componentes hex a buffers
            const iv = Buffer.from(ivHex, 'hex');
            const authTag = Buffer.from(authTagHex, 'hex');

            // Debug de componentes
            console.log(`🔍 Componentes del descifrado:`);
            console.log(`  - IV: ${ivHex} (${iv.length} bytes)`);
            console.log(`  - AuthTag: ${authTagHex} (${authTag.length} bytes)`);
            console.log(`  - Key hash: ${keyHash}`);
            console.log(`  - Datos cifrados: ${encryptedDataHex.substring(0, 40)}... (${encryptedDataHex.length/2} bytes)`);

            // Crear descifrador
            const decipher = crypto.createDecipheriv(this.algorithm, key, iv, { authTagLength: 16 });
            decipher.setAuthTag(authTag);

            console.log(`🔓 Aplicando descifrado...`);

            let decrypted = decipher.update(encryptedDataHex, 'hex', 'utf8');
            
            // Este es donde probablemente falla
            console.log(`🔓 Finalizando descifrado...`);
            decrypted += decipher.final('utf8');

            console.log(`✅ Descifrado exitoso - Resultado: ${decrypted.length} caracteres`);
            return decrypted;

        } catch (error) {
            console.error('❌ Error en descifrado Level 3:', error.message);
            console.error('❌ Stack trace:', error.stack);
            
            // Debug detallado en caso de error
            console.error('❌ Datos problemáticos:', {
                original: encryptedText?.substring(0, 100) + (encryptedText?.length > 100 ? '...' : ''),
                length: encryptedText?.length,
                parts: encryptedText?.split(':').map((part, i) => ({
                    index: i,
                    length: part.length,
                    isEven: part.length % 2 === 0,
                    content: part.substring(0, 50) + (part.length > 50 ? '...' : '')
                })),
                keyInfo: {
                    exists: !!this.getKey(),
                    length: this.getKey()?.length,
                    hash: this.getKey() ? this._getKeyHash(Buffer.from(this.getKey(), 'hex')) : 'N/A'
                }
            });

            // Sugerir posibles causas
            if (error.message.includes('unable to authenticate data') || 
                error.message.includes('Unsupported state')) {
                console.error('💡 Posibles causas:');
                console.error('   1. Clave de descifrado diferente a la de cifrado');
                console.error('   2. Datos corruptos durante transporte/almacenamiento');
                console.error('   3. AuthTag o IV incorrectos');
                console.error('   4. Datos cifrados con versión diferente del algoritmo');
            }

            throw new Error(`Error en descifrado Level 3: ${error.message}`);
        }
    }

    /**
     * Test interno de descifrado para validar el cifrado
     */
    _testDecryption(encryptedResult, originalText, expectedKeyHash) {
        console.log(`🧪 Test de descifrado interno...`);
        
        const testDecrypted = this.decrypt(encryptedResult);
        
        if (testDecrypted !== originalText) {
            throw new Error('Test de descifrado falló: texto no coincide');
        }
        
        console.log(`✅ Test de descifrado exitoso`);
        return true;
    }

    /**
     * Método auxiliar para validar la integridad de datos cifrados
     */
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

    /**
     * Método de diagnóstico para debug
     */
    diagnose() {
        console.log('🔍 === DIAGNÓSTICO LEVEL 3 ENCRYPTION ===');
        
        try {
            const rawKey = this.getKey();
            console.log('🔑 Clave:');
            console.log(`  - Existe: ${!!rawKey}`);
            console.log(`  - Tipo: ${typeof rawKey}`);
            console.log(`  - Longitud: ${rawKey?.length || 'N/A'}`);
            console.log(`  - Es hex válido: ${rawKey ? /^[0-9a-fA-F]+$/.test(rawKey) : 'N/A'}`);
            console.log(`  - Hash: ${rawKey ? this._getKeyHash(Buffer.from(rawKey, 'hex')) : 'N/A'}`);
            
            console.log('🔧 Configuración:');
            console.log(`  - Algoritmo: ${this.algorithm}`);
            console.log(`  - Crypto disponible: ${!!crypto}`);
            
            // Test básico
            console.log('🧪 Test básico:');
            const testText = 'test123';
            const encrypted = this.encrypt(testText);
            const decrypted = this.decrypt(encrypted);
            console.log(`  - Cifrado/Descifrado: ${testText === decrypted ? '✅ OK' : '❌ FAIL'}`);
            
        } catch (error) {
            console.error('❌ Error en diagnóstico:', error.message);
        }
        
        console.log('🔍 === FIN DIAGNÓSTICO ===');
    }

    /**
     * Método para comparar claves (útil para debug)
     */
    compareKeys(otherKeyHash) {
        const currentKey = this.getKey();
        if (!currentKey) return false;
        
        const currentHash = this._getKeyHash(Buffer.from(currentKey, 'hex'));
        return currentHash === otherKeyHash;
    }
}

module.exports = new Level3Encryption();