const level1 = require('./level1');
const level2 = require('./level2');
const level3 = require('./level3');

class TripleEncryptor {
    constructor() {
        this.levels = [level1, level2, level3];
        this.encryptionMetrics = {
            totalEncryptions: 0,
            totalDecryptions: 0,
            errors: 0
        };
    }

    tripleEncrypt(text) {
        try {
            const startTime = Date.now();
            let encrypted = text;

            // Aplicar cifrado en secuencia: L1 → L2 → L3
            for (let i = 0; i < this.levels.length; i++) {
                encrypted = this.levels[i].encrypt(encrypted);
                console.log(`🔐 Cifrado Level ${i + 1} aplicado`);
            }

            this.encryptionMetrics.totalEncryptions++;
            console.log(`⚡ Triple cifrado completado en ${Date.now() - startTime}ms`);

            return encrypted;
        } catch (error) {
            this.encryptionMetrics.errors++;
            console.error('❌ Error en triple cifrado:', error);
            throw new Error('Error en triple cifrado');
        }
    }

    tripleDecrypt(encryptedText) {
        try {
            const startTime = Date.now();
            let decrypted = encryptedText;

            // Aplicar descifrado en orden inverso: L3 → L2 → L1
            for (let i = this.levels.length - 1; i >= 0; i--) {
                decrypted = this.levels[i].decrypt(decrypted);
                console.log(`🔓 Descifrado Level ${i + 1} aplicado`);
            }

            this.encryptionMetrics.totalDecryptions++;
            console.log(`⚡ Triple descifrado completado en ${Date.now() - startTime}ms`);

            return decrypted;
        } catch (error) {
            this.encryptionMetrics.errors++;
            console.error('❌ Error en triple descifrado:', error);
            throw new Error('Error en triple descifrado');
        }
    }

    // Métodos de conveniencia
    encrypt(text) {
        return this.tripleEncrypt(text);
    }

    decrypt(encryptedText) {
        return this.tripleDecrypt(encryptedText);
    }

    // Obtener métricas de rendimiento
    getMetrics() {
        return {
            ...this.encryptionMetrics,
            errorRate: this.encryptionMetrics.errors / (this.encryptionMetrics.totalEncryptions + this.encryptionMetrics.totalDecryptions) || 0
        };
    }

    // Verificar salud del sistema de cifrado
    async healthCheck() {
        try {
            const testData = 'health_check_' + Date.now();
            const encrypted = this.encrypt(testData);
            const decrypted = this.decrypt(encrypted);

            if (decrypted === testData) {
                console.log('✅ Health check de cifrado exitoso');
                return { healthy: true, message: 'Sistema de cifrado funcionando correctamente' };
            } else {
                throw new Error('Datos no coinciden después del cifrado/descifrado');
            }
        } catch (error) {
            console.error('❌ Health check de cifrado falló:', error);
            return { healthy: false, message: error.message };
        }
    }
}

module.exports = new TripleEncryptor();