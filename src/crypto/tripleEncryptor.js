const level1 = require('./level1');
const level2 = require('./level2');
const level3 = require('./level3');
const { clog } = require('./debug');

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
                clog(`🔐 Cifrado Level ${i + 1} aplicado`);
            }

            this.encryptionMetrics.totalEncryptions++;
            clog(`⚡ Triple cifrado completado en ${Date.now() - startTime}ms`);

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
                clog(`🔓 Descifrado Level ${i + 1} aplicado`);
            }

            this.encryptionMetrics.totalDecryptions++;
            clog(`⚡ Triple descifrado completado en ${Date.now() - startTime}ms`);

            return decrypted;
        } catch (error) {
            this.encryptionMetrics.errors++;
            console.error('❌ Error en triple descifrado:', error);
            throw new Error('Error en triple descifrado');
        }
    }

    // Ejecuta fn (SÍNCRONA) usando una clave concreta en los tres niveles en vez de la del
    // entorno. Lo usa la migración para descifrar con la clave antigua y cifrar con la nueva
    // sin tocar process.env. `quiet` silencia los logs por operación (hay miles en una migración).
    withKey(encryptionKeyHex, fn, { quiet = false } = {}) {
        const savedKeys = this.levels.map(level => level.getKey);
        const methods = ['log', 'info', 'debug', 'warn', 'error'];
        const savedConsole = Object.fromEntries(methods.map(m => [m, console[m]]));

        this.levels.forEach(level => { level.getKey = () => encryptionKeyHex; });
        if (quiet) {
            // También `error`: probar una clave equivocada es una operación normal en una migración
            // y los niveles vuelcan fragmentos del texto cifrado al fallar.
            methods.forEach(m => { console[m] = () => {}; });
        }

        try {
            return fn();
        } finally {
            this.levels.forEach((level, i) => { level.getKey = savedKeys[i]; });
            methods.forEach(m => { console[m] = savedConsole[m]; });
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