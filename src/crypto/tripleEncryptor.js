const crypto = require('crypto');
const secureEnv = require('../config/secure-env');
const level1 = require('./level1');
const level2 = require('./level2');
const level3 = require('./level3');

// CIFRADOR DE CAMPOS (el nombre del archivo se conserva por compatibilidad con el resto del código).
//
// Formato v4 (el que se ESCRIBE): un único AES-256-GCM con autenticación.
//
//     v4:<base64( iv[12] | authTag[16] | ciphertext )>
//
// - La clave se separa por propósito con HKDF-SHA256 a partir de la clave maestra, así que la clave
//   que cifra campos de BD nunca es la misma que usa otro componente.
// - IV aleatorio de 96 bits por mensaje; AAD fijo que liga el texto cifrado a este formato.
// - Cualquier alteración del texto cifrado (un bit) hace fallar el descifrado.
//
// Formato heredado (solo se LEE): los datos cifrados antes de la v4 usaban tres capas
// (AES-CBC → AES-GCM → ChaCha20) con LA MISMA clave. Seguirán descifrándose, y la próxima rotación
// de claves los re-cifra en v4 (npm run rotate-keys). No se registra nada en consola.
//
// Límite a tener en cuenta: con IV aleatorio de 96 bits conviene no superar ~2^32 mensajes con la
// misma clave; la rotación periódica de claves existe, entre otras cosas, para eso.

const V4_PREFIX = 'v4:';
const V4_AAD = Buffer.from('secure-server/field/v4');
const HKDF_INFO = 'secure-server/v4/field-encryption';

class FieldEncryptor {
    constructor() {
        this.legacyLevels = [level1, level2, level3];
        this.getKey = () => secureEnv.getSecret('encryption');
        this.encryptionMetrics = { totalEncryptions: 0, totalDecryptions: 0, errors: 0 };
    }

    _fieldKey() {
        const masterHex = this.getKey();
        if (typeof masterHex !== 'string' || !/^[0-9a-fA-F]{64}$/.test(masterHex)) {
            throw new Error('Clave de cifrado inválida');
        }
        return Buffer.from(crypto.hkdfSync('sha256', Buffer.from(masterHex, 'hex'), Buffer.alloc(0), HKDF_INFO, 32));
    }

    isLegacy(value) {
        return typeof value === 'string' && !value.startsWith(V4_PREFIX);
    }

    encrypt(text) {
        try {
            if (typeof text !== 'string') throw new TypeError('Solo se puede cifrar texto');

            const iv = crypto.randomBytes(12);
            const cipher = crypto.createCipheriv('aes-256-gcm', this._fieldKey(), iv, { authTagLength: 16 });
            cipher.setAAD(V4_AAD);
            const data = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);

            this.encryptionMetrics.totalEncryptions++;
            return V4_PREFIX + Buffer.concat([iv, cipher.getAuthTag(), data]).toString('base64');
        } catch (error) {
            this.encryptionMetrics.errors++;
            throw new Error('Error al cifrar');
        }
    }

    decrypt(encryptedText) {
        try {
            if (typeof encryptedText !== 'string' || encryptedText.length === 0) throw new TypeError('Texto cifrado inválido');

            let plain;
            if (encryptedText.startsWith(V4_PREFIX)) {
                const raw = Buffer.from(encryptedText.slice(V4_PREFIX.length), 'base64');
                if (raw.length < 28) throw new Error('Texto cifrado truncado');

                const decipher = crypto.createDecipheriv('aes-256-gcm', this._fieldKey(), raw.subarray(0, 12), { authTagLength: 16 });
                decipher.setAAD(V4_AAD);
                decipher.setAuthTag(raw.subarray(12, 28));
                plain = Buffer.concat([decipher.update(raw.subarray(28)), decipher.final()]).toString('utf8');
            } else {
                // Formato heredado de tres capas: L3 → L2 → L1
                plain = encryptedText;
                for (let i = this.legacyLevels.length - 1; i >= 0; i--) plain = this.legacyLevels[i].decrypt(plain);
            }

            this.encryptionMetrics.totalDecryptions++;
            return plain;
        } catch (error) {
            this.encryptionMetrics.errors++;
            throw new Error('Error al descifrar');
        }
    }

    // Ejecuta fn (SÍNCRONA) usando una clave concreta en vez de la del entorno. Lo usa la migración
    // para descifrar con la clave antigua y cifrar con la nueva sin tocar process.env.
    // (`quiet` se acepta por compatibilidad: ya no hay logs que silenciar.)
    withKey(encryptionKeyHex, fn) {
        const savedKey = this.getKey;
        const savedLevelKeys = this.legacyLevels.map(level => level.getKey);

        this.getKey = () => encryptionKeyHex;
        this.legacyLevels.forEach(level => { level.getKey = () => encryptionKeyHex; });

        try {
            return fn();
        } finally {
            this.getKey = savedKey;
            this.legacyLevels.forEach((level, i) => { level.getKey = savedLevelKeys[i]; });
        }
    }

    // Alias de conveniencia (API anterior)
    tripleEncrypt(text) { return this.encrypt(text); }
    tripleDecrypt(text) { return this.decrypt(text); }

    getMetrics() {
        const operations = this.encryptionMetrics.totalEncryptions + this.encryptionMetrics.totalDecryptions;
        return {
            ...this.encryptionMetrics,
            format: 'v4 (AES-256-GCM)',
            errorRate: operations ? this.encryptionMetrics.errors / operations : 0
        };
    }

    // Comprueba que el cifrado actual funciona Y que los datos heredados siguen siendo legibles
    async healthCheck() {
        try {
            const probe = 'health_check_' + crypto.randomBytes(8).toString('hex');
            if (this.decrypt(this.encrypt(probe)) !== probe) throw new Error('El cifrado v4 no es reversible');

            // El formato heredado debe seguir descifrándose con la clave en uso
            let legacy = probe;
            for (const level of this.legacyLevels) legacy = level.encrypt(legacy);
            if (this.decrypt(legacy) !== probe) throw new Error('El formato heredado no es legible');

            // Un texto alterado debe rechazarse
            const tampered = this.encrypt(probe).slice(0, -2) + 'AA';
            let rejected = false;
            try { this.decrypt(tampered); } catch { rejected = true; }
            if (!rejected) throw new Error('Se aceptó un texto cifrado alterado');

            return { healthy: true, message: 'Sistema de cifrado funcionando correctamente' };
        } catch (error) {
            return { healthy: false, message: error.message };
        }
    }
}

module.exports = new FieldEncryptor();
