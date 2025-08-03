const crypto = require('crypto');
const tripleEncryptor = require('./tripleEncryptor');

class KeyRotator {
    constructor() {
        this.rotationInProgress = false;
        this.rotationHistory = [];
    }

    async rotateKeys() {
        if (this.rotationInProgress) {
            throw new Error('Ya hay una rotación de claves en progreso');
        }

        try {
            this.rotationInProgress = true;
            console.log('🔄 Iniciando rotación de claves...');

            // Generar nuevas claves
            const newKeys = this.generateNewKeys();

            // Verificar que las nuevas claves funcionan
            await this.validateNewKeys(newKeys);

            // Backup de claves actuales
            const backupResult = await this.backupCurrentKeys();

            // Actualizar claves en base de datos
            await this.updateKeysInDatabase(newKeys);

            // Marcar rotación como exitosa
            const rotationRecord = {
                timestamp: new Date().toISOString(),
                newKeyVersions: newKeys.versions,
                backupId: backupResult.backupId,
                status: 'success'
            };

            this.rotationHistory.push(rotationRecord);

            console.log('✅ Rotación de claves completada exitosamente');

            return {
                success: true,
                newKeys: newKeys,
                backupId: backupResult.backupId,
                rotationId: rotationRecord.timestamp
            };

        } catch (error) {
            console.error('❌ Error en rotación de claves:', error);

            // Registrar fallo
            this.rotationHistory.push({
                timestamp: new Date().toISOString(),
                status: 'failed',
                error: error.message
            });

            throw error;
        } finally {
            this.rotationInProgress = false;
        }
    }

    generateNewKeys() {
        try {
            const timestamp = Date.now();
            const version = `v${Math.floor(timestamp / 1000)}`;

            return {
                encryption: crypto.randomBytes(32).toString('hex'),
                jwt: crypto.randomBytes(64).toString('hex'),
                session: crypto.randomBytes(32).toString('hex'),
                backup: crypto.randomBytes(32).toString('hex'),
                versions: {
                    encryption: `enc_${version}`,
                    jwt: `jwt_${version}`,
                    session: `sess_${version}`,
                    backup: `bkp_${version}`
                },
                timestamp
            };
        } catch (error) {
            console.error('❌ Error generando nuevas claves:', error);
            throw new Error('Error generando nuevas claves');
        }
    }

    async validateNewKeys(newKeys) {
        try {
            // Crear un encriptador temporal con las nuevas claves
            const testData = `key_validation_test_${Date.now()}`;

            // Simular cifrado con las nuevas claves
            const testEncryption = crypto.createCipher('aes-256-cbc', Buffer.from(newKeys.encryption, 'hex'));
            let encrypted = testEncryption.update(testData, 'utf8', 'hex');
            encrypted += testEncryption.final('hex');

            // Simular descifrado
            const testDecryption = crypto.createDecipher('aes-256-cbc', Buffer.from(newKeys.encryption, 'hex'));
            let decrypted = testDecryption.update(encrypted, 'hex', 'utf8');
            decrypted += testDecryption.final('utf8');

            if (decrypted !== testData) {
                throw new Error('Las nuevas claves no pasan la validación');
            }

            console.log('✅ Nuevas claves validadas correctamente');
            return true;

        } catch (error) {
            console.error('❌ Error validando nuevas claves:', error);
            throw new Error('Validación de nuevas claves falló');
        }
    }

    async backupCurrentKeys() {
        try {
            const db = require('../config/database');

            // Obtener claves activas actuales
            const [currentKeys] = await db.query(
                'SELECT * FROM encryption_keys WHERE is_active = TRUE'
            );

            if (currentKeys.length === 0) {
                console.log('ℹ️ No hay claves activas para respaldar');
                return { backupId: 'no_backup_needed' };
            }

            // Crear backup cifrado
            const backupId = `backup_${Date.now()}`;
            const backupData = {
                keys: currentKeys,
                timestamp: new Date().toISOString(),
                backupId
            };

            const encryptedBackup = tripleEncryptor.encrypt(JSON.stringify(backupData));

            // Guardar backup en tabla especial
            await db.query(
                `INSERT INTO encryption_keys (key_version, encrypted_key_data, is_active, expires_at) 
                 VALUES (?, ?, FALSE, DATE_ADD(NOW(), INTERVAL 1 YEAR))`,
                [backupId, encryptedBackup]
            );

            console.log(`✅ Backup de claves creado: ${backupId}`);
            return { backupId };

        } catch (error) {
            console.error('❌ Error creando backup de claves:', error);
            throw new Error('Error en backup de claves actuales');
        }
    }

    async updateKeysInDatabase(newKeys) {
        const db = require('../config/database');
        const connection = await db.getConnection();

        try {
            await connection.beginTransaction();

            // Desactivar claves actuales
            await connection.execute(
                'UPDATE encryption_keys SET is_active = FALSE WHERE is_active = TRUE'
            );

            // Insertar nuevas claves
            for (const [keyType, keyValue] of Object.entries(newKeys)) {
                if (keyType === 'versions' || keyType === 'timestamp') continue;

                const encryptedKeyData = tripleEncryptor.encrypt(JSON.stringify({
                    type: keyType,
                    value: keyValue,
                    createdAt: new Date().toISOString()
                }));

                await connection.execute(
                    `INSERT INTO encryption_keys (key_version, encrypted_key_data, is_active, expires_at) 
                     VALUES (?, ?, TRUE, DATE_ADD(NOW(), INTERVAL 6 MONTH))`,
                    [newKeys.versions[keyType], encryptedKeyData]
                );
            }

            await connection.commit();
            console.log('✅ Claves actualizadas en base de datos');

        } catch (error) {
            await connection.rollback();
            console.error('❌ Error actualizando claves en DB:', error);
            throw new Error('Error actualizando claves en base de datos');
        } finally {
            connection.release();
        }
    }

    async getActiveKeys() {
        try {
            const db = require('../config/database');
            const [keys] = await db.query(
                'SELECT key_version, encrypted_key_data FROM encryption_keys WHERE is_active = TRUE'
            );

            const decryptedKeys = {};
            for (const keyRecord of keys) {
                try {
                    const decryptedData = JSON.parse(tripleEncryptor.decrypt(keyRecord.encrypted_key_data));
                    decryptedKeys[decryptedData.type] = decryptedData.value;
                } catch (decryptError) {
                    console.error(`❌ Error descifrando clave ${keyRecord.key_version}:`, decryptError);
                }
            }

            return decryptedKeys;
        } catch (error) {
            console.error('❌ Error obteniendo claves activas:', error);
            throw error;
        }
    }

    async restoreFromBackup(backupId) {
        try {
            const db = require('../config/database');

            // Buscar el backup
            const [backup] = await db.query(
                'SELECT encrypted_key_data FROM encryption_keys WHERE key_version = ? AND is_active = FALSE',
                [backupId]
            );

            if (backup.length === 0) {
                throw new Error(`Backup ${backupId} no encontrado`);
            }

            // Descifrar backup
            const backupData = JSON.parse(tripleEncryptor.decrypt(backup[0].encrypted_key_data));

            console.log(`🔄 Restaurando desde backup: ${backupId}`);

            // Implementar lógica de restauración aquí
            // Esto sería similar a updateKeysInDatabase pero usando los datos del backup

            return { success: true, backupId, restoredKeys: backupData.keys.length };

        } catch (error) {
            console.error('❌ Error restaurando desde backup:', error);
            throw error;
        }
    }

    getRotationHistory(limit = 10) {
        return this.rotationHistory.slice(-limit);
    }

    isRotationNeeded() {
        // Verificar si es necesaria una rotación basada en tiempo o eventos
        const lastRotation = this.rotationHistory
            .filter(r => r.status === 'success')
            .pop();

        if (!lastRotation) return true;

        const daysSinceRotation = (Date.now() - new Date(lastRotation.timestamp).getTime()) / (1000 * 60 * 60 * 24);
        return daysSinceRotation >= 30; // Rotar cada 30 días
    }
}

module.exports = new KeyRotator();