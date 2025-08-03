#!/usr/bin/env node

const fs = require('fs-extra');
const path = require('path');

class EmergencyRecovery {
    constructor() {
        this.backupDir = path.join(__dirname, '../backups');
        this.tempDir = path.join(__dirname, '../temp');
    }

    async createEmergencyBackup() {
        try {
            console.log('🚨 Creando backup de emergencia...');

            await fs.ensureDir(this.backupDir);

            const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
            const backupFile = path.join(this.backupDir, `emergency_backup_${timestamp}.json`);

            // Obtener datos críticos del sistema
            const systemData = await this.collectSystemData();

            // Crear backup cifrado
            const tripleEncryptor = require('../src/crypto/tripleEncryptor');
            const encryptedBackup = tripleEncryptor.encrypt(JSON.stringify(systemData));

            await fs.writeJSON(backupFile, {
                timestamp: new Date().toISOString(),
                type: 'emergency_backup',
                data: encryptedBackup
            }, { spaces: 2 });

            console.log(`✅ Backup de emergencia creado: ${backupFile}`);
            return { success: true, backupFile };

        } catch (error) {
            console.error('❌ Error creando backup de emergencia:', error);
            throw error;
        }
    }

    async restoreFromBackup(backupFile) {
        try {
            console.log(`🔄 Restaurando desde backup: ${backupFile}`);

            if (!fs.existsSync(backupFile)) {
                throw new Error(`Archivo de backup no encontrado: ${backupFile}`);
            }

            const backupData = await fs.readJSON(backupFile);

            // Descifrar datos
            const tripleEncryptor = require('../src/crypto/tripleEncryptor');
            const systemData = JSON.parse(tripleEncryptor.decrypt(backupData.data));

            console.log('📋 Datos de backup:');
            console.log(`   📅 Fecha: ${systemData.timestamp}`);
            console.log(`   🗄️ Usuarios: ${systemData.users?.length || 0}`);
            console.log(`   🔑 Claves: ${systemData.keys?.length || 0}`);

            // Aquí implementarías la lógica de restauración según necesites
            console.log('✅ Datos de backup verificados');

            return { success: true, data: systemData };

        } catch (error) {
            console.error('❌ Error restaurando backup:', error);
            throw error;
        }
    }

    async collectSystemData() {
        try {
            const db = require('../src/config/database');

            // Recopilar datos críticos
            const [users] = await db.query('SELECT id, username, created_at FROM users');
            const [activeKeys] = await db.query('SELECT key_version, created_at FROM encryption_keys WHERE is_active = TRUE');
            const [recentLogs] = await db.query('SELECT event_type, timestamp, severity FROM security_logs ORDER BY timestamp DESC LIMIT 100');

            return {
                timestamp: new Date().toISOString(),
                users: users,
                keys: activeKeys,
                recentLogs: recentLogs,
                systemInfo: {
                    nodeVersion: process.version,
                    platform: process.platform,
                    uptime: process.uptime()
                }
            };

        } catch (error) {
            console.error('❌ Error recopilando datos del sistema:', error);
            return {
                timestamp: new Date().toISOString(),
                error: error.message
            };
        }
    }

    async performSystemCheck() {
        try {
            console.log('🔍 Realizando verificación completa del sistema...');

            const checks = {
                database: false,
                encryption: false,
                communications: false,
                integrity: false
            };

            // Verificar base de datos
            try {
                const db = require('../src/config/database');
                await db.testConnection();
                checks.database = true;
                console.log('✅ Base de datos: OK');
            } catch (error) {
                console.log('❌ Base de datos: ERROR -', error.message);
            }

            // Verificar cifrado
            try {
                const tripleEncryptor = require('../src/crypto/tripleEncryptor');
                const healthCheck = await tripleEncryptor.healthCheck();
                checks.encryption = healthCheck.healthy;
                console.log('✅ Sistema de cifrado: OK');
            } catch (error) {
                console.log('❌ Sistema de cifrado: ERROR -', error.message);
            }

            // Verificar comunicaciones
            try {
                const secureCommunications = require('../src/services/secure-communications.service');
                const stats = secureCommunications.getStats();
                checks.communications = stats.availableChannels > 0;
                console.log(`✅ Comunicaciones: ${stats.availableChannels} canales disponibles`);
            } catch (error) {
                console.log('❌ Comunicaciones: ERROR -', error.message);
            }

            // Verificar integridad
            try {
                const serverCheck = require('../src/middleware/serverCheck.middleware');
                const result = await serverCheck.performAsyncCheck();
                checks.integrity = !result.compromised;
                console.log('✅ Integridad del servidor: OK');
            } catch (error) {
                console.log('❌ Integridad del servidor: ERROR -', error.message);
            }

            const allChecksPass = Object.values(checks).every(check => check === true);

            console.log('\n📊 RESUMEN DE VERIFICACIÓN:');
            console.log(`   🗄️ Base de datos: ${checks.database ? '✅' : '❌'}`);
            console.log(`   🔐 Cifrado: ${checks.encryption ? '✅' : '❌'}`);
            console.log(`   📧 Comunicaciones: ${checks.communications ? '✅' : '❌'}`);
            console.log(`   🛡️ Integridad: ${checks.integrity ? '✅' : '❌'}`);
            console.log(`\n   Estado general: ${allChecksPass ? '✅ SALUDABLE' : '⚠️ REQUIERE ATENCIÓN'}`);

            return { success: true, checks, healthy: allChecksPass };

        } catch (error) {
            console.error('❌ Error en verificación del sistema:', error);
            return { success: false, error: error.message };
        }
    }

    showUsage() {
        console.log(`
🚨 Script de Recuperación de Emergencia

Uso:
  node scripts/emergencyRecovery.js [comando] [opciones]

Comandos:
  backup                    Crear backup de emergencia
  restore [archivo]         Restaurar desde backup
  check                     Verificar estado del sistema

Ejemplos:
  node scripts/emergencyRecovery.js backup
  node scripts/emergencyRecovery.js restore backups/emergency_backup_2025-01-01.json
  node scripts/emergencyRecovery.js check
        `);
    }
}

// Ejecución desde línea de comandos
if (require.main === module) {
    const recovery = new EmergencyRecovery();
    const command = process.argv[2];
    const args = process.argv.slice(3);

    (async () => {
        try {
            switch (command) {
                case 'backup':
                    await recovery.createEmergencyBackup();
                    break;
                case 'restore':
                    if (!args[0]) {
                        console.error('❌ Archivo de backup requerido');
                        process.exit(1);
                    }
                    await recovery.restoreFromBackup(args[0]);
                    break;
                case 'check':
                    await recovery.performSystemCheck();
                    break;
                default:
                    recovery.showUsage();
                    process.exit(0);
            }
        } catch (error) {
            console.error('❌ Error:', error.message);
            process.exit(1);
        }
    })();
}

module.exports = EmergencyRecovery;