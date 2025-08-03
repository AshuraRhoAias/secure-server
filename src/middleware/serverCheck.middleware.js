const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

class ServerCheckMiddleware {
    constructor() {
        this.lastIntegrityCheck = null;
        this.serverFingerprint = null;
        this.criticalFiles = [
            'src/index.js',
            'src/config/database.js',
            'src/crypto/tripleEncryptor.js',
            'src/security/secure-auth.service.js'
        ];
        this.initializeFingerprint();
    }

    initializeFingerprint() {
        try {
            this.serverFingerprint = this.calculateServerFingerprint();
            console.log('🔒 Fingerprint del servidor inicializado');
        } catch (error) {
            console.error('❌ Error inicializando fingerprint del servidor:', error);
        }
    }

    calculateServerFingerprint() {
        try {
            const fileHashes = [];

            for (const filePath of this.criticalFiles) {
                if (fs.existsSync(filePath)) {
                    const fileContent = fs.readFileSync(filePath, 'utf8');
                    const hash = crypto.createHash('sha256').update(fileContent).digest('hex');
                    fileHashes.push(`${filePath}:${hash}`);
                }
            }

            const combinedHash = crypto.createHash('sha256')
                .update(fileHashes.join('|'))
                .digest('hex');

            return combinedHash;
        } catch (error) {
            console.error('❌ Error calculando fingerprint:', error);
            return null;
        }
    }

    async performIntegrityCheck() {
        try {
            const currentFingerprint = this.calculateServerFingerprint();

            if (!currentFingerprint) {
                throw new Error('No se pudo calcular el fingerprint actual');
            }

            if (this.serverFingerprint !== currentFingerprint) {
                console.log('🚨 ¡ALERTA! Cambio de integridad detectado en el servidor');

                // Registrar el incidente
                await this.logIntegrityBreach(this.serverFingerprint, currentFingerprint);

                // Enviar alerta inmediata
                await this.sendIntegrityAlert();

                return {
                    compromised: true,
                    originalFingerprint: this.serverFingerprint,
                    currentFingerprint: currentFingerprint
                };
            }

            this.lastIntegrityCheck = Date.now();

            // Registrar verificación exitosa
            await this.logIntegrityCheck(currentFingerprint);

            return {
                compromised: false,
                fingerprint: currentFingerprint,
                lastCheck: this.lastIntegrityCheck
            };

        } catch (error) {
            console.error('❌ Error en verificación de integridad:', error);
            throw error;
        }
    }

    async logIntegrityCheck(fingerprint) {
        try {
            const db = require('../config/database');
            const tripleEncryptor = require('../crypto/tripleEncryptor');

            const systemData = {
                fingerprint,
                timestamp: new Date().toISOString(),
                criticalFiles: this.criticalFiles,
                processInfo: {
                    nodeVersion: process.version,
                    platform: process.platform,
                    uptime: process.uptime()
                }
            };

            const encryptedSystemData = tripleEncryptor.encrypt(JSON.stringify(systemData));

            await db.query(
                `INSERT INTO server_integrity (fingerprint_hash, system_data_encrypted, status) 
                 VALUES (?, ?, 'secure') 
                 ON DUPLICATE KEY UPDATE 
                 system_data_encrypted = VALUES(system_data_encrypted), 
                 last_check = NOW(), 
                 status = 'secure'`,
                [fingerprint, encryptedSystemData]
            );

        } catch (error) {
            console.error('❌ Error logging integrity check:', error);
        }
    }

    async logIntegrityBreach(originalFingerprint, currentFingerprint) {
        try {
            const db = require('../config/database');
            const tripleEncryptor = require('../crypto/tripleEncryptor');

            const breachData = {
                event: 'INTEGRITY_BREACH',
                originalFingerprint,
                currentFingerprint,
                timestamp: new Date().toISOString(),
                criticalFiles: this.criticalFiles,
                severity: 'CRITICAL'
            };

            const encryptedBreachData = tripleEncryptor.encrypt(JSON.stringify(breachData));

            // Log en security_logs
            await db.query(
                `INSERT INTO security_logs (event_type, encrypted_details, severity) 
                 VALUES ('SERVER_INTEGRITY_BREACH', ?, 'critical')`,
                [encryptedBreachData]
            );

            // Actualizar tabla de integridad
            await db.query(
                `UPDATE server_integrity SET status = 'compromised', last_check = NOW() 
                 WHERE fingerprint_hash = ?`,
                [originalFingerprint]
            );

        } catch (error) {
            console.error('❌ Error logging integrity breach:', error);
        }
    }

    async sendIntegrityAlert() {
        try {
            const secureCommunications = require('../services/secure-communications.service');

            await secureCommunications.sendSecureAlert({
                type: 'SERVER_INTEGRITY_BREACH',
                severity: 'critical',
                details: 'Se ha detectado un cambio no autorizado en archivos críticos del servidor',
                action: 'Verificación inmediata requerida',
                timestamp: new Date().toISOString()
            }, 'critical');

        } catch (error) {
            console.error('❌ Error enviando alerta de integridad:', error);
        }
    }

    // Middleware para verificar integridad en cada request crítico
    checkIntegrity() {
        return async (req, res, next) => {
            try {
                // Solo verificar en operaciones críticas
                const criticalPaths = ['/api/users', '/api/auth', '/api/admin'];
                const isCriticalPath = criticalPaths.some(path => req.path.startsWith(path));

                if (!isCriticalPath) {
                    return next();
                }

                // Verificar si ha pasado suficiente tiempo desde la última verificación
                const timeSinceLastCheck = Date.now() - (this.lastIntegrityCheck || 0);
                const checkInterval = 60 * 60 * 1000; // 1 hora

                if (timeSinceLastCheck > checkInterval) {
                    const result = await this.performIntegrityCheck();

                    if (result.compromised) {
                        return res.status(503).json({
                            success: false,
                            message: 'Servicio temporalmente no disponible por razones de seguridad',
                            code: 'INTEGRITY_COMPROMISED'
                        });
                    }
                }

                next();

            } catch (error) {
                console.error('❌ Error en middleware de integridad:', error);
                next(); // Continuar para no romper la aplicación
            }
        };
    }

    // Método para verificación asíncrona (usado por cron jobs)
    async performAsyncCheck() {
        try {
            console.log('🔍 Ejecutando verificación de integridad programada...');
            const result = await this.performIntegrityCheck();

            if (result.compromised) {
                console.log('🚨 SERVIDOR COMPROMETIDO - Alerta enviada');
            } else {
                console.log('✅ Integridad del servidor verificada');
            }

            return result;
        } catch (error) {
            console.error('❌ Error en verificación asíncrona:', error);
            throw error;
        }
    }

    getStatus() {
        return {
            serverFingerprint: this.serverFingerprint,
            lastIntegrityCheck: this.lastIntegrityCheck,
            criticalFiles: this.criticalFiles,
            checkInterval: '1 hour'
        };
    }
}

module.exports = new ServerCheckMiddleware();