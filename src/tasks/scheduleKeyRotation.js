const cron = require('node-cron');
const keyRotator = require('../crypto/keyRotator');
const secureAuthService = require('../security/secure-auth.service');
const secureCommunications = require('../services/secure-communications.service');

class ScheduleKeyRotation {
    constructor() {
        this.isRotationEnabled = process.env.AUTO_ROTATION_ENABLED === 'true';
        this.isRunning = false;
        this.rotationHistory = [];
        this.nextRotationTime = null;

        this.jobs = [];
    }

    // Se arranca desde la elección de líder (src/tasks/leader.js): con varias instancias solo UNA planifica la rotación
    start() {
        if (this.jobs.length > 0) return;
        if (this.isRotationEnabled) {
            this.initializeSchedules();
        } else {
            console.log('⏰ Rotación automática deshabilitada por configuración');
        }
    }

    stop() {
        this.jobs.forEach(job => job.stop());
        this.jobs = [];
    }

    initializeSchedules() {
        console.log('⏰ Inicializando planificador de rotación de claves...');

        // Rotación mensual de claves - día 1 de cada mes a las 2:00 AM
        this.jobs.push(cron.schedule('0 2 1 * *', async () => {
            await this.executeMonthlyRotation();
        }, {
            scheduled: true,
            timezone: "America/Mexico_City"
        }));

        // Limpieza de sesiones expiradas - todos los días a las 3:00 AM
        this.jobs.push(cron.schedule('0 3 * * *', async () => {
            await this.executeSessionCleanup();
        }, {
            scheduled: true,
            timezone: "America/Mexico_City"
        }));

        // Verificación de integridad - cada 6 horas
        this.jobs.push(cron.schedule('0 */6 * * *', async () => {
            await this.executeIntegrityCheck();
        }, {
            scheduled: true,
            timezone: "America/Mexico_City"
        }));

        this.calculateNextRotation();
        console.log('✅ Planificador inicializado');
    }

    async executeMonthlyRotation() {
        if (this.isRunning) {
            console.log('⚠️ Rotación ya en progreso, saltando ejecución');
            return;
        }

        try {
            this.isRunning = true;
            const rotationId = this.generateRotationId();
            const startTime = Date.now();

            console.log(`🔄 Iniciando rotación mensual ${rotationId}...`);

            // Ejecutar rotación de claves
            const rotationResult = await keyRotator.rotateKeys();

            const duration = Date.now() - startTime;

            // Registrar rotación exitosa
            this.rotationHistory.push({
                id: rotationId,
                timestamp: new Date().toISOString(),
                duration,
                status: 'success',
                details: rotationResult
            });

            console.log(`✅ Rotación mensual ${rotationId} completada en ${duration}ms`);

            // Enviar notificación de éxito
            await this.sendRotationSuccessNotification(rotationId, duration, rotationResult);

            this.calculateNextRotation();

        } catch (error) {
            const rotationId = this.generateRotationId();

            console.error(`❌ Error en rotación mensual ${rotationId}:`, error);

            // Registrar rotación fallida
            this.rotationHistory.push({
                id: rotationId,
                timestamp: new Date().toISOString(),
                status: 'failed',
                error: error.message
            });

            // Enviar alerta crítica de fallo
            await secureCommunications.sendSecureAlert({
                type: 'KEY_ROTATION_FAILED',
                severity: 'critical',
                details: `Rotación mensual ${rotationId} falló: ${error.message}`,
                action: 'Se requiere intervención manual inmediata',
                timestamp: new Date().toISOString()
            }, 'critical');

        } finally {
            this.isRunning = false;
        }
    }

    async sendRotationSuccessNotification(rotationId, duration, rotationResult) {
        try {
            await secureCommunications.sendSecureAlert({
                type: 'KEY_ROTATION_SUCCESS',
                severity: 'info',
                details: `Rotación ${rotationId} completada exitosamente`,
                duration: duration,
                timestamp: new Date().toISOString(),
                nextRotation: this.getNextRotationDate()
            }, 'normal');

            console.log(`📧 Notificación de rotación exitosa enviada para ${rotationId}`);

        } catch (error) {
            console.error('❌ Error enviando notificación de rotación exitosa:', error);
        }
    }

    async executeSessionCleanup() {
        if (!require('../maintenance').guard.isOpen()) {
            console.log('⏸️ Limpieza de sesiones omitida: servidor en mantenimiento');
            return;
        }

        try {
            console.log('🧹 Ejecutando limpieza de sesiones expiradas...');

            const db = require('../config/database');

            // Limpiar sesiones expiradas
            const result = await db.query(
                'DELETE FROM user_sessions WHERE expires_at < NOW()'
            );

            if (result.affectedRows > 0) {
                console.log(`🧹 ${result.affectedRows} sesiones expiradas eliminadas`);
            }

            // Limpiar IPs bloqueadas expiradas
            const ipResult = await db.query(
                'DELETE FROM blocked_ips WHERE blocked_until < NOW()'
            );

            if (ipResult.affectedRows > 0) {
                console.log(`🧹 ${ipResult.affectedRows} IPs desbloqueadas automáticamente`);
            }

            console.log('✅ Limpieza de sesiones completada');

        } catch (error) {
            console.error('❌ Error en limpieza de sesiones:', error);
        }
    }

    async executeIntegrityCheck() {
        try {
            if (!require('../maintenance').guard.isOpen()) {
                console.log('⏸️ Verificación de integridad omitida: servidor en mantenimiento');
                return;
            }

            console.log('🔍 Ejecutando verificación de integridad programada...');

            const serverCheck = require('../middleware/serverCheck.middleware');
            await serverCheck.performAsyncCheck();

            console.log('✅ Verificación de integridad completada');

        } catch (error) {
            console.error('❌ Error en verificación de integridad:', error);

            // Enviar alerta si la verificación falla
            await secureCommunications.sendSecureAlert({
                type: 'INTEGRITY_CHECK_FAILED',
                severity: 'high',
                details: `Verificación de integridad falló: ${error.message}`,
                timestamp: new Date().toISOString()
            }, 'high');
        }
    }

    generateRotationId() {
        const date = new Date();
        const year = date.getFullYear();
        const month = String(date.getMonth() + 1).padStart(2, '0');
        const random = Math.random().toString(36).substring(2, 8).toUpperCase();

        return `ROT-${year}${month}-${random}`;
    }

    calculateNextRotation() {
        const now = new Date();
        const nextMonth = new Date(now.getFullYear(), now.getMonth() + 1, 1, 2, 0, 0);
        this.nextRotationTime = nextMonth;
    }

    getNextRotationDate() {
        return this.nextRotationTime ? this.nextRotationTime.toISOString() : null;
    }

    // Método para ejecutar rotación manual
    async executeManualRotation() {
        console.log('🔄 Ejecutando rotación manual de claves...');

        if (this.isRunning) {
            throw new Error('Ya hay una rotación en progreso');
        }

        try {
            this.isRunning = true;
            const rotationId = this.generateRotationId();

            console.log(`🚀 Iniciando rotación manual ${rotationId}...`);

            const result = await keyRotator.rotateKeys();

            this.rotationHistory.push({
                id: rotationId,
                timestamp: new Date().toISOString(),
                status: 'success',
                type: 'manual',
                details: result
            });

            console.log(`✅ Rotación manual ${rotationId} completada`);
            return { success: true, rotationId, result };

        } catch (error) {
            console.error('❌ Error en rotación manual:', error);
            throw error;
        } finally {
            this.isRunning = false;
        }
    }

    getScheduleStatus() {
        return {
            isEnabled: this.isRotationEnabled,
            isRunning: this.isRunning,
            nextRotation: this.getNextRotationDate(),
            rotationHistory: this.rotationHistory.slice(-10),
            totalRotations: this.rotationHistory.length
        };
    }
}

module.exports = new ScheduleKeyRotation();