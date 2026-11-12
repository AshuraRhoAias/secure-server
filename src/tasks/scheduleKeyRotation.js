const crypto = require('crypto');
const cron = require('node-cron');
const keyRotator = require('../crypto/keyRotator');
const secureAuthService = require('../security/secure-auth.service');
const secureCommunications = require('../services/secure-communications.service');

class ScheduleKeyRotation {
    constructor() {
        this.isRotationEnabled = process.env.AUTO_ROTATION_ENABLED === 'true';
        // Rotación programada: SEMANAL por defecto (domingo 2:00). Descifra y vuelve a cifrar TODO con claves nuevas, con el
        // servidor en mantenimiento (sin entradas ni salidas) mientras dura. Formato cron de 5 campos.
        this.rotationCron = process.env.KEY_ROTATION_CRON || '0 2 * * 0';
        this.timezone = process.env.KEY_ROTATION_TZ || 'America/Mexico_City';
        this.isRunning = false;
        this.rotationHistory = [];

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

        // Rotación de claves (por defecto semanal). Se niega a planificarla si no puede funcionar: mejor un aviso al arrancar
        // que una rotación que falla cada semana dejando el servidor en mantenimiento.
        const refusal = this.rotationRefusal();
        if (refusal) {
            console.error(`⛔ Rotación programada NO activada: ${refusal}`);
        } else {
            this.jobs.push(cron.schedule(this.rotationCron, async () => {
                await this.executeScheduledRotation();
            }, { scheduled: true, timezone: this.timezone }));
            console.log(`🔄 Rotación de claves programada: "${this.rotationCron}" (${this.timezone})`);
        }

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

        console.log('✅ Planificador inicializado');
    }

    // Por qué no se puede planificar la rotación (o null si se puede)
    rotationRefusal() {
        if (!cron.validate(this.rotationCron)) return `KEY_ROTATION_CRON no es una expresión cron válida: "${this.rotationCron}"`;
        const mode = require('../config/secure-env').getKeyInfo().mode;
        if (mode !== 'stable') {
            return 'las claves están en modo legacy (sin KEY_EPOCH): cambian cada día y la rotación se negaría. Define KEY_EPOCH (y migra con scripts/rotateKeys.js --legacy-scan-days si ya hay datos)';
        }
        return null;
    }

    async executeScheduledRotation() {
        if (this.isRunning) {
            console.log('⚠️ Rotación ya en progreso, saltando ejecución');
            return;
        }

        try {
            this.isRunning = true;
            const rotationId = this.generateRotationId();
            const startTime = Date.now();

            console.log(`🔄 Iniciando rotación programada ${rotationId}...`);

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

            console.log(`✅ Rotación programada ${rotationId} completada en ${duration}ms`);

            // Enviar notificación de éxito
            await this.sendRotationSuccessNotification(rotationId, duration, rotationResult);

        } catch (error) {
            const rotationId = this.generateRotationId();

            console.error(`❌ Error en rotación programada ${rotationId}:`, error);

            // Registrar rotación fallida
            this.rotationHistory.push({
                id: rotationId,
                timestamp: new Date().toISOString(),
                status: 'failed',
                error: error.message
            });

            // Alerta crítica de fallo: es lo ÚNICO que sale mientras el servidor está en mantenimiento (ver
            // secure-communications). Texto fijo: el detalle del error se queda en los registros del servidor, no en un correo.
            await secureCommunications.sendSecureAlert({
                type: 'KEY_ROTATION_FAILED',
                severity: 'critical',
                details: `La rotación programada ${rotationId} falló en la fase ${error.rotationPhase || 'desconocida'}. ` +
                    'Los datos no se han perdido: si la base de datos no llegó a confirmar, se reabrió con las claves anteriores; si llegó, ' +
                    'el servidor sigue en mantenimiento hasta ejecutar "npm run rotate-keys -- recover". Detalle en los registros del servidor.',
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
                schedule: this.scheduleDescription()
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
            const [result] = await db.query(
                'DELETE FROM user_sessions WHERE expires_at < NOW()'
            );

            if (result.affectedRows > 0) {
                console.log(`🧹 ${result.affectedRows} sesiones expiradas eliminadas`);
            }

            // Limpiar IPs bloqueadas expiradas
            const [ipResult] = await db.query(
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
                details: 'La verificación de integridad programada falló (detalle en los registros del servidor)',
                timestamp: new Date().toISOString()
            }, 'high');
        }
    }

    generateRotationId() {
        const date = new Date();
        const year = date.getFullYear();
        const month = String(date.getMonth() + 1).padStart(2, '0');
        const random = crypto.randomBytes(3).toString('hex').toUpperCase();

        return `ROT-${year}${month}-${random}`;
    }

    // Programación legible ("0 2 * * 0" en America/Mexico_City). No se calcula la fecha de la próxima ejecución: node-cron 4.2
    // la da mal para expresiones semanales (devuelve 2034).
    scheduleDescription() {
        return `${this.rotationCron} (${this.timezone})`;
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
            schedule: this.scheduleDescription(),
            rotationHistory: this.rotationHistory.slice(-10),
            totalRotations: this.rotationHistory.length
        };
    }
}

module.exports = new ScheduleKeyRotation();