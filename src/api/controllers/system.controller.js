const serverCheck = require('../../middleware/serverCheck.middleware');
const secureCommunications = require('../../services/secure-communications.service');
const anomalyDetection = require('../../security/anomaly-detection.service');
const scheduleKeyRotation = require('../../tasks/scheduleKeyRotation');
const audit = require('../../services/audit.service');
const { getNetworkPosture } = require('../../security/network-hardening.check');

class SystemController {
    constructor() {
        // Los métodos se pasan como handlers de Express: preservar `this`
        Object.getOwnPropertyNames(SystemController.prototype)
            .filter(name => name !== 'constructor')
            .forEach(name => { this[name] = this[name].bind(this); });
    }

    async getSystemStatus(req, res) {
        try {
            const integrityStatus = serverCheck.getStatus();
            const encryptionMetrics = require('../../crypto/tripleEncryptor').getMetrics();
            const protectionStats = require('../../middleware/protection.middleware').getProtectionStats();

            res.json({
                success: true,
                status: {
                    server: {
                        uptime: process.uptime(),
                        nodeVersion: process.version,
                        platform: process.platform,
                        environment: process.env.NODE_ENV || 'development'
                    },
                    security: {
                        integrityCheck: integrityStatus,
                        communications: secureCommunications.getStats(),
                        rotationSchedule: scheduleKeyRotation.getScheduleStatus(),
                        anomalies: anomalyDetection.getStats(),
                        // Qué puede hacer este proceso en la red (CAP_NET_RAW, ping sin privilegios...)
                        networkPosture: getNetworkPosture()
                    },
                    encryption: encryptionMetrics,
                    protection: protectionStats,
                    timestamp: new Date().toISOString()
                }
            });

        } catch (error) {
            console.error('❌ Error obteniendo estado del sistema:', error);
            res.status(500).json({
                success: false,
                message: 'Error obteniendo estado del sistema'
            });
        }
    }

    async performIntegrityCheck(req, res) {
        try {
            const result = await serverCheck.performAsyncCheck();

            res.json({
                success: true,
                message: 'Verificación de integridad completada',
                result
            });

        } catch (error) {
            console.error('❌ Error en verificación de integridad:', error);
            res.status(500).json({
                success: false,
                message: 'Error en verificación de integridad'
            });
        }
    }

    // La rotación bloquea el servidor entero y reescribe los datos y el .env: no se dispara por HTTP.
    // Se ejecuta con `npm run rotate-keys` (con confirmación explícita) o por el planificador mensual.
    async rotateKeys(req, res) {
        res.status(501).json({
            success: false,
            message: 'La rotación de claves no se puede lanzar por la API. Usa "npm run rotate-keys" en el servidor o el planificador mensual (AUTO_ROTATION_ENABLED=true).',
            code: 'USE_CLI'
        });
    }

    async getRotationStatus(req, res) {
        try {
            const { guard, getRotationService } = require('../../maintenance');
            const service = getRotationService();
            const secureEnv = require('../../config/secure-env');
            const journal = service.readJournal();

            res.json({
                success: true,
                rotation: {
                    keys: secureEnv.getKeyInfo(),
                    guard: guard.state,
                    lastRotation: journal && {
                        id: journal.id, phase: journal.phase, startedAt: journal.startedAt,
                        finishedAt: journal.finishedAt, oldEpoch: journal.oldEpoch, newEpoch: journal.newEpoch
                    },
                    // Solo metadatos de la cabecera: sin claves ni datos
                    backups: service.listBackups().map(b => ({
                        name: require('path').basename(b.file), epoch: b.epoch, createdAt: b.createdAt,
                        bytes: b.bytes, compression: b.compression, rawBytes: b.rawBytes, tables: b.tables
                    }))
                }
            });
        } catch (error) {
            console.error('❌ Error obteniendo estado de rotación:', error);
            res.status(500).json({ success: false, message: 'Error obteniendo estado de rotación' });
        }
    }

    async testCommunications(req, res) {
        try {
            const results = await secureCommunications.testChannels();

            res.json({
                success: true,
                message: 'Test de comunicaciones completado',
                results
            });

        } catch (error) {
            console.error('❌ Error en test de comunicaciones:', error);
            res.status(500).json({
                success: false,
                message: 'Error en test de comunicaciones'
            });
        }
    }

    async getSecurityLogs(req, res) {
        try {
            const { severity } = req.query;
            const page = Math.max(1, parseInt(req.query.page, 10) || 1);
            const limit = Math.min(200, Math.max(1, parseInt(req.query.limit, 10) || 50));
            const offset = (page - 1) * limit;

            if (severity && !['low', 'medium', 'high', 'critical'].includes(severity)) {
                return res.status(400).json({
                    success: false,
                    message: 'severity debe ser low, medium, high o critical',
                    code: 'VALIDATION_ERROR'
                });
            }

            const db = require('../../config/database');
            let query = `
                SELECT id, event_type, ip_address, timestamp, severity, risk_score 
                FROM security_logs 
            `;
            let params = [];

            if (severity) {
                query += ' WHERE severity = ?';
                params.push(severity);
            }

            // page/limit ya son enteros acotados; se interpolan porque LIMIT con
            // parámetros preparados falla en algunas versiones de MySQL 8.
            query += ` ORDER BY timestamp DESC, id DESC LIMIT ${limit} OFFSET ${offset}`;

            const [logs] = await db.query(query, params);

            // Contar total
            let countQuery = 'SELECT COUNT(*) as total FROM security_logs';
            let countParams = [];

            if (severity) {
                countQuery += ' WHERE severity = ?';
                countParams.push(severity);
            }

            const [countResult] = await db.query(countQuery, countParams);
            const total = countResult[0].total;

            res.json({
                success: true,
                logs,
                pagination: {
                    page,
                    limit,
                    total,
                    pages: Math.ceil(total / limit)
                }
            });

        } catch (error) {
            console.error('❌ Error obteniendo logs de seguridad:', error);
            res.status(500).json({
                success: false,
                message: 'Error obteniendo logs de seguridad'
            });
        }
    }

    async getBlockedIPs(req, res) {
        try {
            const db = require('../../config/database');
            const [ips] = await db.query(
                `SELECT ip_address, reason, blocked_until, block_count, created_at
                 FROM blocked_ips ORDER BY created_at DESC LIMIT 200`
            );

            res.json({ success: true, blockedIPs: ips });
        } catch (error) {
            console.error('❌ Error obteniendo IPs bloqueadas:', error);
            res.status(500).json({
                success: false,
                message: 'Error obteniendo IPs bloqueadas'
            });
        }
    }

    async unblockIP(req, res) {
        try {
            const ip = req.params.ip;

            if (!require('net').isIP(ip)) {
                return res.status(400).json({
                    success: false,
                    message: 'Dirección IP inválida',
                    code: 'VALIDATION_ERROR'
                });
            }

            const unblocked = await anomalyDetection.unblockIP(ip);

            if (!unblocked) {
                return res.status(500).json({
                    success: false,
                    message: 'No se pudo desbloquear la IP'
                });
            }

            await audit.log('IP_UNBLOCKED_MANUALLY', { ip }, { req, severity: 'medium', riskScore: 10 });

            res.json({ success: true, message: `IP ${ip} desbloqueada` });
        } catch (error) {
            console.error('❌ Error desbloqueando IP:', error);
            res.status(500).json({
                success: false,
                message: 'Error desbloqueando IP'
            });
        }
    }
}

module.exports = new SystemController();