const serverCheck = require('../../middleware/serverCheck.middleware');
const keyRotator = require('../../crypto/keyRotator');
const secureCommunications = require('../../services/secure-communications.service');

class SystemController {
    async getSystemStatus(req, res) {
        try {
            const integrityStatus = serverCheck.getStatus();
            const encryptionMetrics = require('../../crypto/tripleEncryptor').getMetrics();
            const protectionStats = require('../../middleware/protection.middleware').getProtectionStats();

            res.json({
                success: true,
                status: {
                    integrity: integrityStatus,
                    encryption: encryptionMetrics,
                    protection: protectionStats,
                    uptime: process.uptime(),
                    nodeVersion: process.version,
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

    async rotateKeys(req, res) {
        try {
            const result = await keyRotator.rotateKeys();

            res.json({
                success: true,
                message: 'Rotación de claves completada',
                rotationId: result.rotationId
            });

        } catch (error) {
            console.error('❌ Error en rotación de claves:', error);
            res.status(500).json({
                success: false,
                message: error.message
            });
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
            const { page = 1, limit = 50, severity } = req.query;
            const offset = (page - 1) * limit;

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

            query += ' ORDER BY timestamp DESC LIMIT ? OFFSET ?';
            params.push(parseInt(limit), parseInt(offset));

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
                    page: parseInt(page),
                    limit: parseInt(limit),
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
}

module.exports = new SystemController();