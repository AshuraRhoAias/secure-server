const serverCheck = require('../../middleware/serverCheck.middleware');
const secureCommunications = require('../../services/secure-communications.service');
const anomalyDetection = require('../../security/anomaly-detection.service');
const scheduleKeyRotation = require('../../tasks/scheduleKeyRotation');
const audit = require('../../services/audit.service');
const { getNetworkPosture } = require('../../security/network-hardening.check');
const securityEvents = require('../../security/security-events.service');
const { sqlInt } = require('../../config/sql');
const approvals = require('../../security/admin-actions');
const alerts = require('../../security/alerts.service');
const dashboard = require('../../security/dashboard.service');
const privacy = require('../../security/privacy.service');

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
            const protectionStats = await require('../../middleware/protection.middleware').getProtectionStats();

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
                        anomalies: await anomalyDetection.getStats(),
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
            const sev = severity || null;

            // Consultas fijas: el filtro opcional es `(? IS NULL OR severity = ?)`, no se concatena SQL.
            // page/limit son enteros acotados; LIMIT/OFFSET pasan por sqlInt (no admiten parámetros).
            const [logs] = await db.query(
                `SELECT id, event_type, ip_address, timestamp, severity, risk_score
                 FROM security_logs
                 WHERE (? IS NULL OR severity = ?)
                 ORDER BY timestamp DESC, id DESC
                 LIMIT ${sqlInt(limit)} OFFSET ${sqlInt(offset)}`,
                [sev, sev]
            );

            const [countResult] = await db.query(
                'SELECT COUNT(*) as total FROM security_logs WHERE (? IS NULL OR severity = ?)',
                [sev, sev]
            );
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

    // Tabla de análisis: eventos filtrables (los filtros ya vienen validados en system.routes.js)
    async getSecurityEvents(req, res) {
        try {
            const q = req.validated?.query || {};
            const events = await securityEvents.list({
                type: q.type, rule: q.rule, severity: q.severity, ip: q.ip, userId: q.userId,
                sinceHours: q.hours, beforeId: q.before, limit: q.limit
            });

            res.json({
                success: true,
                events,
                nextBefore: events.length === (q.limit || 100) ? events[events.length - 1].id : null
            });
        } catch (error) {
            console.error('❌ Error obteniendo eventos de seguridad:', error.code || error.message);
            res.status(500).json({ success: false, message: 'Error obteniendo eventos de seguridad' });
        }
    }

    // Resumen: qué pasó en las últimas N horas, quién insiste y con qué reglas
    async getSecuritySummary(req, res) {
        try {
            const summary = await securityEvents.summary({ hours: req.validated?.query?.hours });
            res.json({ success: true, summary });
        } catch (error) {
            console.error('❌ Error obteniendo el resumen de seguridad:', error.code || error.message);
            res.status(500).json({ success: false, message: 'Error obteniendo el resumen de seguridad' });
        }
    }

    // Libera una cuenta bloqueada por intentos fallidos (el dueño no puede esperar o lo pide soporte)
    async unlockAccount(req, res) {
        try {
            const { username } = req.body;
            const secureAuth = require('../../security/secure-auth.service');
            await secureAuth.unlockAccount(username, { adminId: req.user.id });

            await audit.log('ACCOUNT_UNLOCKED_MANUALLY', { usernameHash: secureAuth.generateUsernameHash(username) }, { req, severity: 'medium', riskScore: 10 });
            await securityEvents.record({
                type: 'ACCOUNT_UNLOCKED', severity: 'info', req, usernameHash: secureAuth.generateUsernameHash(username),
                details: { by: req.user.id }
            });
            res.json({ success: true, message: 'Cuenta liberada' });
        } catch (error) {
            console.error('❌ Error liberando cuenta:', error.code || error.message);
            res.status(500).json({ success: false, message: 'Error liberando la cuenta' });
        }
    }

    // Dispositivo perdido y sin códigos de recuperación. Un administrador SOLICITA el reinicio y otro lo APRUEBA
    // (ADMIN_APPROVALS_REQUIRED=1 lo ejecuta al momento). Ver security/admin-approvals.service.js
    async resetMfa(req, res) {
        try {
            const db = require('../../config/database');
            const secureAuth = require('../../security/secure-auth.service');
            const [rows] = await db.query('SELECT id FROM users WHERE username_hash = ?', [secureAuth.generateUsernameHash(req.body.username)]);
            if (rows.length === 0) return res.status(404).json({ success: false, message: 'Usuario no encontrado', code: 'NOT_FOUND' });

            const outcome = await approvals.request({
                action: 'mfa_reset', targetUserId: rows[0].id, reason: req.body.reason, requestedBy: req.user.id
            });
            await audit.log('MFA_RESET_REQUESTED', { userId: rows[0].id, approvalId: outcome.id, status: outcome.status }, { req, severity: 'high', riskScore: 40 });

            if (outcome.status === 'pending') {
                return res.status(202).json({
                    success: true, approvalId: outcome.id, status: 'pending',
                    message: 'Solicitud creada: otro administrador debe aprobarla con POST /api/system/approvals/:id/approve'
                });
            }
            res.json({ success: true, approvalId: outcome.id, status: outcome.status, message: 'MFA desactivado para ese usuario' });
        } catch (error) {
            this.approvalFailure(res, error, 'Error reiniciando el MFA');
        }
    }

    async listApprovals(req, res) {
        try {
            const list = await approvals.list({ status: req.validated?.query?.status || null });
            res.json({ success: true, approvals: list });
        } catch (error) {
            this.approvalFailure(res, error, 'Error listando solicitudes');
        }
    }

    async approveApproval(req, res) {
        try {
            const outcome = await approvals.approve(req.validated.params.id, req.user.id);
            await audit.log('ADMIN_APPROVAL_APPROVED', { approvalId: outcome.id, action: outcome.action }, { req, severity: 'high', riskScore: 30 });
            res.json({ success: true, ...outcome });
        } catch (error) {
            this.approvalFailure(res, error, 'Error aprobando la solicitud');
        }
    }

    async rejectApproval(req, res) {
        try {
            res.json({ success: true, ...(await approvals.reject(req.validated.params.id, req.user.id)) });
        } catch (error) {
            this.approvalFailure(res, error, 'Error rechazando la solicitud');
        }
    }

    // ------------------------------------------------------------------ alertas y panel (solo admin)

    async listAlerts(req, res) {
        try {
            const q = req.validated?.query || {};
            const list = await alerts.list({ status: q.status || null, severity: q.severity || null, beforeId: q.before || null, limit: q.limit });
            res.json({ success: true, alerts: list, nextBefore: list.length === q.limit ? list[list.length - 1].id : null });
        } catch (error) {
            this.opsFailure(res, error, 'Error listando alertas');
        }
    }

    async evaluateAlerts(req, res) {
        try {
            res.json({ success: true, result: await alerts.evaluate() });
        } catch (error) {
            this.opsFailure(res, error, 'Error evaluando alertas');
        }
    }

    async acknowledgeAlert(req, res) {
        try {
            await alerts.acknowledge(req.validated.params.id, req.user.id);
            await securityEvents.record({ type: 'ALERT_ACKNOWLEDGED', severity: 'info', req, details: { alertId: req.validated.params.id } });
            res.json({ success: true, status: 'acknowledged' });
        } catch (error) {
            this.opsFailure(res, error, 'Error reconociendo la alerta');
        }
    }

    async resolveAlert(req, res) {
        try {
            await alerts.resolve(req.validated.params.id, req.user.id);
            await securityEvents.record({ type: 'ALERT_RESOLVED', severity: 'info', req, details: { alertId: req.validated.params.id } });
            res.json({ success: true, status: 'resolved' });
        } catch (error) {
            this.opsFailure(res, error, 'Error resolviendo la alerta');
        }
    }

    async getDashboard(req, res) {
        try {
            res.set('Cache-Control', 'no-store');
            res.json({ success: true, dashboard: await dashboard.snapshot({ hours: req.validated?.query?.hours }) });
        } catch (error) {
            this.opsFailure(res, error, 'Error generando el panel');
        }
    }

    // ------------------------------------------------------------------ datos personales e incidentes (solo admin)

    async exportUserData(req, res) {
        try {
            const data = await privacy.exportUser(req.validated.params.id);
            await audit.log('PRIVACY_EXPORT', { exportedUserId: req.validated.params.id, by: req.user.id }, { req, severity: 'high', riskScore: 40 });
            res.set('Cache-Control', 'no-store');
            res.set('Content-Disposition', `attachment; filename="user-${Number(req.validated.params.id)}-export.json"`);
            res.json({ success: true, export: data });
        } catch (error) {
            this.opsFailure(res, error, 'Error exportando los datos');
        }
    }

    // Borrar los datos de un usuario: pide que otro administrador lo apruebe. confirmUsername evita equivocarse de cuenta.
    async requestUserErase(req, res) {
        try {
            const user = await privacy.findUser(req.validated.params.id);
            if (!user) return res.status(404).json({ success: false, message: 'Usuario no encontrado', code: 'NOT_FOUND' });
            if (user.role !== 'user') {
                return res.status(409).json({ success: false, message: 'No se borra una cuenta con privilegios: quítale antes el rol', code: 'ROLE_PROTECTED' });
            }
            let username = null;
            try { username = require('../../crypto/tripleEncryptor').decrypt(user.username_encrypted); } catch { /* sin nombre legible */ }
            if (username !== req.body.confirmUsername) {
                return res.status(400).json({ success: false, message: 'confirmUsername no coincide con el usuario que se va a borrar', code: 'CONFIRMATION_MISMATCH' });
            }

            const outcome = await approvals.request({ action: 'user_erase', targetUserId: user.id, reason: req.body.reason, requestedBy: req.user.id });
            if (outcome.status === 'pending') {
                return res.status(202).json({
                    success: true, approvalId: outcome.id, status: 'pending',
                    message: 'Solicitud creada: otro administrador debe aprobarla con POST /api/system/approvals/:id/approve'
                });
            }
            res.json({ success: true, approvalId: outcome.id, status: outcome.status, result: outcome.result });
        } catch (error) {
            this.opsFailure(res, error, 'Error solicitando el borrado');
        }
    }

    async revokeUserSessions(req, res) {
        try {
            const closed = await require('../../security/secure-auth.service').revokeAllSessions(req.validated.params.id, { reason: 'admin_revoked' });
            await securityEvents.record({
                type: 'SESSIONS_REVOKED_USER', severity: 'high', riskScore: 30, req, userId: req.validated.params.id,
                details: { closed, by: req.user.id, reason: req.body.reason }
            });
            res.json({ success: true, closed });
        } catch (error) {
            this.opsFailure(res, error, 'Error cerrando las sesiones');
        }
    }

    // Interruptor de emergencia: cierra TODAS las sesiones de TODOS los usuarios (todos tendrán que iniciar sesión de nuevo)
    async revokeAllSessions(req, res) {
        try {
            const db = require('../../config/database');
            const [result] = await db.query(
                "UPDATE user_sessions SET expires_at = NOW(), revoked_at = NOW(), revoked_reason = 'admin_revoked_all' WHERE revoked_at IS NULL AND expires_at > NOW()"
            );
            await securityEvents.record({
                type: 'SESSIONS_REVOKED_ALL', severity: 'critical', riskScore: 60, req,
                details: { closed: result.affectedRows, by: req.user.id, reason: req.body.reason }
            });
            res.json({ success: true, closed: result.affectedRows });
        } catch (error) {
            this.opsFailure(res, error, 'Error cerrando las sesiones');
        }
    }

    opsFailure(res, error, fallback) {
        const known = error instanceof alerts.AlertError || error instanceof privacy.PrivacyError || error instanceof approvals.ApprovalError;
        if (known) return res.status(error.status).json({ success: false, message: error.message, code: error.code });
        console.error(`❌ ${fallback}:`, error.code || error.message);
        res.status(500).json({ success: false, message: fallback });
    }

    approvalFailure(res, error, fallback) {
        if (error instanceof approvals.ApprovalError) {
            return res.status(error.status).json({ success: false, message: error.message, code: error.code });
        }
        console.error(`❌ ${fallback}:`, error.code || error.message);
        res.status(500).json({ success: false, message: fallback });
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