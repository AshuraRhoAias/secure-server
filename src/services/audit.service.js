const db = require('../config/database');
const tripleEncryptor = require('../crypto/tripleEncryptor');

const ENCRYPTION_VERSION = 'v4.0.0';

// Registro de auditoría reutilizable por cualquier API.
// Los detalles se cifran con el cifrador triple antes de guardarse en security_logs.
//
//   await audit.log('NOTE_CREATED', { noteId }, { req, severity: 'low', riskScore: 5 });
class AuditService {
    async log(eventType, details = {}, { req = null, severity = 'low', riskScore = 0 } = {}) {
        try {
            const payload = {
                ...details,
                action: eventType,
                timestamp: new Date().toISOString(),
                ...(req && {
                    userId: req.user?.id,
                    path: req.originalUrl,
                    method: req.method
                })
            };

            await db.query(
                `INSERT INTO security_logs
                    (event_type, encrypted_details, ip_address, user_agent, severity, risk_score,
                     encrypted_timestamp, encryption_version, created_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW())`,
                [
                    eventType,
                    tripleEncryptor.encrypt(JSON.stringify(payload)),
                    req?.ip || 'Unknown',
                    req?.headers?.['user-agent'] || null,
                    severity,
                    riskScore,
                    tripleEncryptor.encrypt(payload.timestamp),
                    ENCRYPTION_VERSION
                ]
            );
        } catch (error) {
            // La auditoría nunca debe romper la petición principal
            console.error('❌ Error registrando auditoría:', error.message);
        }
    }
}

module.exports = new AuditService();
