const secureAuthService = require('../security/secure-auth.service');

class AuthMiddleware {
    constructor() {
        this.activeValidations = new Map();
    }

    async verifyJWT(req, res, next) {
        try {
            const authHeader = req.headers.authorization;

            if (!authHeader || !authHeader.startsWith('Bearer ')) {
                return res.status(401).json({
                    success: false,
                    message: 'Token de autorización requerido',
                    code: 'MISSING_TOKEN'
                });
            }

            const token = authHeader.substring(7);
            const currentIP = req.ip || req.connection.remoteAddress;

            // Validar token con verificaciones de seguridad
            const validation = await secureAuthService.validateToken(token, currentIP);

            if (!validation.valid) {
                // Log del intento de acceso inválido
                await this.logInvalidAccess(req, validation.error);

                return res.status(401).json({
                    success: false,
                    message: validation.error,
                    code: 'INVALID_TOKEN'
                });
            }

            // Agregar información del usuario al request
            req.user = {
                id: validation.userId,
                username: validation.username,
                sessionId: validation.sessionId,
                riskLevel: validation.riskLevel
            };

            // Agregar headers de información de sesión
            res.setHeader('X-Session-Risk-Level', validation.riskLevel);
            res.setHeader('X-Session-Valid', 'true');

            next();

        } catch (error) {
            console.error('❌ Error en verificación JWT:', error);

            return res.status(500).json({
                success: false,
                message: 'Error interno del servidor',
                code: 'INTERNAL_ERROR'
            });
        }
    }

    async logInvalidAccess(req, error) {
        try {
            const db = require('../config/database');
            const tripleEncryptor = require('../crypto/tripleEncryptor');

            const logData = {
                ip: req.ip,
                userAgent: req.headers['user-agent'],
                path: req.path,
                method: req.method,
                error,
                timestamp: new Date().toISOString()
            };

            const encryptedDetails = tripleEncryptor.encrypt(JSON.stringify(logData));

            await db.query(
                `INSERT INTO security_logs (event_type, encrypted_details, ip_address, severity) 
                    VALUES ('INVALID_TOKEN_ACCESS', ?, ?, 'medium')`,
                [encryptedDetails, req.ip]
            );

        } catch (logError) {
            console.error('❌ Error logging invalid access:', logError);
        }
    }
}

const authMiddleware = new AuthMiddleware();

module.exports = authMiddleware;