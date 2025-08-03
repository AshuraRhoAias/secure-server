const secureAuthService = require('../../security/secure-auth.service');
const tripleEncryptor = require('../../crypto/tripleEncryptor');
const bcrypt = require('bcryptjs');

class AuthController {
    async register(req, res) {
        try {
            const { username, email, password, deviceInfo } = req.body;

            // Validaciones básicas
            if (!username || !email || !password) {
                return res.status(400).json({
                    success: false,
                    message: 'Todos los campos son requeridos'
                });
            }

            // Verificar si el usuario ya existe
            const db = require('../../config/database');
            const [existingUsers] = await db.query(
                'SELECT id FROM users WHERE username = ?',
                [username]
            );

            if (existingUsers.length > 0) {
                return res.status(409).json({
                    success: false,
                    message: 'El usuario ya existe'
                });
            }

            // Cifrar datos personales
            const encryptedEmail = tripleEncryptor.encrypt(email);
            const passwordHash = await bcrypt.hash(password, 12);

            // Generar fingerprint del dispositivo
            const deviceFingerprint = secureAuthService.generateDeviceFingerprint(deviceInfo || {});

            // Crear usuario
            const result = await db.query(
                `INSERT INTO users (username, email_encrypted, password_hash, device_fingerprint) 
                 VALUES (?, ?, ?, ?)`,
                [username, encryptedEmail, passwordHash, deviceFingerprint]
            );

            // Log del registro
            await this.logUserAction('USER_REGISTERED', {
                userId: result.insertId,
                username,
                ipAddress: req.ip
            });

            res.status(201).json({
                success: true,
                message: 'Usuario registrado exitosamente',
                userId: result.insertId
            });

        } catch (error) {
            console.error('❌ Error en registro:', error);
            res.status(500).json({
                success: false,
                message: 'Error interno del servidor'
            });
        }
    }

    async login(req, res) {
        try {
            const { username, password, deviceInfo } = req.body;

            if (!username || !password) {
                return res.status(400).json({
                    success: false,
                    message: 'Username y password son requeridos'
                });
            }

            // Preparar información del dispositivo
            const enrichedDeviceInfo = {
                ...deviceInfo,
                ipAddress: req.ip,
                userAgent: req.headers['user-agent']
            };

            // Autenticar usuario
            const authResult = await secureAuthService.authenticateUser(
                username,
                password,
                enrichedDeviceInfo
            );

            // Log del login exitoso
            await this.logUserAction('USER_LOGIN_SUCCESS', {
                username,
                ipAddress: req.ip,
                riskLevel: authResult.riskLevel
            });

            res.json({
                success: true,
                message: 'Autenticación exitosa',
                token: authResult.token,
                expiresAt: authResult.expiresAt,
                riskLevel: authResult.riskLevel
            });

        } catch (error) {
            console.error('❌ Error en login:', error);

            // Log del login fallido
            await this.logUserAction('USER_LOGIN_FAILED', {
                username: req.body.username,
                ipAddress: req.ip,
                error: error.message
            });

            res.status(401).json({
                success: false,
                message: error.message
            });
        }
    }

    async logout(req, res) {
        try {
            // Invalidar sesión
            const db = require('../../config/database');
            const authHeader = req.headers.authorization;

            if (authHeader && authHeader.startsWith('Bearer ')) {
                const token = authHeader.substring(7);
                const tokenHash = secureAuthService.hashToken(token);

                await db.query(
                    'UPDATE user_sessions SET expires_at = NOW() WHERE jwt_token_hash = ?',
                    [tokenHash]
                );
            }

            // Log del logout
            await this.logUserAction('USER_LOGOUT', {
                userId: req.user?.id,
                username: req.user?.username,
                ipAddress: req.ip
            });

            res.json({
                success: true,
                message: 'Sesión cerrada exitosamente'
            });

        } catch (error) {
            console.error('❌ Error en logout:', error);
            res.status(500).json({
                success: false,
                message: 'Error cerrando sesión'
            });
        }
    }

    async getProfile(req, res) {
        try {
            const db = require('../../config/database');
            const [users] = await db.query(
                'SELECT id, username, created_at, risk_level FROM users WHERE id = ?',
                [req.user.id]
            );

            if (users.length === 0) {
                return res.status(404).json({
                    success: false,
                    message: 'Usuario no encontrado'
                });
            }

            const user = users[0];

            // Obtener sesiones activas
            const [sessions] = await db.query(
                `SELECT ip_address, location_country, risk_level, created_at 
                 FROM user_sessions 
                 WHERE user_id = ? AND expires_at > NOW() 
                 ORDER BY created_at DESC`,
                [req.user.id]
            );

            res.json({
                success: true,
                user: {
                    id: user.id,
                    username: user.username,
                    createdAt: user.created_at,
                    riskLevel: user.risk_level,
                    activeSessions: sessions.length,
                    sessions: sessions
                }
            });

        } catch (error) {
            console.error('❌ Error obteniendo perfil:', error);
            res.status(500).json({
                success: false,
                message: 'Error obteniendo perfil'
            });
        }
    }

    async logUserAction(action, details) {
        try {
            const db = require('../../config/database');
            const tripleEncryptor = require('../../crypto/tripleEncryptor');

            const encryptedDetails = tripleEncryptor.encrypt(JSON.stringify({
                ...details,
                timestamp: new Date().toISOString()
            }));

            await db.query(
                `INSERT INTO security_logs (event_type, encrypted_details, ip_address, severity) 
                    VALUES (?, ?, ?, 'low')`,
                [action, encryptedDetails, details.ipAddress]
            );

        } catch (error) {
            console.error('❌ Error logging user action:', error);
        }
    }
}

module.exports = new AuthController();