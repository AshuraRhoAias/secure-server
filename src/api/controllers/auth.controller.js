const secureAuthService = require('../../security/secure-auth.service');
const tripleEncryptor = require('../../crypto/tripleEncryptor');
const bcrypt = require('bcryptjs');

class AuthController {
    constructor() {
        // Bind methods to preserve 'this' context
        this.register = this.register.bind(this);
        this.login = this.login.bind(this);
        this.logout = this.logout.bind(this);
        this.getProfile = this.getProfile.bind(this);
        this.logUserAction = this.logUserAction.bind(this);
    }

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
            const [result] = await db.query(
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
            
            // Log del error de registro
            try {
                await this.logUserAction('USER_REGISTRATION_ERROR', {
                    username: req.body?.username,
                    ipAddress: req.ip,
                    error: error.message
                });
            } catch (logError) {
                console.error('❌ Error logging registration error:', logError);
            }

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
            try {
                await this.logUserAction('USER_LOGIN_FAILED', {
                    username: req.body?.username,
                    ipAddress: req.ip,
                    error: error.message
                });
            } catch (logError) {
                console.error('❌ Error logging login failure:', logError);
            }

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
            
            try {
                await this.logUserAction('USER_LOGOUT_ERROR', {
                    userId: req.user?.id,
                    username: req.user?.username,
                    ipAddress: req.ip,
                    error: error.message
                });
            } catch (logError) {
                console.error('❌ Error logging logout error:', logError);
            }

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

            // Log de acceso al perfil
            await this.logUserAction('USER_PROFILE_ACCESS', {
                userId: req.user.id,
                username: req.user.username,
                ipAddress: req.ip
            });

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
            
            try {
                await this.logUserAction('USER_PROFILE_ERROR', {
                    userId: req.user?.id,
                    username: req.user?.username,
                    ipAddress: req.ip,
                    error: error.message
                });
            } catch (logError) {
                console.error('❌ Error logging profile error:', logError);
            }

            res.status(500).json({
                success: false,
                message: 'Error obteniendo perfil'
            });
        }
    }

    async logUserAction(action, details) {
        try {
            const db = require('../../config/database');
            
            const logData = {
                ...details,
                timestamp: new Date().toISOString(),
                userAgent: details.userAgent || 'Unknown'
            };

            const encryptedDetails = tripleEncryptor.encrypt(JSON.stringify(logData));

            await db.query(
                `INSERT INTO security_logs (event_type, encrypted_details, ip_address, severity, risk_score) 
                 VALUES (?, ?, ?, ?, ?)`,
                [
                    action, 
                    encryptedDetails, 
                    details.ipAddress || 'Unknown',
                    this.getSeverityForAction(action),
                    this.getRiskScoreForAction(action)
                ]
            );

            console.log(`📝 Log: ${action} - IP: ${details.ipAddress || 'Unknown'}`);

        } catch (error) {
            console.error('❌ Error logging user action:', error);
            // No lanzar error para evitar interrumpir el flujo principal
        }
    }

    getSeverityForAction(action) {
        const severityMap = {
            'USER_REGISTERED': 'low',
            'USER_LOGIN_SUCCESS': 'low',
            'USER_LOGIN_FAILED': 'medium',
            'USER_LOGOUT': 'low',
            'USER_PROFILE_ACCESS': 'low',
            'USER_REGISTRATION_ERROR': 'medium',
            'USER_LOGOUT_ERROR': 'medium',
            'USER_PROFILE_ERROR': 'medium'
        };

        return severityMap[action] || 'low';
    }

    getRiskScoreForAction(action) {
        const riskScoreMap = {
            'USER_REGISTERED': 10,
            'USER_LOGIN_SUCCESS': 5,
            'USER_LOGIN_FAILED': 40,
            'USER_LOGOUT': 5,
            'USER_PROFILE_ACCESS': 5,
            'USER_REGISTRATION_ERROR': 30,
            'USER_LOGOUT_ERROR': 20,
            'USER_PROFILE_ERROR': 20
        };

        return riskScoreMap[action] || 10;
    }

    // Método para validar datos de entrada
    validateRegistrationData(username, email, password) {
        const errors = [];

        // Validar username
        if (!username || username.length < 3) {
            errors.push('El username debe tener al menos 3 caracteres');
        }

        if (!/^[a-zA-Z0-9_]+$/.test(username)) {
            errors.push('El username solo puede contener letras, números y guiones bajos');
        }

        // Validar email
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!email || !emailRegex.test(email)) {
            errors.push('El email no tiene un formato válido');
        }

        // Validar password
        if (!password || password.length < 8) {
            errors.push('La contraseña debe tener al menos 8 caracteres');
        }

        if (!/(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/.test(password)) {
            errors.push('La contraseña debe contener al menos una mayúscula, una minúscula y un número');
        }

        return errors;
    }

    // Método para obtener estadísticas de autenticación
    async getAuthStats() {
        try {
            const db = require('../../config/database');
            
            const [loginStats] = await db.query(`
                SELECT 
                    COUNT(*) as total_logins,
                    COUNT(CASE WHEN event_type = 'USER_LOGIN_SUCCESS' THEN 1 END) as successful_logins,
                    COUNT(CASE WHEN event_type = 'USER_LOGIN_FAILED' THEN 1 END) as failed_logins
                FROM security_logs 
                WHERE event_type IN ('USER_LOGIN_SUCCESS', 'USER_LOGIN_FAILED') 
                AND created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
            `);

            const [userStats] = await db.query(`
                SELECT 
                    COUNT(*) as total_users,
                    COUNT(CASE WHEN created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR) THEN 1 END) as new_users_24h
                FROM users
            `);

            return {
                loginStats: loginStats[0],
                userStats: userStats[0],
                timestamp: new Date().toISOString()
            };

        } catch (error) {
            console.error('❌ Error obteniendo estadísticas de auth:', error);
            return null;
        }
    }
}

module.exports = new AuthController();