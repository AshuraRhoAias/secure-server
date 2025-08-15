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

            // Verificar si el usuario ya existe (usando username cifrado)
            const db = require('../../config/database');
            const encryptedUsername = tripleEncryptor.encrypt(username);

            // Para verificar existencia, necesitamos buscar por un hash del username
            const usernameHash = this.generateUsernameHash(username);
            const [existingUsers] = await db.query(
                'SELECT id FROM users WHERE username_hash = ?',
                [usernameHash]
            );

            if (existingUsers.length > 0) {
                return res.status(409).json({
                    success: false,
                    message: 'El usuario ya existe'
                });
            }

            // Cifrar todos los datos sensibles
            const encryptedEmail = tripleEncryptor.encrypt(email);
            const passwordHash = await bcrypt.hash(password, 12);
            const deviceFingerprint = secureAuthService.generateDeviceFingerprint(deviceInfo || {});

            // Cifrar metadatos adicionales
            const encryptedMetadata = tripleEncryptor.encrypt(JSON.stringify({
                originalUsername: username,
                registrationIP: req.ip,
                registrationUserAgent: req.headers['user-agent'],
                deviceFingerprint: deviceFingerprint,
                registrationTimestamp: new Date().toISOString()
            }));

            // Calcular nivel de riesgo inicial
            const initialRiskLevel = 'low';
            const encryptedRiskLevel = tripleEncryptor.encrypt(initialRiskLevel);

            // Crear usuario con todos los campos cifrados
            const [result] = await db.query(
                `INSERT INTO users (
                    username_encrypted, 
                    username_hash, 
                    email_encrypted, 
                    password_hash, 
                    device_fingerprint,
                    risk_level_encrypted,
                    encrypted_metadata,
                    encryption_version,
                    created_at,
                    updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW())`,
                [
                    encryptedUsername,
                    usernameHash,
                    encryptedEmail, 
                    passwordHash, 
                    deviceFingerprint,
                    encryptedRiskLevel,
                    encryptedMetadata,
                    this.getCurrentEncryptionVersion()
                ]
            );

            // Log del registro con datos cifrados
            await this.logUserAction('USER_REGISTERED', {
                userId: result.insertId,
                usernameHash: usernameHash,
                ipAddress: req.ip,
                encryptionVersion: this.getCurrentEncryptionVersion()
            });

            res.status(201).json({
                success: true,
                message: 'Usuario registrado exitosamente',
                userId: result.insertId,
                encryptionVersion: this.getCurrentEncryptionVersion()
            });

        } catch (error) {
            console.error('❌ Error en registro:', error);
            
            // Log del error de registro
            try {
                await this.logUserAction('USER_REGISTRATION_ERROR', {
                    usernameAttempt: req.body?.username ? this.generateUsernameHash(req.body.username) : 'unknown',
                    ipAddress: req.ip,
                    error: error.message,
                    encryptionVersion: this.getCurrentEncryptionVersion()
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

            // Buscar usuario por hash del username
            const usernameHash = this.generateUsernameHash(username);
            const db = require('../../config/database');
            
            const [users] = await db.query(
                'SELECT id, username_encrypted, password_hash, risk_level_encrypted, encrypted_metadata, encryption_version FROM users WHERE username_hash = ?',
                [usernameHash]
            );

            if (users.length === 0) {
                await this.logUserAction('USER_LOGIN_FAILED', {
                    usernameHash: usernameHash,
                    ipAddress: req.ip,
                    error: 'Usuario no encontrado'
                });

                return res.status(401).json({
                    success: false,
                    message: 'Credenciales inválidas'
                });
            }

            const user = users[0];

            // Verificar password
            const isValidPassword = await bcrypt.compare(password, user.password_hash);
            if (!isValidPassword) {
                await this.logUserAction('USER_LOGIN_FAILED', {
                    userId: user.id,
                    usernameHash: usernameHash,
                    ipAddress: req.ip,
                    error: 'Password incorrecto'
                });

                return res.status(401).json({
                    success: false,
                    message: 'Credenciales inválidas'
                });
            }

            // Descifrar datos del usuario
            const decryptedUsername = tripleEncryptor.decrypt(user.username_encrypted);
            const decryptedRiskLevel = tripleEncryptor.decrypt(user.risk_level_encrypted);

            // Preparar información del dispositivo
            const enrichedDeviceInfo = {
                ...deviceInfo,
                ipAddress: req.ip,
                userAgent: req.headers['user-agent']
            };

            // Autenticar usuario con datos descifrados
            const authResult = await secureAuthService.authenticateUser(
                decryptedUsername,
                password,
                enrichedDeviceInfo
            );

            // Actualizar última actividad y nivel de riesgo si cambió
            if (authResult.riskLevel !== decryptedRiskLevel) {
                const newEncryptedRiskLevel = tripleEncryptor.encrypt(authResult.riskLevel);
                await db.query(
                    'UPDATE users SET risk_level_encrypted = ?, updated_at = NOW() WHERE id = ?',
                    [newEncryptedRiskLevel, user.id]
                );
            }

            // Log del login exitoso
            await this.logUserAction('USER_LOGIN_SUCCESS', {
                userId: user.id,
                usernameHash: usernameHash,
                ipAddress: req.ip,
                riskLevel: authResult.riskLevel,
                encryptionVersion: user.encryption_version
            });

            res.json({
                success: true,
                message: 'Autenticación exitosa',
                token: authResult.token,
                expiresAt: authResult.expiresAt,
                riskLevel: authResult.riskLevel,
                encryptionVersion: user.encryption_version
            });

        } catch (error) {
            console.error('❌ Error en login:', error);

            // Log del login fallido
            try {
                await this.logUserAction('USER_LOGIN_FAILED', {
                    usernameHash: req.body?.username ? this.generateUsernameHash(req.body.username) : 'unknown',
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

    async getProfile(req, res) {
        try {
            const db = require('../../config/database');
            const [users] = await db.query(
                `SELECT id, username_encrypted, risk_level_encrypted, encrypted_metadata, 
                        encryption_version, created_at, updated_at 
                 FROM users WHERE id = ?`,
                [req.user.id]
            );

            if (users.length === 0) {
                return res.status(404).json({
                    success: false,
                    message: 'Usuario no encontrado'
                });
            }

            const user = users[0];

            // Descifrar datos sensibles
            const decryptedUsername = tripleEncryptor.decrypt(user.username_encrypted);
            const decryptedRiskLevel = tripleEncryptor.decrypt(user.risk_level_encrypted);
            
            let decryptedMetadata = {};
            try {
                decryptedMetadata = JSON.parse(tripleEncryptor.decrypt(user.encrypted_metadata));
            } catch (metadataError) {
                console.warn('⚠️ No se pudo descifrar metadata del usuario');
            }

            // Obtener sesiones activas
            const [sessions] = await db.query(
                `SELECT ip_address, location_country, risk_level, created_at 
                 FROM user_sessions 
                 WHERE user_id = ? AND expires_at > NOW() 
                 ORDER BY created_at DESC`,
                [req.user.id]
            );

            // Cifrar timestamps para respuesta
            const encryptedCreatedAt = tripleEncryptor.encrypt(user.created_at.toISOString());
            const encryptedUpdatedAt = tripleEncryptor.encrypt(user.updated_at.toISOString());

            // Log de acceso al perfil
            await this.logUserAction('USER_PROFILE_ACCESS', {
                userId: req.user.id,
                usernameHash: this.generateUsernameHash(decryptedUsername),
                ipAddress: req.ip,
                encryptionVersion: user.encryption_version
            });

            res.json({
                success: true,
                user: {
                    id: user.id, // ID se mantiene sin cifrar por ser clave primaria
                    username: decryptedUsername,
                    riskLevel: decryptedRiskLevel,
                    encryptionVersion: tripleEncryptor.encrypt(user.encryption_version.toString()),
                    createdAt: encryptedCreatedAt,
                    updatedAt: encryptedUpdatedAt,
                    activeSessions: sessions.length,
                    sessions: sessions,
                    metadata: decryptedMetadata
                }
            });

        } catch (error) {
            console.error('❌ Error obteniendo perfil:', error);
            
            try {
                await this.logUserAction('USER_PROFILE_ERROR', {
                    userId: req.user?.id,
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

    async logout(req, res) {
        try {
            // Invalidar sesión
            const db = require('../../config/database');
            const authHeader = req.headers.authorization;

            if (authHeader && authHeader.startsWith('Bearer ')) {
                const token = authHeader.substring(7);
                const tokenHash = secureAuthService.hashToken(token);

                await db.query(
                    'UPDATE user_sessions SET expires_at = NOW(), updated_at = NOW() WHERE jwt_token_hash = ?',
                    [tokenHash]
                );
            }

            // Log del logout
            await this.logUserAction('USER_LOGOUT', {
                userId: req.user?.id,
                usernameHash: req.user?.username ? this.generateUsernameHash(req.user.username) : 'unknown',
                ipAddress: req.ip,
                timestamp: new Date().toISOString()
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

    // ============ MÉTODOS AUXILIARES PARA CIFRADO ============

    generateUsernameHash(username) {
        // Crear hash determinístico para búsquedas
        const crypto = require('crypto');
        const salt = process.env.BASE_SEED || 'default_salt';
        return crypto.createHash('sha256').update(username + salt).digest('hex');
    }

    getCurrentEncryptionVersion() {
        // Versión actual del sistema de cifrado
        return 'v3.1.0';
    }

    async logUserAction(action, details) {
        try {
            const db = require('../../config/database');
            
            // Cifrar todos los detalles del log
            const logData = {
                ...details,
                timestamp: new Date().toISOString(),
                userAgent: details.userAgent || 'Unknown',
                action: action
            };

            const encryptedDetails = tripleEncryptor.encrypt(JSON.stringify(logData));

            // Cifrar también el timestamp del log
            const encryptedTimestamp = tripleEncryptor.encrypt(new Date().toISOString());

            await db.query(
                `INSERT INTO security_logs (
                    event_type, 
                    encrypted_details, 
                    ip_address, 
                    severity, 
                    risk_score,
                    encrypted_timestamp,
                    encryption_version,
                    created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, NOW())`,
                [
                    action, 
                    encryptedDetails, 
                    details.ipAddress || 'Unknown',
                    this.getSeverityForAction(action),
                    this.getRiskScoreForAction(action),
                    encryptedTimestamp,
                    this.getCurrentEncryptionVersion()
                ]
            );

            console.log(`📝 Log cifrado: ${action} - IP: ${details.ipAddress || 'Unknown'}`);

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

    // Método para reencriptar datos existentes (migración)
    async reencryptExistingData() {
        try {
            const db = require('../../config/database');
            console.log('🔄 Iniciando reencriptación de datos existentes...');

            // Obtener usuarios con datos no cifrados
            const [users] = await db.query(`
                SELECT id, username, email, risk_level, created_at, updated_at 
                FROM users 
                WHERE username_encrypted IS NULL OR username_encrypted = ''
            `);

            let processedCount = 0;

            for (const user of users) {
                try {
                    // Cifrar datos
                    const encryptedUsername = tripleEncryptor.encrypt(user.username);
                    const usernameHash = this.generateUsernameHash(user.username);
                    const encryptedEmail = user.email ? tripleEncryptor.encrypt(user.email) : null;
                    const encryptedRiskLevel = user.risk_level ? tripleEncryptor.encrypt(user.risk_level) : tripleEncryptor.encrypt('low');
                    
                    const encryptedMetadata = tripleEncryptor.encrypt(JSON.stringify({
                        migrationDate: new Date().toISOString(),
                        originalCreatedAt: user.created_at.toISOString(),
                        migrationVersion: this.getCurrentEncryptionVersion()
                    }));

                    // Actualizar registro
                    await db.query(`
                        UPDATE users SET 
                            username_encrypted = ?,
                            username_hash = ?,
                            email_encrypted = ?,
                            risk_level_encrypted = ?,
                            encrypted_metadata = ?,
                            encryption_version = ?,
                            updated_at = NOW()
                        WHERE id = ?
                    `, [
                        encryptedUsername,
                        usernameHash,
                        encryptedEmail,
                        encryptedRiskLevel,
                        encryptedMetadata,
                        this.getCurrentEncryptionVersion(),
                        user.id
                    ]);

                    processedCount++;
                    console.log(`✅ Usuario ${user.id} reencriptado`);

                } catch (userError) {
                    console.error(`❌ Error reencriptando usuario ${user.id}:`, userError);
                }
            }

            console.log(`🔄 Reencriptación completada: ${processedCount}/${users.length} usuarios procesados`);
            return { success: true, processed: processedCount, total: users.length };

        } catch (error) {
            console.error('❌ Error en reencriptación masiva:', error);
            throw error;
        }
    }

    // Método para verificar integridad de datos cifrados
    async verifyEncryptionIntegrity() {
        try {
            const db = require('../../config/database');
            console.log('🔍 Verificando integridad del cifrado...');

            const [users] = await db.query(`
                SELECT id, username_encrypted, email_encrypted, risk_level_encrypted 
                FROM users 
                WHERE username_encrypted IS NOT NULL AND username_encrypted != ''
                LIMIT 10
            `);

            let successfulDecryptions = 0;
            let errors = [];

            for (const user of users) {
                try {
                    // Intentar descifrar cada campo
                    if (user.username_encrypted) {
                        tripleEncryptor.decrypt(user.username_encrypted);
                    }
                    if (user.email_encrypted) {
                        tripleEncryptor.decrypt(user.email_encrypted);
                    }
                    if (user.risk_level_encrypted) {
                        tripleEncryptor.decrypt(user.risk_level_encrypted);
                    }

                    successfulDecryptions++;

                } catch (decryptError) {
                    errors.push({
                        userId: user.id,
                        error: decryptError.message
                    });
                }
            }

            const integrityScore = (successfulDecryptions / users.length) * 100;

            console.log(`🔍 Integridad del cifrado: ${integrityScore.toFixed(2)}% (${successfulDecryptions}/${users.length})`);

            return {
                success: true,
                integrityScore,
                successfulDecryptions,
                totalChecked: users.length,
                errors: errors.length > 0 ? errors : null
            };

        } catch (error) {
            console.error('❌ Error verificando integridad:', error);
            throw error;
        }
    }
}

module.exports = new AuthController();