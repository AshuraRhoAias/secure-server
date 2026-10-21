const secureAuthService = require('../../security/secure-auth.service');
const { AuthError } = secureAuthService;
const { normalizeIp } = require('../../security/ip');
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

    // Solo se aceptan estos campos (texto corto) de deviceInfo: alimentan la huella del dispositivo
    cleanDeviceInfo(deviceInfo) {
        const out = {};
        if (deviceInfo && typeof deviceInfo === 'object' && !Array.isArray(deviceInfo)) {
            for (const key of ['screenResolution', 'timezone', 'language', 'platform', 'colorDepth', 'pixelRatio']) {
                const value = deviceInfo[key];
                if (typeof value === 'string' || typeof value === 'number') out[key] = String(value).slice(0, 100);
            }
        }
        return out;
    }

    async register(req, res) {
        try {
            // Formato, longitudes y tipos ya los validó validate.body en auth.routes.js
            const { username, email, password } = req.body;
            const deviceInfo = this.cleanDeviceInfo(req.body.deviceInfo);
            const ip = normalizeIp(req.ip);

            // bcrypt solo mira los primeros 72 BYTES: más allá se ignoraría en silencio
            if (Buffer.byteLength(password, 'utf8') > 72) {
                return res.status(400).json({
                    success: false,
                    message: 'La contraseña no puede superar 72 bytes',
                    code: 'VALIDATION_ERROR'
                });
            }

            const db = require('../../config/database');
            const usernameHash = this.generateUsernameHash(username);

            const [existingUsers] = await db.query('SELECT id FROM users WHERE username_hash = ?', [usernameHash]);
            if (existingUsers.length > 0) {
                return res.status(409).json({ success: false, message: 'El usuario ya existe' });
            }

            const passwordHash = await bcrypt.hash(password, 12);
            const deviceFingerprint = secureAuthService.generateDeviceFingerprint({
                ...deviceInfo, userAgent: req.headers['user-agent']
            });

            const encryptedMetadata = tripleEncryptor.encrypt(JSON.stringify({
                originalUsername: username,
                registrationIP: ip,
                registrationUserAgent: req.headers['user-agent'],
                deviceFingerprint,
                registrationTimestamp: new Date().toISOString()
            }));

            let result;
            try {
                [result] = await db.query(
                    `INSERT INTO users (
                        username_encrypted, username_hash, email_encrypted, password_hash, device_fingerprint,
                        risk_level_encrypted, encrypted_metadata, encryption_version, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW())`,
                    [
                        tripleEncryptor.encrypt(username),
                        usernameHash,
                        tripleEncryptor.encrypt(email),
                        passwordHash,
                        deviceFingerprint,
                        tripleEncryptor.encrypt('low'),
                        encryptedMetadata,
                        this.getCurrentEncryptionVersion()
                    ]
                );
            } catch (insertError) {
                // Dos registros simultáneos del mismo usuario: gana uno (índice único username_hash)
                if (insertError.code === 'ER_DUP_ENTRY') {
                    return res.status(409).json({ success: false, message: 'El usuario ya existe' });
                }
                throw insertError;
            }

            await this.logUserAction('USER_REGISTERED', {
                userId: result.insertId,
                usernameHash,
                ipAddress: ip,
                encryptionVersion: this.getCurrentEncryptionVersion()
            });

            res.status(201).json({
                success: true,
                message: 'Usuario registrado exitosamente',
                userId: result.insertId,
                encryptionVersion: this.getCurrentEncryptionVersion()
            });

        } catch (error) {
            // Nunca se vuelcan al log el usuario, el email ni la contraseña de la petición
            console.error('❌ Error en registro:', error.code || error.message);

            try {
                await this.logUserAction('USER_REGISTRATION_ERROR', {
                    ipAddress: normalizeIp(req.ip),
                    error: error.code || 'ERROR',
                    encryptionVersion: this.getCurrentEncryptionVersion()
                });
            } catch (logError) {
                console.error('❌ Error logging registration error:', logError.message);
            }

            res.status(500).json({ success: false, message: 'Error interno del servidor' });
        }
    }

    async login(req, res) {
        const { username, password } = req.body;
        const ip = normalizeIp(req.ip);

        try {
            const authResult = await secureAuthService.authenticateUser(username, password, {
                ...this.cleanDeviceInfo(req.body.deviceInfo),
                ipAddress: ip,
                userAgent: req.headers['user-agent']
            });

            const db = require('../../config/database');
            await db.query(
                'UPDATE users SET risk_level_encrypted = ?, updated_at = NOW() WHERE id = ?',
                [tripleEncryptor.encrypt(authResult.riskLevel), authResult.userId]
            );

            await this.logUserAction('USER_LOGIN_SUCCESS', {
                userId: authResult.userId,
                usernameHash: this.generateUsernameHash(username),
                ipAddress: ip,
                riskLevel: authResult.riskLevel,
                encryptionVersion: this.getCurrentEncryptionVersion()
            });

            res.json({
                success: true,
                message: 'Autenticación exitosa',
                token: authResult.token,
                expiresAt: authResult.expiresAt,
                riskLevel: authResult.riskLevel,
                encryptionVersion: this.getCurrentEncryptionVersion()
            });

        } catch (error) {
            // Errores previstos (credenciales, cuenta bloqueada): mensaje y código estables
            if (error instanceof AuthError) {
                await this.logUserAction('USER_LOGIN_FAILED', {
                    usernameHash: this.generateUsernameHash(username),
                    ipAddress: ip,
                    error: error.code
                });

                if (error.retryAfter) res.set('Retry-After', String(error.retryAfter));
                return res.status(error.status).json({
                    success: false,
                    message: error.message,
                    code: error.code,
                    ...(error.retryAfter && { retryAfter: error.retryAfter })
                });
            }

            // Cualquier otro error es nuestro: se registra, pero al cliente NO se le cuenta el detalle
            console.error('❌ Error en login:', error.code || error.message);
            res.status(500).json({ success: false, message: 'Error interno del servidor' });
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
                    'UPDATE user_sessions SET expires_at = NOW() WHERE jwt_token_hash = ?',
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

    // Una sola implementación del hash de usuario (la usa también el servicio de autenticación)
    generateUsernameHash(username) {
        return secureAuthService.generateUsernameHash(username);
    }

    getCurrentEncryptionVersion() {
        // Versión actual del sistema de cifrado
        return 'v4.0.0';
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

    // ✅ MÉTODO PARA LIMPIAR REGISTROS PROBLEMÁTICOS
    async cleanupEmptyUsernames() {
        try {
            const db = require('../../config/database');
            
            console.log('🧹 Iniciando limpieza de registros problemáticos...');
            
            // Buscar registros con username_hash vacío o problemático
            const [emptyUsers] = await db.query(`
                SELECT id, username_encrypted, username_hash, created_at 
                FROM users 
                WHERE username_hash = '' 
                   OR username_hash IS NULL 
                   OR username_encrypted = '' 
                   OR username_encrypted IS NULL
            `);
            
            console.log(`🧹 Encontrados ${emptyUsers.length} registros problemáticos`);
            
            if (emptyUsers.length > 0) {
                // Mostrar registros problemáticos
                emptyUsers.forEach((user, index) => {
                    console.log(`  ${index + 1}. ID: ${user.id}, Hash: "${user.username_hash}", Encrypted: "${user.username_encrypted}", Created: ${user.created_at}`);
                });
                
                // Eliminar registros problemáticos (solo si están completamente vacíos)
                const [deleteResult] = await db.query(`
                    DELETE FROM users 
                    WHERE (username_hash = '' OR username_hash IS NULL)
                      AND (username_encrypted = '' OR username_encrypted IS NULL)
                `);
                
                console.log(`🧹 ${deleteResult.affectedRows} registros vacíos eliminados`);
                
                return { 
                    cleaned: deleteResult.affectedRows, 
                    found: emptyUsers.length,
                    details: emptyUsers
                };
            }
            
            console.log('✅ No se encontraron registros problemáticos');
            return { cleaned: 0, found: 0, details: [] };
            
        } catch (error) {
            console.error('❌ Error limpiando usernames vacíos:', error);
            throw error;
        }
    }

    // ✅ MÉTODO PARA VALIDAR INTEGRIDAD COMPLETA
    async validateDataIntegrity() {
        try {
            const db = require('../../config/database');
            console.log('🔍 Validando integridad completa de datos...');

            // Obtener todos los usuarios
            const [users] = await db.query(`
                SELECT id, username_encrypted, username_hash, email_encrypted, 
                       risk_level_encrypted, encrypted_metadata, encryption_version
                FROM users 
                ORDER BY id
            `);

            let validUsers = 0;
            let errors = [];
            let warnings = [];

            for (const user of users) {
                let userErrors = [];
                
                // Validar username
                try {
                    if (!user.username_encrypted || user.username_encrypted === '') {
                        userErrors.push('Username cifrado vacío');
                    } else {
                        const decryptedUsername = tripleEncryptor.decrypt(user.username_encrypted);
                        if (!decryptedUsername || decryptedUsername.trim() === '') {
                            userErrors.push('Username descifrado vacío');
                        }
                        
                        // Validar consistencia del hash
                        const expectedHash = this.generateUsernameHash(decryptedUsername);
                        if (expectedHash !== user.username_hash) {
                            userErrors.push('Hash de username inconsistente');
                        }
                    }
                } catch (e) {
                    userErrors.push(`Error descifrado username: ${e.message}`);
                }

                // Validar email
                try {
                    if (user.email_encrypted) {
                        tripleEncryptor.decrypt(user.email_encrypted);
                    }
                } catch (e) {
                    userErrors.push(`Error descifrado email: ${e.message}`);
                }

                // Validar risk level
                try {
                    if (user.risk_level_encrypted) {
                        tripleEncryptor.decrypt(user.risk_level_encrypted);
                    }
                } catch (e) {
                    userErrors.push(`Error descifrado risk_level: ${e.message}`);
                }

                // Validar metadata
                try {
                    if (user.encrypted_metadata) {
                        const metadata = tripleEncryptor.decrypt(user.encrypted_metadata);
                        JSON.parse(metadata);
                    }
                } catch (e) {
                    warnings.push(`User ${user.id}: Metadata no válida - ${e.message}`);
                }

                if (userErrors.length === 0) {
                    validUsers++;
                } else {
                    errors.push({
                        userId: user.id,
                        errors: userErrors
                    });
                }
            }

            const integrityScore = users.length > 0 ? (validUsers / users.length) * 100 : 100;

            console.log(`🔍 Integridad de datos: ${integrityScore.toFixed(2)}% (${validUsers}/${users.length})`);
            if (warnings.length > 0) {
                console.log(`⚠️ ${warnings.length} advertencias encontradas`);
            }
            if (errors.length > 0) {
                console.log(`❌ ${errors.length} usuarios con errores`);
            }

            return {
                success: true,
                totalUsers: users.length,
                validUsers,
                integrityScore,
                errors: errors.length > 0 ? errors : null,
                warnings: warnings.length > 0 ? warnings : null
            };

        } catch (error) {
            console.error('❌ Error validando integridad:', error);
            throw error;
        }
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
                    // Validar que el username no esté vacío
                    if (!user.username || user.username.trim() === '') {
                        console.log(`⚠️ Usuario ${user.id} tiene username vacío, saltando...`);
                        continue;
                    }

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