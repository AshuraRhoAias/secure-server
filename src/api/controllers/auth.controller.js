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

            // ✅ VALIDACIONES MEJORADAS
            if (!username || !email || !password) {
                return res.status(400).json({
                    success: false,
                    message: 'Todos los campos son requeridos'
                });
            }

            // ✅ VALIDAR STRINGS VACÍOS Y ESPACIOS EN BLANCO
            const trimmedUsername = username.trim();
            const trimmedEmail = email.trim();

            if (trimmedUsername === '' || trimmedEmail === '' || password.trim() === '') {
                return res.status(400).json({
                    success: false,
                    message: 'Los campos no pueden estar vacíos'
                });
            }

            // ✅ VALIDACIONES ADICIONALES
            if (trimmedUsername.length < 3) {
                return res.status(400).json({
                    success: false,
                    message: 'El username debe tener al menos 3 caracteres'
                });
            }

            if (password.length < 6) {
                return res.status(400).json({
                    success: false,
                    message: 'La password debe tener al menos 6 caracteres'
                });
            }

            // Validar formato de email básico
            const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            if (!emailRegex.test(trimmedEmail)) {
                return res.status(400).json({
                    success: false,
                    message: 'Formato de email inválido'
                });
            }

            // Verificar si el usuario ya existe (usando username cifrado)
            const db = require('../../config/database');
            
            // ✅ USAR USERNAME LIMPIO PARA CIFRADO
            const encryptedUsername = tripleEncryptor.encrypt(trimmedUsername);

            // Para verificar existencia, necesitamos buscar por un hash del username
            const usernameHash = this.generateUsernameHash(trimmedUsername);
            
            // ✅ LOG PARA DEBUGGING
            console.log(`🔍 Registrando usuario: "${trimmedUsername}" -> Hash: ${usernameHash.substring(0, 8)}...`);
            
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
            const encryptedEmail = tripleEncryptor.encrypt(trimmedEmail);
            const passwordHash = await bcrypt.hash(password, 12);
            const deviceFingerprint = secureAuthService.generateDeviceFingerprint(deviceInfo || {});

            // Cifrar metadatos adicionales
            const encryptedMetadata = tripleEncryptor.encrypt(JSON.stringify({
                originalUsername: trimmedUsername,
                registrationIP: req.ip,
                registrationUserAgent: req.headers['user-agent'],
                deviceFingerprint: deviceFingerprint,
                registrationTimestamp: new Date().toISOString()
            }));

            // Calcular nivel de riesgo inicial
            const initialRiskLevel = 'low';
            const encryptedRiskLevel = tripleEncryptor.encrypt(initialRiskLevel);

            // ✅ VALIDAR QUE LOS DATOS CIFRADOS NO ESTÉN VACÍOS
            if (!encryptedUsername || !usernameHash || !encryptedEmail) {
                throw new Error('Error en proceso de cifrado: datos vacíos generados');
            }

            console.log(`🔐 Datos cifrados listos para inserción:
                - Username cifrado: ${encryptedUsername.length} chars
                - Username hash: ${usernameHash.length} chars
                - Email cifrado: ${encryptedEmail.length} chars`);

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
            
            // ✅ LOG MÁS DETALLADO PARA DEBUGGING
            console.error('❌ Datos del request:', {
                username: req.body?.username,
                usernameLength: req.body?.username?.length,
                usernameType: typeof req.body?.username,
                email: req.body?.email,
                emailLength: req.body?.email?.length,
                hasPassword: !!req.body?.password
            });
            
            // Log del error de registro
            try {
                await this.logUserAction('USER_REGISTRATION_ERROR', {
                    usernameAttempt: req.body?.username ? this.generateUsernameHash(req.body.username.trim()) : 'unknown',
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

            // ✅ VALIDACIONES MEJORADAS
            if (!username || !password) {
                return res.status(400).json({
                    success: false,
                    message: 'Username y password son requeridos'
                });
            }

            // ✅ VALIDAR STRINGS VACÍOS
            const trimmedUsername = username.trim();
            if (trimmedUsername === '' || password.trim() === '') {
                return res.status(400).json({
                    success: false,
                    message: 'Los campos no pueden estar vacíos'
                });
            }

            // Buscar usuario por hash del username
            const usernameHash = this.generateUsernameHash(trimmedUsername);
            const db = require('../../config/database');
            
            console.log(`🔍 Intentando login para: "${trimmedUsername}" -> Hash: ${usernameHash.substring(0, 8)}...`);
            
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
                    usernameHash: req.body?.username ? this.generateUsernameHash(req.body.username.trim()) : 'unknown',
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

    // ✅ MÉTODO AUXILIAR MEJORADO
    generateUsernameHash(username) {
        // Crear hash determinístico para búsquedas
        const crypto = require('crypto');
        
        // ✅ VALIDAR ENTRADA
        if (!username || typeof username !== 'string') {
            throw new Error('Username inválido para generar hash');
        }
        
        const trimmedUsername = username.trim();
        if (trimmedUsername === '') {
            throw new Error('Username vacío no puede ser hasheado');
        }
        
        const salt = process.env.BASE_SEED || 'default_salt';
        const hash = crypto.createHash('sha256').update(trimmedUsername + salt).digest('hex');
        
        console.log(`🔑 Hash generado para "${trimmedUsername}": ${hash.substring(0, 8)}...`);
        return hash;
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