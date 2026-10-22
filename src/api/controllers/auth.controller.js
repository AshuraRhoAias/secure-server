const secureAuthService = require('../../security/secure-auth.service');
const { AuthError } = secureAuthService;
const { normalizeIp } = require('../../security/ip');
const mfaService = require('../../security/mfa.service');
const { MfaError } = mfaService;
const events = require('../../security/security-events.service');
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
        Object.getOwnPropertyNames(AuthController.prototype)
            .filter(name => name !== 'constructor')
            .forEach(name => { this[name] = this[name].bind(this); });
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
            const authResult = await secureAuthService.authenticateUser(username, password, this.deviceContext(req, ip));

            // Contraseña correcta pero la cuenta tiene MFA: falta el segundo factor (POST /api/auth/login/mfa)
            if (authResult.mfaRequired) {
                return res.json({
                    success: true,
                    mfaRequired: true,
                    message: 'Se requiere el segundo factor',
                    mfaToken: authResult.mfaToken,
                    mfaTokenExpiresIn: authResult.mfaTokenExpiresIn
                });
            }

            await this.finishLogin(res, authResult, { usernameHash: this.generateUsernameHash(username), ip });
        } catch (error) {
            await this.failedAuth(res, error, { usernameHash: this.generateUsernameHash(username), ip, where: 'login' });
        }
    }

    // Paso 2 con MFA: canjea el reto de login() por la sesión
    async loginMfa(req, res) {
        const { mfaToken, otp, recoveryCode } = req.body;
        const ip = normalizeIp(req.ip);
        let usernameHash = 'unknown';

        try {
            if (!otp && !recoveryCode) {
                return res.status(400).json({ success: false, message: 'Envía otp o recoveryCode', code: 'VALIDATION_ERROR' });
            }
            try { usernameHash = require('jsonwebtoken').decode(mfaToken)?.uh || 'unknown'; } catch { /* se valida dentro */ }

            const authResult = await secureAuthService.verifyMfaChallenge(mfaToken, { otp, recoveryCode }, this.deviceContext(req, ip));
            await this.finishLogin(res, authResult, { usernameHash, ip });
        } catch (error) {
            await this.failedAuth(res, error, { usernameHash, ip, where: 'login-mfa' });
        }
    }

    deviceContext(req, ip) {
        return { ...this.cleanDeviceInfo(req.body.deviceInfo), ipAddress: ip, userAgent: req.headers['user-agent'] };
    }

    async finishLogin(res, authResult, { usernameHash, ip }) {
        const db = require('../../config/database');
        await db.query(
            'UPDATE users SET risk_level_encrypted = ?, updated_at = NOW() WHERE id = ?',
            [tripleEncryptor.encrypt(authResult.riskLevel), authResult.userId]
        );

        await this.logUserAction('USER_LOGIN_SUCCESS', {
            userId: authResult.userId, usernameHash, ipAddress: ip, riskLevel: authResult.riskLevel,
            authMethods: authResult.amr, encryptionVersion: this.getCurrentEncryptionVersion()
        });

        res.json({
            success: true,
            message: 'Autenticación exitosa',
            ...this.tokenFields(authResult),
            riskLevel: authResult.riskLevel,
            authMethods: authResult.amr,
            encryptionVersion: this.getCurrentEncryptionVersion()
        });
    }

    // token = JWT de acceso (corto); refreshToken = para pedir otro sin volver a iniciar sesión (POST /api/auth/refresh)
    tokenFields(result) {
        return {
            token: result.token,
            refreshToken: result.refreshToken,
            expiresAt: result.expiresAt,
            expiresIn: result.expiresIn,
            refreshExpiresAt: result.refreshExpiresAt,
            sessionExpiresAt: result.sessionExpiresAt
        };
    }

    // Renueva el token de acceso con el refresh token (que rota). Sin sesión previa: el refresh ES la credencial.
    async refresh(req, res) {
        const ip = normalizeIp(req.ip);
        try {
            const result = await secureAuthService.refreshSession(req.body.refreshToken, this.deviceContext(req, ip));
            res.set('Cache-Control', 'no-store');
            res.json({ success: true, ...this.tokenFields(result), authMethods: result.amr, riskLevel: result.riskLevel });
        } catch (error) {
            if (error instanceof AuthError) {
                res.set('Cache-Control', 'no-store');
                return res.status(error.status).json({ success: false, message: error.message, code: error.code });
            }
            console.error('❌ Error renovando sesión:', error.code || error.message);
            res.status(500).json({ success: false, message: 'Error interno del servidor' });
        }
    }

    // Sesiones abiertas del usuario (dispositivo, país, último uso) para que reconozca las que no son suyas
    async listSessions(req, res) {
        try {
            const sessions = await secureAuthService.listSessions(req.user.id, req.user.sessionId);
            res.json({ success: true, sessions });
        } catch (error) {
            console.error('❌ Error listando sesiones:', error.code || error.message);
            res.status(500).json({ success: false, message: 'Error interno del servidor' });
        }
    }

    async revokeSession(req, res) {
        try {
            const closed = await secureAuthService.revokeSession(req.user.id, req.validated.params.id, 'user_revoked');
            if (!closed) return res.status(404).json({ success: false, message: 'Sesión no encontrada', code: 'NOT_FOUND' });
            await events.record({ type: 'SESSION_REVOKED', severity: 'info', req, userId: req.user.id, details: { sessionId: req.validated.params.id } });
            res.json({ success: true, message: 'Sesión cerrada' });
        } catch (error) {
            console.error('❌ Error cerrando la sesión:', error.code || error.message);
            res.status(500).json({ success: false, message: 'Error interno del servidor' });
        }
    }

    // "Cerrar todas las sesiones": la actual incluida, salvo que se pida conservarla con { keepCurrent: true }
    async logoutAll(req, res) {
        try {
            const keepCurrent = req.body?.keepCurrent === true;
            const closed = await secureAuthService.revokeAllSessions(req.user.id, {
                exceptSessionId: keepCurrent ? req.user.sessionId : null, reason: 'user_logout_all'
            });
            await events.record({ type: 'LOGOUT_ALL', severity: 'info', req, userId: req.user.id, details: { closed, keepCurrent } });
            res.json({ success: true, message: `Se cerraron ${closed} sesión(es)`, closed, keptCurrent: keepCurrent });
        } catch (error) {
            console.error('❌ Error cerrando todas las sesiones:', error.code || error.message);
            res.status(500).json({ success: false, message: 'Error interno del servidor' });
        }
    }

    async failedAuth(res, error, { usernameHash, ip, where }) {
        // Errores previstos (credenciales, bloqueo, MFA): mensaje y código estables
        if (error instanceof AuthError) {
            await this.logUserAction('USER_LOGIN_FAILED', { usernameHash, ipAddress: ip, error: error.code });

            if (error.retryAfter) res.set('Retry-After', String(error.retryAfter));
            return res.status(error.status).json({
                success: false,
                message: error.message,
                code: error.code,
                ...(error.retryAfter && { retryAfter: error.retryAfter })
            });
        }

        // Cualquier otro error es nuestro: se registra, pero al cliente NO se le cuenta el detalle
        console.error(`❌ Error en ${where}:`, error.code || error.message);
        res.status(500).json({ success: false, message: 'Error interno del servidor' });
    }

    // ------------------------------------------------------------------ MFA (requiere sesión)

    async mfaStatus(req, res) {
        res.json({ success: true, mfa: await mfaService.status(req.user.id) });
    }

    async mfaSetup(req, res) {
        try {
            const setup = await mfaService.beginSetup(req.user.id, req.user.username);
            await this.logUserAction('MFA_SETUP_STARTED', { userId: req.user.id, ipAddress: normalizeIp(req.ip) });
            res.json({
                success: true,
                message: 'Escanea el QR con tu app de autenticación y confirma con POST /api/auth/mfa/enable',
                ...setup
            });
        } catch (error) {
            this.mfaFailure(res, error);
        }
    }

    async mfaEnable(req, res) {
        try {
            const { recoveryCodes } = await mfaService.enable(req.user.id, req.body.otp);
            await this.logUserAction('MFA_ENABLED', { userId: req.user.id, ipAddress: normalizeIp(req.ip) });
            await events.record({ type: 'MFA_ENABLED', severity: 'info', req, userId: req.user.id });
            res.json({
                success: true,
                message: 'Autenticación en dos pasos activada. Guarda estos códigos de recuperación: no se volverán a mostrar.',
                recoveryCodes
            });
        } catch (error) {
            this.mfaFailure(res, error);
        }
    }

    // Desactivar y regenerar códigos exigen contraseña Y un segundo factor válido: una sesión robada no basta
    async requireStrongReauth(req) {
        const { password, otp, recoveryCode } = req.body;
        if (!(await mfaService.passwordMatches(req.user.id, password))) {
            throw new MfaError('INVALID_CREDENTIALS', 'Credenciales inválidas', 401);
        }
        if (!(await mfaService.verify(req.user.id, { otp, recoveryCode })).ok) {
            throw new MfaError('INVALID_OTP', 'Código incorrecto', 401);
        }
    }

    async mfaDisable(req, res) {
        try {
            await this.requireStrongReauth(req);
            await mfaService.disable(req.user.id);
            await this.logUserAction('MFA_DISABLED', { userId: req.user.id, ipAddress: normalizeIp(req.ip) });
            await events.record({ type: 'MFA_DISABLED', severity: 'medium', riskScore: 30, req, userId: req.user.id });
            res.json({ success: true, message: 'Autenticación en dos pasos desactivada' });
        } catch (error) {
            this.mfaFailure(res, error);
        }
    }

    async mfaRegenerateCodes(req, res) {
        try {
            await this.requireStrongReauth(req);
            const recoveryCodes = await mfaService.regenerateRecoveryCodes(req.user.id);
            await events.record({ type: 'MFA_RECOVERY_CODES_REGENERATED', severity: 'low', req, userId: req.user.id });
            res.json({ success: true, recoveryCodes, message: 'Los códigos anteriores ya no sirven' });
        } catch (error) {
            this.mfaFailure(res, error);
        }
    }

    mfaFailure(res, error) {
        if (error instanceof MfaError) {
            return res.status(error.status).json({ success: false, message: error.message, code: error.code });
        }
        console.error('❌ Error en MFA:', error.code || error.message);
        res.status(500).json({ success: false, message: 'Error interno del servidor' });
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
            await secureAuthService.revokeSession(req.user.id, req.user.sessionId, 'user_logout');

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
            'USER_PROFILE_ERROR': 'medium',
            'MFA_DISABLED': 'medium'
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