const secureAuthService = require('../../security/secure-auth.service');
const { AuthError } = secureAuthService;
const { normalizeIp } = require('../../security/ip');
const mfaService = require('../../security/mfa.service');
const { MfaError } = mfaService;
const webauthn = require('../../security/webauthn.service');
const events = require('../../security/security-events.service');
const tripleEncryptor = require('../../crypto/tripleEncryptor');
const bcrypt = require('bcryptjs');
const userAdmin = require('../../security/user-admin.service');

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
                    mfaTokenExpiresIn: authResult.mfaTokenExpiresIn,
                    methods: authResult.mfaMethods
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

    // Paso 2 con passkey. A) opciones (reto)  B) firma
    async loginWebauthnOptions(req, res) {
        const ip = normalizeIp(req.ip);
        try {
            const options = await secureAuthService.beginWebauthnLogin(req.body.mfaToken, this.deviceContext(req, ip));
            res.set('Cache-Control', 'no-store');
            res.json({ success: true, options });
        } catch (error) {
            if (error instanceof webauthn.WebauthnError) return this.webauthnFailure(res, error);
            await this.failedAuth(res, error, { usernameHash: 'unknown', ip, where: 'login-webauthn-options' });
        }
    }

    async loginWebauthn(req, res) {
        const ip = normalizeIp(req.ip);
        let usernameHash = 'unknown';
        try {
            try { usernameHash = require('jsonwebtoken').decode(req.body.mfaToken)?.uh || 'unknown'; } catch { /* se valida dentro */ }
            const authResult = await secureAuthService.verifyWebauthnChallenge(req.body.mfaToken, req.body.credential, this.deviceContext(req, ip));
            await this.finishLogin(res, authResult, { usernameHash, ip });
        } catch (error) {
            if (error instanceof webauthn.WebauthnError) return this.webauthnFailure(res, error);
            await this.failedAuth(res, error, { usernameHash, ip, where: 'login-webauthn' });
        }
    }

    // ------------------------------------------------------------------ gestionar passkeys (sesión iniciada)

    // Contraseña SIEMPRE; y, si ya hay un segundo factor, también un código válido: una sesión robada no puede
    // añadir su propia llave para quedarse (ni quitar la del dueño).
    async requireManageReauth(req) {
        if (!(await mfaService.passwordMatches(req.user.id, req.body.password))) {
            throw new MfaError('INVALID_CREDENTIALS', 'Credenciales inválidas', 401);
        }
        if (await mfaService.hasSecondFactor(req.user.id)) {
            const { otp, recoveryCode } = req.body;
            if (!(otp || recoveryCode) || !(await mfaService.verify(req.user.id, { otp, recoveryCode })).ok) {
                throw new MfaError('INVALID_OTP', 'Código incorrecto', 401);
            }
        }
    }

    async webauthnList(req, res) {
        try {
            const rows = await webauthn.listCredentials(req.user.id);
            res.json({ success: true, enabled: webauthn.enabled(), credentials: rows.map(webauthn.publicCredential) });
        } catch (error) {
            this.webauthnFailure(res, error);
        }
    }

    async webauthnRegisterOptions(req, res) {
        try {
            await this.requireManageReauth(req);
            const options = await webauthn.beginRegistration(req.user.id, req.user.username);
            res.set('Cache-Control', 'no-store');
            res.json({ success: true, options });
        } catch (error) {
            this.webauthnFailure(res, error);
        }
    }

    async webauthnRegister(req, res) {
        try {
            const hadFactor = await mfaService.hasSecondFactor(req.user.id);
            const { id } = await webauthn.finishRegistration(req.user.id, req.body.credential, req.body.name);
            // La primera llave es el primer segundo factor: sin códigos de recuperación, perderla dejaría a la persona fuera
            const recoveryCodes = hadFactor ? undefined : await mfaService.regenerateRecoveryCodes(req.user.id);
            await events.record({ type: 'WEBAUTHN_REGISTERED', severity: 'low', riskScore: 10, req, userId: req.user.id, details: { credentialRow: id } });
            res.status(201).json({
                success: true, id,
                ...(recoveryCodes && { recoveryCodes, message: 'Guarda estos códigos de recuperación: no se volverán a mostrar.' })
            });
        } catch (error) {
            this.webauthnFailure(res, error);
        }
    }

    async webauthnRemove(req, res) {
        try {
            await this.requireManageReauth(req);
            if (!(await webauthn.removeCredential(req.user.id, req.validated.params.id))) {
                return res.status(404).json({ success: false, message: 'Llave no encontrada', code: 'NOT_FOUND' });
            }
            // Si era el último factor, los códigos de recuperación ya no protegen nada
            if (!(await mfaService.hasSecondFactor(req.user.id))) await mfaService.clearRecoveryCodes(req.user.id);
            await events.record({ type: 'WEBAUTHN_REMOVED', severity: 'medium', riskScore: 20, req, userId: req.user.id, details: { credentialRow: req.validated.params.id } });
            res.json({ success: true, message: 'Llave eliminada' });
        } catch (error) {
            this.webauthnFailure(res, error);
        }
    }

    webauthnFailure(res, error) {
        if (error instanceof webauthn.WebauthnError || error instanceof MfaError) {
            return res.status(error.status).json({ success: false, message: error.message, code: error.code });
        }
        console.error('❌ Error en WebAuthn:', error.code || error.message);
        res.status(500).json({ success: false, message: 'Error interno del servidor' });
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
        const [flags] = await db.query('SELECT must_change_password FROM users WHERE id = ?', [authResult.userId]);

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
            encryptionVersion: this.getCurrentEncryptionVersion(),
            passwordChangeRequired: Number(flags[0]?.must_change_password) === 1
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

    // Cambio de contraseña propio. Decisión: responde 200 SIN tokens nuevos. El JWT no lleva el indicador de "cambio obligatorio"
    // (se lee de la BD con la sesión en cada petición), así que la sesión actual y su refresh siguen valiendo; solo se cierran
    // las DEMÁS sesiones del usuario.
    async changePassword(req, res) {
        try {
            const result = await userAdmin.changePassword(req.user.id, {
                currentSessionId: req.user.sessionId,
                currentPassword: req.body.currentPassword,
                newPassword: req.body.newPassword
            });
            res.set('Cache-Control', 'no-store');
            res.json({ success: true, message: 'Contraseña cambiada', sessionsClosed: result.sessionsClosed });
        } catch (error) {
            if (error instanceof userAdmin.UserAdminError) {
                return res.status(error.status).json({ success: false, message: error.message, code: error.code });
            }
            console.error('❌ Error cambiando la contraseña:', error.code || error.message);
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
}

module.exports = new AuthController();