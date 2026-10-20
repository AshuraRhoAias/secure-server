const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const geoip = require('geoip-lite');
const credentialBuilder = require('../config/credential-builder');

class SecureAuthService {
    constructor() {
        this.suspiciousSessions = new Set();
        this.deviceFingerprints = new Map();
        this.failedAttempts = new Map();
        this.setupSessionMonitoring();
    }

    async authenticateUser(username, password, deviceInfo) {
        try {
            // Verificar intentos fallidos previos
            if (await this.isAccountLocked(username)) {
                throw new Error('Cuenta temporalmente bloqueada por múltiples intentos fallidos');
            }

            // Validar credenciales básicas
            const user = await this.validateCredentials(username, password);
            if (!user) {
                await this.recordFailedAttempt(username, deviceInfo);
                throw new Error('Credenciales inválidas');
            }

            // Generar fingerprint del dispositivo
            const deviceFingerprint = this.generateDeviceFingerprint(deviceInfo);

            // Calcular nivel de riesgo
            const riskLevel = await this.calculateRiskLevel(user, deviceInfo, deviceFingerprint);

            // Crear sesión segura
            const sessionData = {
                userId: user.id,
                username: user.username, // Ya viene descifrado del validateCredentials
                deviceFingerprint,
                ipAddress: deviceInfo.ipAddress,
                riskLevel,
                createdAt: Date.now()
            };

            const token = await this.generateSecureToken(sessionData);
            await this.createSecureSession(token, sessionData);

            // Limpiar intentos fallidos exitosos
            this.failedAttempts.delete(username);

            return {
                success: true,
                token,
                expiresAt: new Date(Date.now() + 5 * 24 * 60 * 60 * 1000),
                riskLevel,
                requiresVerification: false
            };

        } catch (error) {
            await this.logFailedAttempt(username, deviceInfo, error.message);
            throw error;
        }
    }

    // ✅ MÉTODO CORREGIDO PARA USAR COLUMNAS CIFRADAS
    async validateCredentials(username, password) {
        const db = require('../config/database');
        const tripleEncryptor = require('../crypto/tripleEncryptor');

        try {
            // ✅ Generar hash del username para buscar en la base de datos
            const usernameHash = this.generateUsernameHash(username);
            
            // ✅ Consulta corregida usando las columnas cifradas
            const [users] = await db.query(
                'SELECT id, username_encrypted, password_hash, risk_level_encrypted FROM users WHERE username_hash = ?',
                [usernameHash]
            );

            if (users.length === 0) {
                console.log(`🔍 Usuario no encontrado para hash: ${usernameHash.substring(0, 8)}...`);
                return null;
            }

            const user = users[0];
            
            // ✅ Verificar password
            const isValidPassword = await bcrypt.compare(password, user.password_hash);
            if (!isValidPassword) {
                console.log(`❌ Password inválido para usuario ID: ${user.id}`);
                return null;
            }

            // ✅ Descifrar username para devolver
            const decryptedUsername = tripleEncryptor.decrypt(user.username_encrypted);
            
            console.log(`✅ Credenciales válidas para el usuario ID: ${user.id}`);

            return {
                id: user.id,
                username: decryptedUsername, // Username descifrado
                password_hash: user.password_hash
            };

        } catch (error) {
            console.error('❌ Error validating credentials:', error);
            return null;
        }
    }

    // ✅ MÉTODO AGREGADO PARA GENERAR HASH DEL USERNAME
    generateUsernameHash(username) {
        // ✅ Validar entrada
        if (!username || typeof username !== 'string') {
            throw new Error('Username inválido para generar hash');
        }
        
        const trimmedUsername = username.trim();
        if (trimmedUsername === '') {
            throw new Error('Username vacío no puede ser hasheado');
        }
        
        // ✅ Usar la misma lógica que en AuthController
        const salt = process.env.BASE_SEED || 'default_salt';
        const hash = crypto.createHash('sha256').update(trimmedUsername + salt).digest('hex');
        
        console.log(`🔑 Hash generado para "${trimmedUsername}": ${hash.substring(0, 8)}... (SecureAuthService)`);
        return hash;
    }

    generateDeviceFingerprint(deviceInfo) {
        const components = [
            deviceInfo.userAgent || '',
            deviceInfo.screenResolution || '',
            deviceInfo.timezone || '',
            deviceInfo.language || '',
            deviceInfo.platform || '',
            deviceInfo.colorDepth || '',
            deviceInfo.pixelRatio || ''
        ].join('|');

        return crypto.createHash('sha256').update(components).digest('hex');
    }

    async calculateRiskLevel(user, deviceInfo, deviceFingerprint) {
        let riskScore = 0;

        // Factor 1: Dispositivo desconocido
        const isKnownDevice = await this.isKnownDevice(user.id, deviceFingerprint);
        if (!isKnownDevice) riskScore += 30;

        // Factor 2: Nueva ubicación geográfica
        const isNewLocation = await this.isNewLocation(user.id, deviceInfo.ipAddress);
        if (isNewLocation) riskScore += 25;

        // Factor 3: Horario inusual
        if (this.isOffHours()) riskScore += 15;

        // Factor 4: Intentos fallidos recientes
        const recentFailures = await this.getRecentFailedAttempts(user.id);
        if (recentFailures > 0) riskScore += (recentFailures * 10);

        // Clasificar riesgo
        if (riskScore >= 70) return 'high';
        if (riskScore >= 40) return 'medium';
        return 'low';
    }

    async generateSecureToken(sessionData) {
        const jwtSecret = credentialBuilder.generateJWTSecret();

        const payload = {
            userId: sessionData.userId,
            username: sessionData.username,
            sessionId: crypto.randomUUID(),
            deviceFingerprint: sessionData.deviceFingerprint,
            riskLevel: sessionData.riskLevel,
            iat: Math.floor(Date.now() / 1000)
        };

        return jwt.sign(payload, jwtSecret, { expiresIn: '5d' });
    }

    async createSecureSession(token, sessionData) {
        const db = require('../config/database');
        const geo = geoip.lookup(sessionData.ipAddress);

        const tokenHash = this.hashToken(token);
        const expiresAt = new Date(Date.now() + 5 * 24 * 60 * 60 * 1000);

        await db.query(`
            INSERT INTO user_sessions 
            (user_id, jwt_token_hash, ip_address, user_agent, device_fingerprint, 
             risk_level, location_country, expires_at) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `, [
            sessionData.userId,
            tokenHash,
            sessionData.ipAddress,
            sessionData.userAgent || 'Unknown',
            sessionData.deviceFingerprint,
            sessionData.riskLevel,
            geo ? geo.country : null,
            expiresAt
        ]);
    }

    async validateToken(token, currentIP) {
        try {
            const jwtSecret = credentialBuilder.generateJWTSecret();
            const decoded = jwt.verify(token, jwtSecret);

            // Verificar que la sesión existe
            const db = require('../config/database');
            const [sessions] = await db.query(
                'SELECT * FROM user_sessions WHERE jwt_token_hash = ? AND expires_at > NOW()',
                [this.hashToken(token)]
            );

            if (sessions.length === 0) {
                throw new Error('Sesión inválida o expirada');
            }

            const session = sessions[0];

            // Verificar si la sesión está marcada como sospechosa
            if (session.is_suspicious) {
                throw new Error('Sesión marcada como sospechosa');
            }

            return {
                valid: true,
                userId: decoded.userId,
                username: decoded.username,
                sessionId: session.id,
                riskLevel: session.risk_level
            };

        } catch (error) {
            return {
                valid: false,
                error: error.message
            };
        }
    }

    hashToken(token) {
        return crypto.createHash('sha256').update(token).digest('hex');
    }

    async recordFailedAttempt(username, deviceInfo) {
        // ✅ Usar hash del username para consistencia
        const usernameHash = this.generateUsernameHash(username);
        const key = `${usernameHash}_${deviceInfo.ipAddress}`;
        const attempts = this.failedAttempts.get(key) || [];

        attempts.push(Date.now());
        this.failedAttempts.set(key, attempts);

        // Limpiar intentos antiguos (más de 1 hora)
        const oneHourAgo = Date.now() - (60 * 60 * 1000);
        const recentAttempts = attempts.filter(timestamp => timestamp > oneHourAgo);
        this.failedAttempts.set(key, recentAttempts);
    }

    async isAccountLocked(username) {
        // ✅ Usar hash del username para consistencia
        const usernameHash = this.generateUsernameHash(username);
        const attempts = this.failedAttempts.get(usernameHash) || [];
        const oneHourAgo = Date.now() - (60 * 60 * 1000);
        const recentAttempts = attempts.filter(timestamp => timestamp > oneHourAgo);

        return recentAttempts.length >= 5; // Bloquear después de 5 intentos fallidos
    }

    setupSessionMonitoring() {
        // Auditoría de sesiones cada 5 minutos
        setInterval(async () => {
            await this.auditActiveSessions();
        }, 5 * 60 * 1000);

        // Limpiar datos antiguos cada hora
        setInterval(() => {
            this.cleanupOldData();
        }, 60 * 60 * 1000);
    }

    async auditActiveSessions() {
        // Implementar auditoría de sesiones activas
        console.log('🔍 Auditando sesiones activas...');
    }

    cleanupOldData() {
        const oneHourAgo = Date.now() - (60 * 60 * 1000);

        // Limpiar intentos fallidos antiguos
        for (const [key, attempts] of this.failedAttempts.entries()) {
            const recentAttempts = attempts.filter(timestamp => timestamp > oneHourAgo);
            if (recentAttempts.length === 0) {
                this.failedAttempts.delete(key);
            } else {
                this.failedAttempts.set(key, recentAttempts);
            }
        }

        console.log('🧹 Limpieza de datos de autenticación completada');
    }

    async logFailedAttempt(username, deviceInfo, error) {
        const db = require('../config/database');
        const tripleEncryptor = require('../crypto/tripleEncryptor');

        try {
            // ✅ Usar hash del username para logging seguro
            const usernameHash = this.generateUsernameHash(username);
            
            const encryptedDetails = tripleEncryptor.encrypt(JSON.stringify({
                usernameHash: usernameHash, // Usar hash en lugar de username real
                ipAddress: deviceInfo.ipAddress,
                userAgent: deviceInfo.userAgent,
                error,
                timestamp: new Date().toISOString()
            }));

            await db.query(
                `INSERT INTO security_logs (event_type, encrypted_details, ip_address, severity) 
                    VALUES ('LOGIN_FAILED', ?, ?, 'medium')`,
                [encryptedDetails, deviceInfo.ipAddress]
            );
        } catch (logError) {
            console.error('❌ Error logging failed attempt:', logError);
        }
    }

    // ======== MÉTODOS FALTANTES AGREGADOS ========

    async isKnownDevice(userId, deviceFingerprint) {
        try {
            const db = require('../config/database');

            const [devices] = await db.query(
                'SELECT id FROM known_devices WHERE user_id = ? AND device_fingerprint = ?',
                [userId, deviceFingerprint]
            );

            const isKnown = devices.length > 0;

            if (!isKnown) {
                try {
                    await db.query(
                        `INSERT INTO known_devices (user_id, device_fingerprint, device_name, is_trusted) 
                         VALUES (?, ?, 'Unknown Device', FALSE)
                         ON DUPLICATE KEY UPDATE last_seen = NOW()`,
                        [userId, deviceFingerprint]
                    );
                } catch (insertError) {
                    console.log('ℹ️ Dispositivo ya existe o tabla no disponible');
                }
            } else {
                await db.query(
                    'UPDATE known_devices SET last_seen = NOW() WHERE user_id = ? AND device_fingerprint = ?',
                    [userId, deviceFingerprint]
                );
            }

            return isKnown;
        } catch (error) {
            console.error('❌ Error verificando dispositivo conocido:', error);
            return false;
        }
    }

    async isNewLocation(userId, ipAddress) {
        try {
            const geo = geoip.lookup(ipAddress);

            if (!geo) return false;

            const db = require('../config/database');

            const [sessions] = await db.query(
                'SELECT DISTINCT location_country FROM user_sessions WHERE user_id = ? AND location_country IS NOT NULL',
                [userId]
            );

            const knownCountries = sessions.map(s => s.location_country);

            return !knownCountries.includes(geo.country);
        } catch (error) {
            console.error('❌ Error verificando nueva ubicación:', error);
            return false;
        }
    }

    isOffHours() {
        const now = new Date();
        const hour = now.getHours();

        // Considerar horario inusual: 11 PM a 6 AM
        return hour >= 23 || hour <= 6;
    }

    async getRecentFailedAttempts(userId) {
        try {
            const db = require('../config/database');

            const [logs] = await db.query(
                `SELECT COUNT(*) as failed_attempts 
                 FROM security_logs 
                 WHERE event_type = 'LOGIN_FAILED' 
                 AND created_at > DATE_SUB(NOW(), INTERVAL 1 HOUR)`,
                []
            );

            return logs[0]?.failed_attempts || 0;
        } catch (error) {
            console.error('❌ Error obteniendo intentos fallidos:', error);
            return 0;
        }
    }
}

module.exports = new SecureAuthService();