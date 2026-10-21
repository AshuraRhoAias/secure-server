const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const geoip = require('geoip-lite');
const credentialBuilder = require('../config/credential-builder');
const { sqlInt } = require('../config/sql');
const events = require('./security-events.service');
const anomalyDetection = require('./anomaly-detection.service');

// Autenticación. Todo el estado de seguridad (intentos fallidos, bloqueos, sesiones) está en
// MySQL (login_attempts, user_sessions, blocked_ips, security_events); no hay Map/Set en memoria.
//
// Cambios respecto a la versión anterior (todos verificados en test_security.js):
//  - El bloqueo de cuenta ahora SÍ funciona. Antes los fallos se guardaban con una clave
//    "usuario_IP" y se consultaban solo por "usuario": nunca coincidían y no se bloqueaba nada.
//  - El bloqueo se aplica también a usuarios que no existen (mismo mensaje y mismos tiempos),
//    para que no sirva para averiguar qué cuentas existen.
//  - Si el usuario no existe se compara igualmente contra un hash falso: sin esa comparación el
//    login respondía ~100 ms más rápido y delataba qué usuarios existen.
//  - El riesgo de login mira solo los fallos de ESE usuario (antes contaba los de todos).
//  - JWT con algoritmo fijado (HS256) y ligado a su sesión; caducidad calculada con la hora de la BD.

const intEnv = (name, fallback) => {
    const n = Number(process.env[name]);
    return Number.isInteger(n) && n > 0 ? n : fallback;
};

// Hash bcrypt de una cadena aleatoria desechada, para igualar el tiempo cuando el usuario no existe
const DUMMY_HASH = bcrypt.hashSync(crypto.randomBytes(16).toString('hex'), 12);

class AuthError extends Error {
    constructor(code, message, { status = 401, retryAfter = null } = {}) {
        super(message);
        this.code = code;
        this.status = status;
        this.retryAfter = retryAfter;
    }
}

class SecureAuthService {
    get lockout() {
        return {
            maxFailures: intEnv('MAX_FAILED_ATTEMPTS', 5),
            windowSec: intEnv('LOCKOUT_WINDOW_SECONDS', 15 * 60),
            ipFailuresToBlock: intEnv('LOGIN_IP_FAILURES_TO_BLOCK', 20)
        };
    }

    get sessionTtlHours() {
        return intEnv('SESSION_TTL_HOURS', 24 * 5);
    }

    async authenticateUser(username, password, deviceInfo) {
        const usernameHash = this.generateUsernameHash(username);
        const ip = deviceInfo.ipAddress;

        // 1. ¿Cuenta bloqueada por demasiados fallos recientes?
        const lock = await this.getLockState(usernameHash);
        if (lock.locked) {
            await events.record({
                type: 'LOGIN_BLOCKED', rule: 'ACCOUNT_LOCKED', severity: 'medium', riskScore: 50,
                action: 'locked_account', ip, usernameHash, details: { retryAfter: lock.retryAfter }
            });
            throw new AuthError('ACCOUNT_LOCKED', 'Cuenta temporalmente bloqueada por múltiples intentos fallidos', {
                status: 429, retryAfter: lock.retryAfter
            });
        }

        // 2. Credenciales (siempre una comparación bcrypt, exista o no el usuario)
        const user = await this.validateCredentials(username, password);
        if (!user) {
            await this.recordAttempt({ usernameHash, ip, success: false, reason: 'bad_credentials' });
            await events.record({
                type: 'LOGIN_FAILED', rule: 'BAD_CREDENTIALS', severity: 'medium', riskScore: 40,
                ip, usernameHash, status: 401
            });
            await this.checkIpFailures(ip);
            throw new AuthError('INVALID_CREDENTIALS', 'Credenciales inválidas');
        }

        // 3. Riesgo, sesión y token
        const deviceFingerprint = this.generateDeviceFingerprint(deviceInfo);
        const risk = await this.calculateRiskLevel(user, deviceInfo, deviceFingerprint, usernameHash);

        const sessionData = {
            userId: user.id,
            username: user.username,
            deviceFingerprint,
            ipAddress: ip,
            userAgent: deviceInfo.userAgent,
            riskLevel: risk.level,
            createdAt: Date.now()
        };

        const token = await this.generateSecureToken(sessionData);
        await this.createSecureSession(token, sessionData);
        await this.recordAttempt({ usernameHash, ip, userId: user.id, success: true });

        return {
            success: true,
            userId: user.id,
            token,
            expiresAt: new Date(Date.now() + this.sessionTtlHours * 3600 * 1000),
            riskLevel: risk.level,
            requiresVerification: false
        };
    }

    async validateCredentials(username, password) {
        const db = require('../config/database');
        const tripleEncryptor = require('../crypto/tripleEncryptor');

        const usernameHash = this.generateUsernameHash(username);
        const [users] = await db.query(
            'SELECT id, username_encrypted, password_hash FROM users WHERE username_hash = ?',
            [usernameHash]
        );

        const user = users[0];
        // Con o sin usuario se ejecuta bcrypt una vez: el tiempo de respuesta no delata si existe
        const passwordOk = await bcrypt.compare(String(password), user ? user.password_hash : DUMMY_HASH);
        if (!user || !passwordOk) return null;

        return { id: user.id, username: tripleEncryptor.decrypt(user.username_encrypted) };
    }

    generateUsernameHash(username) {
        if (!username || typeof username !== 'string') throw new Error('Username inválido para generar hash');

        const trimmed = username.trim();
        if (trimmed === '') throw new Error('Username vacío no puede ser hasheado');

        const salt = process.env.BASE_SEED || 'default_salt';
        return crypto.createHash('sha256').update(trimmed + salt).digest('hex');
    }

    generateDeviceFingerprint(deviceInfo = {}) {
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

    hashToken(token) {
        return crypto.createHash('sha256').update(token).digest('hex');
    }

    // ------------------------------------------------------------------ bloqueo de cuenta

    // Una cuenta está bloqueada si acumula `maxFailures` fallos en la ventana, contando solo los
    // posteriores a su último login correcto. Mientras está bloqueada NO se registran más intentos
    // (si no, un atacante la mantendría bloqueada para siempre).
    async getLockState(usernameHash) {
        const db = require('../config/database');
        const { maxFailures, windowSec } = this.lockout;

        const [rows] = await db.query(
            `SELECT COUNT(*) AS failures
             FROM login_attempts
             WHERE username_hash = ? AND success = 0
               AND created_at > DATE_SUB(NOW(3), INTERVAL ? SECOND)
               AND id > COALESCE((SELECT MAX(id) FROM login_attempts WHERE username_hash = ? AND success = 1), 0)`,
            [usernameHash, windowSec, usernameHash]
        );
        if (Number(rows[0].failures) < maxFailures) return { locked: false };

        // Se desbloquea cuando el fallo nº `maxFailures` más reciente sale de la ventana
        const [oldest] = await db.query(
            `SELECT TIMESTAMPDIFF(SECOND, created_at, NOW(3)) AS age
             FROM login_attempts
             WHERE username_hash = ? AND success = 0
               AND created_at > DATE_SUB(NOW(3), INTERVAL ? SECOND)
               AND id > COALESCE((SELECT MAX(id) FROM login_attempts WHERE username_hash = ? AND success = 1), 0)
             ORDER BY id DESC
             LIMIT 1 OFFSET ${sqlInt(maxFailures - 1)}`,
            [usernameHash, windowSec, usernameHash]
        );
        const age = Number(oldest[0]?.age) || 0;
        return { locked: true, retryAfter: Math.max(1, windowSec - age) };
    }

    async isAccountLocked(username) {
        return (await this.getLockState(this.generateUsernameHash(username))).locked;
    }

    async recordAttempt({ usernameHash, ip, userId = null, success, reason = null }) {
        const db = require('../config/database');
        try {
            await db.query(
                'INSERT INTO login_attempts (username_hash, ip_address, user_id, success, reason) VALUES (?, ?, ?, ?, ?)',
                [usernameHash, String(ip || 'unknown').slice(0, 45), userId, success ? 1 : 0, reason]
            );
        } catch (error) {
            console.error('❌ Error registrando intento de login:', error.code || error.message);
        }
    }

    // Muchos fallos desde la misma IP (aunque sea contra usuarios distintos = "credential stuffing")
    async checkIpFailures(ip) {
        const db = require('../config/database');
        const { ipFailuresToBlock, windowSec } = this.lockout;

        const [rows] = await db.query(
            `SELECT COUNT(*) AS failures FROM login_attempts
             WHERE ip_address = ? AND success = 0 AND created_at > DATE_SUB(NOW(3), INTERVAL ? SECOND)`,
            [String(ip || 'unknown').slice(0, 45), windowSec]
        );
        if (Number(rows[0].failures) >= ipFailuresToBlock) {
            await anomalyDetection.blockIP(ip, 'LOGIN_FAILURES_FROM_IP');
        }
    }

    // ------------------------------------------------------------------ riesgo

    async calculateRiskLevel(user, deviceInfo, deviceFingerprint, usernameHash) {
        let score = 0;
        const reasons = [];

        if (!(await this.isKnownDevice(user.id, deviceFingerprint))) { score += 30; reasons.push('NEW_DEVICE'); }

        const travel = await this.checkLocation(user.id, deviceInfo.ipAddress);
        if (travel.newCountry) { score += 25; reasons.push('NEW_COUNTRY'); }
        if (travel.impossibleTravel) { score += 40; reasons.push('IMPOSSIBLE_TRAVEL'); }

        if (this.isOffHours()) { score += 15; reasons.push('OFF_HOURS'); }

        const failures = await this.getRecentFailedAttempts(usernameHash);
        if (failures > 0) { score += Math.min(failures * 10, 30); reasons.push('RECENT_FAILURES'); }

        const level = score >= 70 ? 'high' : score >= 40 ? 'medium' : 'low';

        // Lo que merece análisis posterior queda en security_events
        if (reasons.includes('IMPOSSIBLE_TRAVEL') || reasons.includes('NEW_COUNTRY') || reasons.includes('NEW_DEVICE')) {
            await events.record({
                type: reasons.includes('IMPOSSIBLE_TRAVEL') ? 'IMPOSSIBLE_TRAVEL' : 'LOGIN_ANOMALY',
                rule: reasons.filter(r => r !== 'OFF_HOURS' && r !== 'RECENT_FAILURES').join('+').slice(0, 64),
                severity: reasons.includes('IMPOSSIBLE_TRAVEL') ? 'high' : 'low',
                riskScore: Math.min(score, 100),
                ip: deviceInfo.ipAddress, userId: user.id, usernameHash,
                details: { reasons, level, country: travel.country }
            });
        }

        return { level, score, reasons };
    }

    async isKnownDevice(userId, deviceFingerprint) {
        const db = require('../config/database');
        try {
            const [devices] = await db.query(
                'SELECT id FROM known_devices WHERE user_id = ? AND device_fingerprint = ?',
                [userId, deviceFingerprint]
            );

            if (devices.length > 0) {
                await db.query('UPDATE known_devices SET last_seen = NOW() WHERE user_id = ? AND device_fingerprint = ?', [userId, deviceFingerprint]);
                return true;
            }

            await db.query(
                `INSERT INTO known_devices (user_id, device_fingerprint, device_name, is_trusted)
                 VALUES (?, ?, 'Unknown Device', FALSE)
                 ON DUPLICATE KEY UPDATE last_seen = NOW()`,
                [userId, deviceFingerprint]
            );
            return false;
        } catch (error) {
            console.error('❌ Error verificando dispositivo conocido:', error.code || error.message);
            return false;
        }
    }

    // País nuevo para este usuario, y "viaje imposible": otra sesión de otro país hace menos de 1 hora
    async checkLocation(userId, ipAddress) {
        const geo = geoip.lookup(ipAddress);
        if (!geo) return { newCountry: false, impossibleTravel: false, country: null };

        const db = require('../config/database');
        try {
            const [sessions] = await db.query(
                `SELECT location_country, TIMESTAMPDIFF(MINUTE, created_at, NOW()) AS minutes_ago
                 FROM user_sessions WHERE user_id = ? AND location_country IS NOT NULL
                 ORDER BY id DESC LIMIT 20`,
                [userId]
            );

            const known = new Set(sessions.map(s => s.location_country));
            const last = sessions[0];
            return {
                country: geo.country,
                newCountry: sessions.length > 0 && !known.has(geo.country),
                impossibleTravel: Boolean(last && last.location_country !== geo.country && Number(last.minutes_ago) < 60)
            };
        } catch (error) {
            console.error('❌ Error verificando ubicación:', error.code || error.message);
            return { newCountry: false, impossibleTravel: false, country: geo.country };
        }
    }

    isOffHours() {
        const hour = new Date().getUTCHours();
        return hour >= 23 || hour <= 6;
    }

    // Fallos recientes de ESTE usuario (la versión anterior contaba los de toda la plataforma)
    async getRecentFailedAttempts(usernameHash) {
        const db = require('../config/database');
        try {
            const [rows] = await db.query(
                `SELECT COUNT(*) AS failures FROM login_attempts
                 WHERE username_hash = ? AND success = 0 AND created_at > DATE_SUB(NOW(3), INTERVAL 1 HOUR)`,
                [usernameHash]
            );
            return Number(rows[0].failures) || 0;
        } catch (error) {
            console.error('❌ Error obteniendo intentos fallidos:', error.code || error.message);
            return 0;
        }
    }

    // ------------------------------------------------------------------ tokens y sesiones

    async generateSecureToken(sessionData) {
        const payload = {
            userId: sessionData.userId,
            username: sessionData.username,
            sessionId: crypto.randomUUID(),
            riskLevel: sessionData.riskLevel
        };

        return jwt.sign(payload, credentialBuilder.generateJWTSecret(), {
            algorithm: 'HS256',
            expiresIn: `${this.sessionTtlHours}h`
        });
    }

    async createSecureSession(token, sessionData) {
        const db = require('../config/database');
        const geo = geoip.lookup(sessionData.ipAddress);

        await db.query(
            `INSERT INTO user_sessions
                (user_id, jwt_token_hash, ip_address, user_agent, device_fingerprint, risk_level, location_country, expires_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, DATE_ADD(NOW(), INTERVAL ? HOUR))`,
            [
                sessionData.userId,
                this.hashToken(token),
                String(sessionData.ipAddress || '').slice(0, 45),
                String(sessionData.userAgent || 'Unknown').slice(0, 500),
                sessionData.deviceFingerprint,
                sessionData.riskLevel,
                geo ? geo.country : null,
                this.sessionTtlHours
            ]
        );
    }

    async validateToken(token) {
        try {
            // Algoritmo fijado: un token firmado con otro algoritmo (o "none") se rechaza
            const decoded = jwt.verify(token, credentialBuilder.generateJWTSecret(), { algorithms: ['HS256'] });

            const db = require('../config/database');
            const [sessions] = await db.query(
                'SELECT id, user_id, risk_level, is_suspicious FROM user_sessions WHERE jwt_token_hash = ? AND expires_at > NOW()',
                [this.hashToken(token)]
            );

            const session = sessions[0];
            // La sesión debe existir Y pertenecer al usuario que dice el token
            if (!session || Number(session.user_id) !== Number(decoded.userId)) throw new Error('Sesión inválida o expirada');
            if (session.is_suspicious) throw new Error('Sesión marcada como sospechosa');

            return {
                valid: true,
                userId: decoded.userId,
                username: decoded.username,
                sessionId: session.id,
                riskLevel: session.risk_level
            };
        } catch (error) {
            // Mensaje genérico: no se distingue firma inválida de caducada
            const known = ['Sesión inválida o expirada', 'Sesión marcada como sospechosa'];
            return { valid: false, error: known.includes(error.message) ? error.message : 'Token inválido o expirado' };
        }
    }

    // Tareas de mantenimiento (las lanza el servicio de limpieza)
    async purgeOldData() {
        const db = require('../config/database');
        const [sessions] = await db.query('DELETE FROM user_sessions WHERE expires_at < DATE_SUB(NOW(), INTERVAL 1 DAY) LIMIT 5000');
        const [attempts] = await db.query('DELETE FROM login_attempts WHERE created_at < DATE_SUB(NOW(), INTERVAL 30 DAY) LIMIT 5000');
        return { sessions: sessions.affectedRows, loginAttempts: attempts.affectedRows };
    }
}

module.exports = new SecureAuthService();
module.exports.AuthError = AuthError;
