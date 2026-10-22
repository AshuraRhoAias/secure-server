const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const geoip = require('geoip-lite');
const credentialBuilder = require('../config/credential-builder');
const { sqlInt } = require('../config/sql');
const events = require('./security-events.service');
const anomalyDetection = require('./anomaly-detection.service');
const { ipSubject } = require('./ip');

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

// Número positivo (admite decimales: ACCESS_TOKEN_MINUTES=0.5 son 30 s)
const numEnv = (name, fallback) => {
    const n = Number(process.env[name]);
    return Number.isFinite(n) && n > 0 ? n : fallback;
};

const MFA_CHALLENGE_SECONDS = 5 * 60;

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
            maxFailures: intEnv('MAX_FAILED_ATTEMPTS', 5),                 // por (usuario, origen)
            globalMaxFailures: intEnv('LOCKOUT_GLOBAL_FAILURES', 20),      // por usuario, desde cualquier origen
            windowSec: intEnv('LOCKOUT_WINDOW_SECONDS', 15 * 60),
            trustedDays: intEnv('TRUSTED_SOURCE_DAYS', 30),
            ipFailuresToBlock: intEnv('LOGIN_IP_FAILURES_TO_BLOCK', 20)
        };
    }

    // Sesiones: JWT de acceso CORTO + refresh token opaco que rota en cada uso.
    //   ACCESS_TOKEN_MINUTES (15)     vida del JWT de acceso: lo que puede robar quien lea una petición
    //   REFRESH_IDLE_DAYS (7)         sin renovar durante este tiempo, la sesión caduca (se desliza con cada uso)
    //   SESSION_ABSOLUTE_DAYS (30)    tope: pasado este tiempo hay que iniciar sesión de nuevo, se renueve o no
    //   REFRESH_REUSE_GRACE_SECONDS   dos pestañas que renuevan a la vez no son un robo (409, sin revocar)
    get sessionConfig() {
        const absoluteSeconds = Math.round(numEnv('SESSION_ABSOLUTE_DAYS', 30) * 86400);
        return {
            accessSeconds: Math.max(1, Math.round(numEnv('ACCESS_TOKEN_MINUTES', 15) * 60)),
            idleSeconds: Math.min(Math.round(numEnv('REFRESH_IDLE_DAYS', 7) * 86400), absoluteSeconds),
            absoluteSeconds,
            reuseGraceSeconds: intEnv('REFRESH_REUSE_GRACE_SECONDS', 10)
        };
    }

    // Paso 1 del login: usuario y contraseña. Si el usuario tiene MFA, NO se crea sesión: se devuelve un
    // "reto" firmado de corta duración que hay que canjear en verifyMfaChallenge con el segundo factor.
    async authenticateUser(username, password, deviceInfo) {
        const usernameHash = this.generateUsernameHash(username);
        const ip = deviceInfo.ipAddress;

        await this.assertNotLocked(usernameHash, ip);

        const user = await this.validateCredentials(username, password);
        if (!user) {
            await this.failLogin({ usernameHash, ip, rule: 'BAD_CREDENTIALS', reason: 'bad_credentials' });
            throw new AuthError('INVALID_CREDENTIALS', 'Credenciales inválidas');
        }

        if (user.mfaEnabled) {
            // Acertar la contraseña NO cuenta como éxito: si lo hiciera, quien la conoce reiniciaría el
            // contador de fallos y podría probar códigos TOTP sin límite.
            return {
                success: true,
                userId: user.id,
                mfaRequired: true,
                mfaToken: this.signMfaChallenge(user, usernameHash),
                mfaTokenExpiresIn: MFA_CHALLENGE_SECONDS
            };
        }

        return this.completeLogin({ user, usernameHash, deviceInfo, amr: ['pwd'] });
    }

    // Paso 2 del login con MFA
    async verifyMfaChallenge(mfaToken, { otp, recoveryCode }, deviceInfo) {
        const mfa = require('./mfa.service');
        const ip = deviceInfo.ipAddress;

        let challenge;
        try {
            challenge = jwt.verify(mfaToken, credentialBuilder.generateJWTSecret(), { algorithms: ['HS256'] });
            if (challenge.typ !== 'mfa') throw new Error('tipo');
        } catch {
            throw new AuthError('INVALID_MFA_TOKEN', 'El reto de verificación no es válido o caducó: vuelve a iniciar sesión');
        }

        // El segundo factor comparte el bloqueo de cuenta con la contraseña
        await this.assertNotLocked(challenge.uh, ip);

        const result = await mfa.verify(challenge.userId, { otp, recoveryCode });
        if (!result.ok) {
            await this.failLogin({
                usernameHash: challenge.uh, ip, userId: challenge.userId,
                rule: result.replay ? 'MFA_CODE_REPLAY' : 'BAD_MFA_CODE', reason: 'bad_mfa'
            });
            throw new AuthError('INVALID_OTP', 'Código incorrecto');
        }

        if (result.method === 'recovery') {
            await events.record({ type: 'MFA_RECOVERY_CODE_USED', severity: 'medium', riskScore: 40, ip, userId: challenge.userId, usernameHash: challenge.uh });
        }

        const user = { id: challenge.userId, username: challenge.username };
        return this.completeLogin({ user, usernameHash: challenge.uh, deviceInfo, amr: ['pwd', result.method === 'recovery' ? 'recovery' : 'otp'] });
    }

    signMfaChallenge(user, usernameHash) {
        return jwt.sign(
            { typ: 'mfa', userId: user.id, username: user.username, uh: usernameHash, jti: crypto.randomUUID() },
            credentialBuilder.generateJWTSecret(),
            { algorithm: 'HS256', expiresIn: MFA_CHALLENGE_SECONDS }
        );
    }

    async assertNotLocked(usernameHash, ip) {
        const lock = await this.getLockState(usernameHash, ip);
        if (!lock.locked) return;

        await events.record({
            type: 'LOGIN_BLOCKED', rule: 'ACCOUNT_LOCKED', severity: 'medium', riskScore: 50,
            action: 'locked_account', ip, usernameHash, details: { retryAfter: lock.retryAfter, scope: lock.scope }
        });
        throw new AuthError('ACCOUNT_LOCKED', 'Cuenta temporalmente bloqueada por múltiples intentos fallidos', {
            status: 429, retryAfter: lock.retryAfter
        });
    }

    async failLogin({ usernameHash, ip, userId = null, rule, reason }) {
        await this.recordAttempt({ usernameHash, ip, userId, success: false, reason });
        await events.record({
            type: 'LOGIN_FAILED', rule, severity: 'medium', riskScore: 40, ip, userId, usernameHash, status: 401
        });
        await this.checkIpFailures(ip);
    }

    // Crea la sesión y los tokens. `amr` dice CÓMO se autenticó (pwd, otp, recovery, sso): el middleware de
    // roles puede exigir otp para administradores.
    async completeLogin({ user, usernameHash, deviceInfo, amr }) {
        const ip = deviceInfo.ipAddress;
        const deviceFingerprint = this.generateDeviceFingerprint(deviceInfo);
        const risk = await this.calculateRiskLevel(user, deviceInfo, deviceFingerprint, usernameHash);

        const sessionData = {
            userId: user.id,
            username: user.username,
            deviceFingerprint,
            ipAddress: ip,
            userAgent: deviceInfo.userAgent,
            riskLevel: risk.level,
            amr,
            sessionUid: crypto.randomUUID(),
            createdAt: Date.now()
        };

        const { refreshToken } = await this.createSecureSession(sessionData);
        const token = await this.generateSecureToken(sessionData);
        await this.recordAttempt({ usernameHash, ip, userId: user.id, success: true });

        return {
            success: true,
            userId: user.id,
            amr,
            riskLevel: risk.level,
            requiresVerification: false,
            ...this.tokenResponse({ token, refreshToken })
        };
    }

    // Lo que el cliente necesita saber de los tokens (login y refresh devuelven lo mismo)
    tokenResponse({ token, refreshToken, absoluteExpiresAt = null }) {
        const cfg = this.sessionConfig;
        const now = Date.now();
        const absolute = absoluteExpiresAt ? new Date(absoluteExpiresAt) : new Date(now + cfg.absoluteSeconds * 1000);
        return {
            token,
            refreshToken,
            expiresIn: cfg.accessSeconds,
            expiresAt: new Date(now + cfg.accessSeconds * 1000),
            refreshExpiresAt: new Date(Math.min(now + cfg.idleSeconds * 1000, absolute.getTime())),
            sessionExpiresAt: absolute
        };
    }

    async validateCredentials(username, password) {
        const db = require('../config/database');
        const tripleEncryptor = require('../crypto/tripleEncryptor');

        const usernameHash = this.generateUsernameHash(username);
        const [users] = await db.query(
            'SELECT id, username_encrypted, password_hash, mfa_enabled FROM users WHERE username_hash = ?',
            [usernameHash]
        );

        const user = users[0];
        // Con o sin usuario se ejecuta bcrypt una vez: el tiempo de respuesta no delata si existe
        const passwordOk = await bcrypt.compare(String(password), user ? user.password_hash : DUMMY_HASH);
        if (!user || !passwordOk) return null;

        return { id: user.id, username: tripleEncryptor.decrypt(user.username_encrypted), mfaEnabled: Boolean(user.mfa_enabled) };
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
    //
    // Dos niveles, pensados para que NO se pueda usar contra el dueño de la cuenta:
    //
    //  1. Por (usuario, ORIGEN): `maxFailures` fallos desde una misma IP (o /64) bloquean ESA combinación.
    //     Quien ataca desde una IP solo consigue bloquearse a sí mismo; el dueño, desde su sitio, entra.
    //  2. Global por usuario: `globalMaxFailures` fallos sumando todos los orígenes (ataque distribuido
    //     contra una cuenta) bloquean a los orígenes que el usuario NO ha usado antes. Un origen de
    //     confianza (login correcto desde él en los últimos `trustedDays` días) no se ve afectado.
    //
    // Solo cuentan los fallos posteriores al último login correcto de esa misma combinación (nivel 1) o
    // del usuario (nivel 2), dentro de la ventana. Mientras algo está bloqueado NO se registran más
    // intentos (si no, el bloqueo se prolongaría indefinidamente). Un administrador puede liberarlo
    // (POST /api/system/accounts/unlock).
    async getLockState(usernameHash, ip) {
        const db = require('../config/database');
        const { maxFailures, globalMaxFailures, windowSec, trustedDays } = this.lockout;
        const subject = ipSubject(ip);

        // Nivel 1: este usuario desde este origen
        const [source] = await db.query(
            `SELECT COUNT(*) AS failures
             FROM login_attempts
             WHERE username_hash = ? AND ip_subject = ? AND success = 0
               AND created_at > DATE_SUB(NOW(3), INTERVAL ? SECOND)
               AND id > COALESCE((SELECT MAX(id) FROM login_attempts WHERE username_hash = ? AND ip_subject = ? AND success = 1), 0)`,
            [usernameHash, subject, windowSec, usernameHash, subject]
        );
        if (Number(source[0].failures) >= maxFailures) {
            const [oldest] = await db.query(
                `SELECT TIMESTAMPDIFF(SECOND, created_at, NOW(3)) AS age
                 FROM login_attempts
                 WHERE username_hash = ? AND ip_subject = ? AND success = 0
                   AND created_at > DATE_SUB(NOW(3), INTERVAL ? SECOND)
                   AND id > COALESCE((SELECT MAX(id) FROM login_attempts WHERE username_hash = ? AND ip_subject = ? AND success = 1), 0)
                 ORDER BY id DESC
                 LIMIT 1 OFFSET ${sqlInt(maxFailures - 1)}`,
                [usernameHash, subject, windowSec, usernameHash, subject]
            );
            return { locked: true, scope: 'source', retryAfter: Math.max(1, windowSec - (Number(oldest[0]?.age) || 0)) };
        }

        // Nivel 2: este usuario desde cualquier origen (ataque distribuido)
        const [global] = await db.query(
            `SELECT COUNT(*) AS failures
             FROM login_attempts
             WHERE username_hash = ? AND success = 0
               AND created_at > DATE_SUB(NOW(3), INTERVAL ? SECOND)
               AND id > COALESCE((SELECT MAX(id) FROM login_attempts WHERE username_hash = ? AND success = 1), 0)`,
            [usernameHash, windowSec, usernameHash]
        );
        if (Number(global[0].failures) < globalMaxFailures) return { locked: false };

        const [trusted] = await db.query(
            `SELECT 1 AS trusted FROM login_attempts
             WHERE username_hash = ? AND ip_subject = ? AND success = 1
               AND (reason IS NULL OR reason <> 'admin_unlock')
               AND created_at > DATE_SUB(NOW(3), INTERVAL ? DAY)
             LIMIT 1`,
            [usernameHash, subject, trustedDays]
        );
        if (trusted.length > 0) return { locked: false, trustedSource: true };

        const [oldestGlobal] = await db.query(
            `SELECT TIMESTAMPDIFF(SECOND, created_at, NOW(3)) AS age
             FROM login_attempts
             WHERE username_hash = ? AND success = 0
               AND created_at > DATE_SUB(NOW(3), INTERVAL ? SECOND)
               AND id > COALESCE((SELECT MAX(id) FROM login_attempts WHERE username_hash = ? AND success = 1), 0)
             ORDER BY id DESC
             LIMIT 1 OFFSET ${sqlInt(globalMaxFailures - 1)}`,
            [usernameHash, windowSec, usernameHash]
        );
        return { locked: true, scope: 'global', retryAfter: Math.max(1, windowSec - (Number(oldestGlobal[0]?.age) || 0)) };
    }

    async isAccountLocked(username, ip) {
        return (await this.getLockState(this.generateUsernameHash(username), ip)).locked;
    }

    async recordAttempt({ usernameHash, ip, userId = null, success, reason = null }) {
        const db = require('../config/database');
        try {
            await db.query(
                'INSERT INTO login_attempts (username_hash, ip_address, ip_subject, user_id, success, reason) VALUES (?, ?, ?, ?, ?, ?)',
                [usernameHash, String(ip || 'unknown').slice(0, 45), ipSubject(ip), userId, success ? 1 : 0, reason]
            );
        } catch (error) {
            console.error('❌ Error registrando intento de login:', error.code || error.message);
        }
    }

    // Libera una cuenta (la usa un administrador). Inserta marcas administrativas que reinician el contador
    // global y el de CADA origen con fallos recientes, sin borrar el historial (sigue disponible para el
    // análisis). Estas marcas NO convierten a nadie en "origen de confianza" (ver getLockState).
    async unlockAccount(username, { adminId } = {}) {
        const db = require('../config/database');
        const usernameHash = this.generateUsernameHash(username);
        const { windowSec } = this.lockout;

        await db.query(
            `INSERT INTO login_attempts (username_hash, ip_address, ip_subject, user_id, success, reason)
             SELECT DISTINCT username_hash, 'admin', ip_subject, NULL, 1, 'admin_unlock'
             FROM login_attempts
             WHERE username_hash = ? AND success = 0 AND created_at > DATE_SUB(NOW(3), INTERVAL ? SECOND)`,
            [usernameHash, windowSec]
        );
        await this.recordAttempt({ usernameHash, ip: 'admin', userId: adminId ?? null, success: true, reason: 'admin_unlock' });
        return usernameHash;
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

    // JWT de acceso: corto, y ligado a su sesión (sessionId = session_uid de la fila). `v: 2` lo distingue de los
    // tokens largos anteriores, que se siguen aceptando hasta que caduquen (se buscan por su hash).
    async generateSecureToken(sessionData) {
        const payload = {
            userId: sessionData.userId,
            username: sessionData.username,
            sessionId: sessionData.sessionUid,
            riskLevel: sessionData.riskLevel,
            amr: sessionData.amr || ['pwd'],
            v: 2
        };

        return jwt.sign(payload, credentialBuilder.generateJWTSecret(), {
            algorithm: 'HS256',
            expiresIn: this.sessionConfig.accessSeconds
        });
    }

    newRefreshToken() {
        return `rt_${crypto.randomBytes(32).toString('base64url')}`; // 256 bits: no se puede adivinar
    }

    async createSecureSession(sessionData) {
        const db = require('../config/database');
        const geo = geoip.lookup(sessionData.ipAddress);
        const cfg = this.sessionConfig;
        const refreshToken = this.newRefreshToken();

        await db.query(
            `INSERT INTO user_sessions
                (user_id, jwt_token_hash, session_uid, refresh_hash, ip_address, user_agent, device_fingerprint, risk_level,
                 location_country, amr, expires_at, absolute_expires_at, last_used_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, DATE_ADD(NOW(), INTERVAL ? SECOND), DATE_ADD(NOW(), INTERVAL ? SECOND), NOW())`,
            [
                sessionData.userId,
                this.hashToken(sessionData.sessionUid),   // la columna es NOT NULL: ya no hay un token largo que hashear
                sessionData.sessionUid,
                this.hashToken(refreshToken),
                String(sessionData.ipAddress || '').slice(0, 45),
                String(sessionData.userAgent || 'Unknown').slice(0, 500),
                sessionData.deviceFingerprint,
                sessionData.riskLevel,
                geo ? geo.country : null,
                (sessionData.amr || ['pwd']).join(',').slice(0, 60),
                cfg.idleSeconds,
                cfg.absoluteSeconds
            ]
        );
        return { refreshToken };
    }

    // Condición de sesión viva, siempre la misma: no revocada, no caducada por inactividad ni por el tope absoluto
    static get LIVE_SESSION() {
        return 'revoked_at IS NULL AND expires_at > NOW() AND (absolute_expires_at IS NULL OR absolute_expires_at > NOW())';
    }

    async validateToken(token) {
        try {
            // Algoritmo fijado: un token firmado con otro algoritmo (o "none") se rechaza
            const decoded = jwt.verify(token, credentialBuilder.generateJWTSecret(), { algorithms: ['HS256'] });
            if (decoded.typ) throw new Error('Token no válido como sesión'); // los retos de MFA no son sesiones

            const db = require('../config/database');
            const live = SecureAuthService.LIVE_SESSION;
            const [sessions] = decoded.v === 2
                ? await db.query(`SELECT id, user_id, risk_level, is_suspicious, last_used_at < DATE_SUB(NOW(), INTERVAL 60 SECOND) AS stale
                                  FROM user_sessions WHERE session_uid = ? AND ${live}`, [String(decoded.sessionId)])
                : await db.query(`SELECT id, user_id, risk_level, is_suspicious, 0 AS stale
                                  FROM user_sessions WHERE jwt_token_hash = ? AND ${live}`, [this.hashToken(token)]);

            const session = sessions[0];
            // La sesión debe existir Y pertenecer al usuario que dice el token
            if (!session || Number(session.user_id) !== Number(decoded.userId)) throw new Error('Sesión inválida o expirada');
            if (session.is_suspicious) throw new Error('Sesión marcada como sospechosa');

            // "Visto por última vez": como mucho una escritura por minuto y sesión
            if (session.stale) {
                db.query('UPDATE user_sessions SET last_used_at = NOW() WHERE id = ?', [session.id]).catch(() => {});
            }

            return {
                valid: true,
                userId: decoded.userId,
                username: decoded.username,
                sessionId: session.id,
                riskLevel: session.risk_level,
                amr: Array.isArray(decoded.amr) ? decoded.amr : ['pwd']
            };
        } catch (error) {
            // Mensaje genérico: no se distingue firma inválida de caducada
            const known = ['Sesión inválida o expirada', 'Sesión marcada como sospechosa'];
            return { valid: false, error: known.includes(error.message) ? error.message : 'Token inválido o expirado' };
        }
    }

    // ------------------------------------------------------------------ renovación (refresh)
    //
    // El refresh token rota en cada uso: el anterior queda en prev_refresh_hash. Si alguien presenta un refresh YA
    // usado fuera de la gracia, o lo robaron o hay un cliente roto: en ambos casos se revoca la sesión entera
    // (quien tenga el token nuevo tampoco sigue). Dentro de la gracia es una carrera entre dos pestañas: 409.
    async refreshSession(refreshToken, deviceInfo = {}) {
        const db = require('../config/database');
        const cfg = this.sessionConfig;
        const hash = this.hashToken(String(refreshToken));
        const invalid = () => new AuthError('INVALID_REFRESH_TOKEN', 'Refresh token no válido o caducado: inicia sesión de nuevo');

        const [rows] = await db.query(
            `SELECT id, user_id, session_uid, risk_level, amr, ip_address, is_suspicious, absolute_expires_at,
                    (${SecureAuthService.LIVE_SESSION}) AS live
             FROM user_sessions WHERE refresh_hash = ?`,
            [hash]
        );
        const session = rows[0];
        if (!session) return this.rejectUnknownRefresh(hash, deviceInfo);
        if (!session.live || session.is_suspicious) throw invalid();

        const [users] = await db.query('SELECT id, username_encrypted FROM users WHERE id = ?', [session.user_id]);
        if (!users[0]) throw invalid();
        const tripleEncryptor = require('../crypto/tripleEncryptor');
        const username = tripleEncryptor.decrypt(users[0].username_encrypted);

        // Rotación ATÓMICA: si dos peticiones llegan con el mismo token, solo una cambia la fila
        const next = this.newRefreshToken();
        const [updated] = await db.query(
            `UPDATE user_sessions
                SET prev_refresh_hash = refresh_hash, refresh_hash = ?, refreshed_at = NOW(), last_used_at = NOW(),
                    expires_at = LEAST(DATE_ADD(NOW(), INTERVAL ? SECOND), COALESCE(absolute_expires_at, DATE_ADD(NOW(), INTERVAL ? SECOND)))
              WHERE id = ? AND refresh_hash = ? AND revoked_at IS NULL`,
            [this.hashToken(next), cfg.idleSeconds, cfg.idleSeconds, session.id, hash]
        );
        if (updated.affectedRows !== 1) {
            throw new AuthError('REFRESH_CONFLICT', 'Otra petición acaba de renovar esta sesión: usa el refresh token más reciente', { status: 409 });
        }

        // Renovar desde otra red no se bloquea (los móviles cambian de red), pero queda registrado
        if (deviceInfo.ipAddress && session.ip_address && ipSubject(deviceInfo.ipAddress) !== ipSubject(session.ip_address)) {
            await events.record({
                type: 'SESSION_REFRESH_NEW_ORIGIN', severity: 'low', riskScore: 15, ip: deviceInfo.ipAddress, userId: session.user_id,
                details: { sessionId: session.id }
            });
        }

        const amr = session.amr ? session.amr.split(',') : ['pwd'];
        const token = await this.generateSecureToken({
            userId: session.user_id, username, sessionUid: session.session_uid, riskLevel: session.risk_level, amr
        });

        return {
            success: true, userId: session.user_id, amr, riskLevel: session.risk_level,
            ...this.tokenResponse({ token, refreshToken: next, absoluteExpiresAt: session.absolute_expires_at })
        };
    }

    async rejectUnknownRefresh(hash, deviceInfo) {
        const db = require('../config/database');
        const cfg = this.sessionConfig;
        const [rows] = await db.query(
            `SELECT id, user_id, TIMESTAMPDIFF(SECOND, refreshed_at, NOW()) AS age, (${SecureAuthService.LIVE_SESSION}) AS live
             FROM user_sessions WHERE prev_refresh_hash = ?`,
            [hash]
        );
        const old = rows[0];

        if (old && old.live) {
            if (Number(old.age) <= cfg.reuseGraceSeconds) {
                throw new AuthError('REFRESH_CONFLICT', 'Otra petición acaba de renovar esta sesión: usa el refresh token más reciente', { status: 409 });
            }
            await this.revokeSession(old.user_id, old.id, 'refresh_reuse');
            await events.record({
                type: 'REFRESH_TOKEN_REUSE', rule: 'REFRESH_REUSE', severity: 'critical', riskScore: 90, action: 'session_revoked',
                ip: deviceInfo.ipAddress, userId: old.user_id, details: { sessionId: old.id }
            });
        }
        throw new AuthError('INVALID_REFRESH_TOKEN', 'Refresh token no válido o caducado: inicia sesión de nuevo');
    }

    // ------------------------------------------------------------------ cerrar sesiones

    async revokeSession(userId, sessionId, reason = 'user_logout') {
        const db = require('../config/database');
        const [result] = await db.query(
            `UPDATE user_sessions SET expires_at = NOW(), revoked_at = NOW(), revoked_reason = ?
             WHERE id = ? AND user_id = ? AND ${SecureAuthService.LIVE_SESSION}`,
            [reason, sqlInt(sessionId, { min: 1, max: 2 ** 31 - 1 }), userId]
        );
        return result.affectedRows;
    }

    // Todas las sesiones del usuario (opcionalmente menos la actual). Devuelve cuántas cerró.
    async revokeAllSessions(userId, { exceptSessionId = null, reason = 'user_logout_all' } = {}) {
        const db = require('../config/database');
        const except = exceptSessionId == null ? null : Number(exceptSessionId);
        const [result] = await db.query(
            `UPDATE user_sessions SET expires_at = NOW(), revoked_at = NOW(), revoked_reason = ?
             WHERE user_id = ? AND ${SecureAuthService.LIVE_SESSION} AND (? IS NULL OR id <> ?)`,
            [reason, userId, except, except]
        );
        return result.affectedRows;
    }

    async listSessions(userId, currentSessionId = null) {
        const db = require('../config/database');
        const [rows] = await db.query(
            `SELECT id, ip_address, user_agent, location_country, risk_level, amr, created_at, last_used_at, expires_at, absolute_expires_at
             FROM user_sessions WHERE user_id = ? AND ${SecureAuthService.LIVE_SESSION} ORDER BY id DESC LIMIT 100`,
            [userId]
        );
        return rows.map(row => ({
            id: row.id,
            current: Number(row.id) === Number(currentSessionId),
            ipAddress: row.ip_address,
            userAgent: row.user_agent,
            country: row.location_country,
            riskLevel: row.risk_level,
            authMethods: row.amr ? row.amr.split(',') : ['pwd'],
            createdAt: row.created_at,
            lastUsedAt: row.last_used_at,
            expiresAt: row.expires_at,
            sessionExpiresAt: row.absolute_expires_at
        }));
    }

    // Tareas de mantenimiento (las lanza el servicio de limpieza)
    async purgeOldData() {
        const db = require('../config/database');
        const [sessions] = await db.query('DELETE FROM user_sessions WHERE expires_at < DATE_SUB(NOW(), INTERVAL 1 DAY) LIMIT 5000');
        const [attempts] = await db.query('DELETE FROM login_attempts WHERE created_at < DATE_SUB(NOW(), INTERVAL 90 DAY) LIMIT 5000');
        return { sessions: sessions.affectedRows, loginAttempts: attempts.affectedRows };
    }
}

module.exports = new SecureAuthService();
module.exports.AuthError = AuthError;
