// Gestión de usuarios por administradores: crear cuentas, listarlas, cambiar roles y cambiar la propia contraseña.
//
//  - Las cuentas se guardan EXACTAMENTE como el registro (username_hash + username_encrypted, bcrypt coste 12, cifrado v4).
//  - Dar el rol `admin` nunca es directo: se crea/queda como `user` y se abre una aprobación `user_set_role` que otro
//    administrador aprueba (admin-actions.js). Ninguna contraseña viaja en los `params` de una aprobación.
//  - Una cuenta creada por un administrador nace con must_change_password = 1: el usuario solo puede cambiarla.

const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const db = require('../config/database');
const tripleEncryptor = require('../crypto/tripleEncryptor');
const { sqlFragment } = require('../config/sql');
const permissions = require('./permissions');
const events = require('./security-events.service');
const secureAuth = require('./secure-auth.service');

const ENCRYPTION_VERSION = 'v4.0.0';
const BCRYPT_COST = 12;

class UserAdminError extends Error {
    constructor(code, message, status = 400) {
        super(message);
        this.code = code;
        this.status = status;
    }
}

// Política de contraseñas: la MISMA que el registro (auth.routes.js: 10–128 caracteres) y el límite de bcrypt (72 bytes).
const PASSWORD_MIN = 10;
const PASSWORD_MAX = 128;

function passwordPolicyError(password) {
    if (typeof password !== 'string' || password.length < PASSWORD_MIN) return `La contraseña debe tener al menos ${PASSWORD_MIN} caracteres`;
    if (password.length > PASSWORD_MAX) return `La contraseña no puede superar ${PASSWORD_MAX} caracteres`;
    // bcrypt solo mira los primeros 72 BYTES: más allá se ignoraría en silencio
    if (Buffer.byteLength(password, 'utf8') > 72) return 'La contraseña no puede superar 72 bytes';
    return null;
}

// Contraseña temporal: 24 caracteres sin ambiguos (0/O, 1/l/I), con mayúscula, minúscula, dígito y símbolo.
function generateTemporaryPassword(length = 24) {
    const sets = ['ABCDEFGHJKLMNPQRSTUVWXYZ', 'abcdefghijkmnopqrstuvwxyz', '23456789', '-_.!#$%*+='];
    const all = sets.join('');
    const chars = sets.map(set => set[crypto.randomInt(set.length)]);
    while (chars.length < length) chars.push(all[crypto.randomInt(all.length)]);
    for (let i = chars.length - 1; i > 0; i--) { // Fisher-Yates con crypto
        const j = crypto.randomInt(i + 1);
        [chars[i], chars[j]] = [chars[j], chars[i]];
    }
    return chars.join('');
}

async function createUser({ username, role, password, createdBy }) {
    if (!permissions.isKnownRole(role)) throw new UserAdminError('VALIDATION_ERROR', 'Rol desconocido');
    const temporary = password == null || password === '';
    const plain = temporary ? generateTemporaryPassword() : password;
    const policy = passwordPolicyError(plain);
    if (policy) throw new UserAdminError('VALIDATION_ERROR', policy);

    const usernameHash = secureAuth.generateUsernameHash(username);
    const [existing] = await db.query('SELECT id FROM users WHERE username_hash = ?', [usernameHash]);
    if (existing.length > 0) throw new UserAdminError('USER_EXISTS', 'El usuario ya existe', 409);

    const passwordHash = await bcrypt.hash(plain, BCRYPT_COST);
    // Con "admin" la cuenta nace como "user": el rol admin solo llega por la aprobación de otro administrador
    const initialRole = role === 'admin' ? 'user' : role;
    const metadata = tripleEncryptor.encrypt(JSON.stringify({
        originalUsername: username, createdByAdmin: createdBy, registrationTimestamp: new Date().toISOString()
    }));

    let result;
    try {
        [result] = await db.query(
            `INSERT INTO users (
                username_encrypted, username_hash, password_hash, risk_level_encrypted, encrypted_metadata, encryption_version,
                role, must_change_password, created_by, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, NOW(), NOW())`,
            [tripleEncryptor.encrypt(username), usernameHash, passwordHash, tripleEncryptor.encrypt('low'), metadata,
                ENCRYPTION_VERSION, initialRole, createdBy]
        );
    } catch (error) {
        if (error.code === 'ER_DUP_ENTRY') throw new UserAdminError('USER_EXISTS', 'El usuario ya existe', 409);
        throw error;
    }
    return { id: result.insertId, username, role: initialRole, requestedRole: role, temporaryPassword: temporary ? plain : null };
}

// Lista paginada por cursor (before = último id visto). La búsqueda es exacta: solo hay hash del nombre.
async function listUsers({ q = null, role = null, limit = 50, before = null } = {}) {
    const where = [];
    const params = [];
    if (q) { where.push('u.username_hash = ?'); params.push(secureAuth.generateUsernameHash(q)); }
    if (role) { where.push('u.role = ?'); params.push(role); }
    if (before) { where.push('u.id < ?'); params.push(before); }
    const max = Math.min(Math.max(Number(limit) || 50, 1), 200);

    const [rows] = await db.query(
        `SELECT u.id, u.username_encrypted, u.role, u.mfa_enabled, u.created_at, u.must_change_password, u.created_by,
                (SELECT COUNT(*) FROM user_sessions WHERE user_id = u.id AND ${sqlFragment('liveSession')}) AS active_sessions
         FROM users u ${where.length ? `WHERE ${where.join(' AND ')}` : ''}
         ORDER BY u.id DESC LIMIT ?`,
        [...params, max + 1]
    );
    const page = rows.slice(0, max);
    const users = page.map(row => {
        let username = null;
        try { username = tripleEncryptor.decrypt(row.username_encrypted); } catch { /* dato ilegible: se muestra vacío */ }
        return {
            id: row.id,
            username,
            role: row.role,
            mfaEnabled: Boolean(row.mfa_enabled),
            createdAt: row.created_at,
            mustChangePassword: Boolean(row.must_change_password),
            createdBy: row.created_by,
            activeSessions: Number(row.active_sessions)
        };
    });
    return { users, nextBefore: rows.length > max ? page[page.length - 1].id : null };
}

// Cambia el rol y cierra TODAS las sesiones del usuario. En una transacción con las filas bloqueadas (FOR UPDATE): dos
// degradaciones simultáneas de admins distintos se serializan y no pueden dejar el sistema sin ningún administrador.
async function applyRole(userId, role, { actor = null, approvedBy = null, source = 'direct' } = {}) {
    if (!permissions.isKnownRole(role)) throw new UserAdminError('VALIDATION_ERROR', 'Rol desconocido');
    const previous = await db.transaction(async (tx) => {
        const [rows] = await tx.query('SELECT id, role, must_change_password FROM users WHERE id = ? FOR UPDATE', [userId]);
        if (!rows[0]) throw new UserAdminError('NOT_FOUND', 'Usuario no encontrado', 404);
        const from = rows[0].role;
        if (from === role) throw new UserAdminError('ROLE_UNCHANGED', `El usuario ya tiene el rol ${role}`, 409);
        // Defensa en profundidad (también con ADMIN_APPROVALS_REQUIRED=1): nunca admin con la contraseña temporal
        if (role === 'admin' && Number(rows[0].must_change_password) === 1) {
            throw new UserAdminError('TARGET_NOT_READY', 'El usuario aún tiene la contraseña temporal: dale el rol admin cuando la haya cambiado', 409);
        }
        if (from === 'admin') {
            const [admins] = await tx.query("SELECT id FROM users WHERE role = 'admin' FOR UPDATE");
            if (admins.length <= 1) throw new UserAdminError('LAST_ADMIN', 'No se puede dejar el sistema sin ningún administrador', 409);
        }
        await tx.query('UPDATE users SET role = ?, updated_at = NOW() WHERE id = ?', [role, userId]);
        return from;
    });
    const sessionsClosed = await secureAuth.revokeAllSessions(userId, { reason: 'role_changed' });
    await events.record({
        type: 'USER_ROLE_CHANGED', severity: 'high', riskScore: 40, userId,
        details: { from: previous, to: role, actor, approvedBy, source, sessionsClosed }
    });
    return { from: previous, to: role, sessionsClosed };
}

async function changePassword(userId, { currentSessionId, currentPassword, newPassword }) {
    const mfa = require('./mfa.service');
    if (!(await mfa.passwordMatches(userId, currentPassword))) {
        throw new UserAdminError('INVALID_CREDENTIALS', 'La contraseña actual no es correcta', 401);
    }
    const policy = passwordPolicyError(newPassword);
    if (policy) throw new UserAdminError('VALIDATION_ERROR', policy);
    if (newPassword === currentPassword) {
        throw new UserAdminError('SAME_PASSWORD', 'La contraseña nueva debe ser distinta de la actual', 400);
    }

    const hash = await bcrypt.hash(newPassword, BCRYPT_COST);
    await db.query('UPDATE users SET password_hash = ?, must_change_password = 0, updated_at = NOW() WHERE id = ?', [hash, userId]);
    // Las DEMÁS sesiones se cierran (si alguien tenía la contraseña vieja, se queda fuera); la actual sigue
    const sessionsClosed = await secureAuth.revokeAllSessions(userId, { exceptSessionId: currentSessionId, reason: 'password_changed' });
    await events.record({ type: 'PASSWORD_CHANGED', severity: 'medium', riskScore: 10, userId, details: { sessionsClosed } });
    return { sessionsClosed };
}

module.exports = {
    UserAdminError, passwordPolicyError, generateTemporaryPassword, createUser, listUsers, applyRole, changePassword,
    PASSWORD_MIN, PASSWORD_MAX
};
