const db = require('../config/database');
const tripleEncryptor = require('../crypto/tripleEncryptor');
const storage = require('../files/storage');
const events = require('./security-events.service');

// Datos personales (SOLO admin): exportar todo lo que el sistema guarda de un usuario y borrarlo.
//
//  EXPORTAR   Devuelve, descifrado, el perfil, las notas, los archivos (metadatos), las sesiones, las identidades SSO y los
//             eventos de seguridad del usuario. No incluye hashes de contraseña, secretos MFA, códigos de recuperación ni
//             claves de archivos, y el contenido de los archivos no se vuelca (se descarga por su propia API).
//  BORRAR     Elimina cuenta, notas, archivos (de la BD y del disco), sesiones, MFA, identidades y dispositivos. Los eventos
//             de seguridad y los intentos de login NO se borran (sirven para investigar ataques) pero se ANONIMIZAN: sin
//             user_id ni hash de usuario. Es irreversible, por eso va con la aprobación de un segundo administrador.
//
// Límite honesto: las copias de seguridad de la base de datos y de FILES_DIR que ya existan siguen conteniendo esos datos
// hasta que caduquen según su retención. Hay que decírselo al usuario; ver docs/RESPUESTA-INCIDENTES.md.

class PrivacyError extends Error {
    constructor(code, message, status) { super(message); this.code = code; this.status = status; }
}

const decrypt = (value) => { try { return value == null ? null : tripleEncryptor.decrypt(value); } catch { return null; } };
const decryptJson = (value) => { try { return JSON.parse(decrypt(value)); } catch { return null; } };

async function findUser(userId) {
    const [rows] = await db.query(
        `SELECT id, username_encrypted, username_hash, email_encrypted, role, risk_level_encrypted, encrypted_metadata, mfa_enabled,
                device_fingerprint, created_at, updated_at FROM users WHERE id = ?`, [userId]);
    return rows[0] || null;
}

async function exportUser(userId) {
    const user = await findUser(userId);
    if (!user) throw new PrivacyError('NOT_FOUND', 'Usuario no encontrado', 404);

    const [notes] = await db.query('SELECT id, title_encrypted, content_encrypted, created_at, updated_at FROM user_notes WHERE user_id = ? ORDER BY id LIMIT 10000', [userId]);
    const [files] = await db.query('SELECT id, filename_encrypted, mime_type, category, size_bytes, sha256, scan_status, sanitize_status, created_at FROM user_files WHERE user_id = ? ORDER BY id LIMIT 10000', [userId]);
    const [sessions] = await db.query('SELECT id, ip_address, user_agent, location_country, risk_level, created_at, last_used_at, expires_at, revoked_at, revoked_reason FROM user_sessions WHERE user_id = ? ORDER BY id DESC LIMIT 500', [userId]);
    const [identities] = await db.query('SELECT issuer, created_at, last_login_at FROM user_identities WHERE user_id = ?', [userId]);
    const [devices] = await db.query('SELECT device_name, is_trusted, created_at, last_seen FROM known_devices WHERE user_id = ?', [userId]);
    const [recovery] = await db.query('SELECT COUNT(*) AS n FROM user_recovery_codes WHERE user_id = ? AND used_at IS NULL', [userId]).catch(() => [[{ n: null }]]);
    const [securityEvents] = await db.query(
        `SELECT created_at, event_type, rule, severity, action_taken, ip_address, method, path, status_code, user_agent, country
         FROM security_events WHERE user_id = ? ORDER BY id DESC LIMIT 5000`, [userId]);
    const [attempts] = await db.query('SELECT created_at, success, reason, ip_address FROM login_attempts WHERE user_id = ? OR username_hash = ? ORDER BY id DESC LIMIT 2000', [userId, user.username_hash]).catch(() => [[]]);

    await events.record({ type: 'PRIVACY_EXPORT', severity: 'medium', riskScore: 30, userId, details: { notes: notes.length, files: files.length } });

    return {
        exportedAt: new Date().toISOString(),
        user: {
            id: user.id,
            username: decrypt(user.username_encrypted),
            email: decrypt(user.email_encrypted),
            role: user.role,
            riskLevel: decrypt(user.risk_level_encrypted),
            metadata: decryptJson(user.encrypted_metadata),
            mfaEnabled: Boolean(user.mfa_enabled),
            recoveryCodesRemaining: recovery[0]?.n == null ? null : Number(recovery[0].n),
            deviceFingerprint: user.device_fingerprint,
            createdAt: user.created_at,
            updatedAt: user.updated_at
        },
        notes: notes.map(n => ({ id: n.id, title: decrypt(n.title_encrypted), content: decrypt(n.content_encrypted), createdAt: n.created_at, updatedAt: n.updated_at })),
        files: files.map(f => ({ id: Number(f.id), name: decrypt(f.filename_encrypted), mimeType: f.mime_type, category: f.category, size: Number(f.size_bytes), sha256: f.sha256, scanStatus: f.scan_status, sanitizeStatus: f.sanitize_status, createdAt: f.created_at })),
        sessions, identities, devices,
        securityEvents,
        loginAttempts: attempts
    };
}

// Elimina todo lo del usuario. Orden: primero BD (en una transacción; las claves ajenas borran en cascada notas, archivos,
// sesiones, MFA, identidades y dispositivos), después los bytes del disco.
async function eraseUser(userId) {
    const user = await findUser(userId);
    if (!user) throw new PrivacyError('NOT_FOUND', 'Usuario no encontrado', 404);
    if (user.role !== 'user') {
        throw new PrivacyError('ROLE_PROTECTED', 'No se borra una cuenta con privilegios: quítale antes el rol con `npm run set-role`', 409);
    }

    const [files] = await db.query('SELECT storage_name FROM user_files WHERE user_id = ?', [userId]);

    const counts = await db.transaction(async (tx) => {
        const [notes] = await tx.query('SELECT COUNT(*) AS n FROM user_notes WHERE user_id = ?', [userId]);
        const [anonEvents] = await tx.query('UPDATE security_events SET user_id = NULL, username_hash = NULL WHERE user_id = ? OR username_hash = ?', [userId, user.username_hash]);
        const [anonAttempts] = await tx.query('UPDATE login_attempts SET user_id = NULL, username_hash = REPEAT(\'0\', 64) WHERE user_id = ? OR username_hash = ?', [userId, user.username_hash]);
        await tx.query('DELETE FROM users WHERE id = ?', [userId]);
        return { notes: Number(notes[0].n), eventsAnonymized: anonEvents.affectedRows, attemptsAnonymized: anonAttempts.affectedRows };
    });

    // Los bytes cifrados del disco: si alguno no se puede borrar se informa (la fila ya no existe, queda huérfano)
    let removed = 0; const failed = [];
    for (const { storage_name: name } of files) {
        try { await storage.removeFinal(name); removed++; } catch { failed.push(name); }
    }

    await events.record({ type: 'USER_ERASED', severity: 'high', riskScore: 40, details: { erasedUserId: userId, files: files.length, ...counts } });
    return { erased: true, notes: counts.notes, files: files.length, filesRemovedFromDisk: removed, filesLeftOnDisk: failed.length, eventsAnonymized: counts.eventsAnonymized, attemptsAnonymized: counts.attemptsAnonymized };
}

module.exports = { exportUser, eraseUser, findUser, PrivacyError };
