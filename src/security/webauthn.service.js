const crypto = require('crypto');
const webauthn = require('@simplewebauthn/server');
const db = require('../config/database');
const events = require('./security-events.service');

// Passkeys / llaves de seguridad (WebAuthn) como SEGUNDO FACTOR, alternativa o complemento del TOTP.
// La verificación criptográfica la hace @simplewebauthn/server; aquí van las reglas del sistema:
//
//  - Retos de un solo uso en BD (webauthn_challenges): caducan a los 5 min, están ligados a un usuario y a un propósito
//    (registrar / iniciar sesión) y se consumen con un DELETE atómico. Un reto robado no vale para otro usuario, ni para
//    el otro propósito, ni dos veces.
//  - Origen y RP ID exactos (WEBAUTHN_ORIGINS, WEBAUTHN_RP_ID): una respuesta firmada para otro sitio no vale (phishing).
//  - Contador de firmas con actualización optimista: una llave clonada (contador que no avanza) se rechaza y deja un
//    evento crítico; dos firmas simultáneas con el mismo contador no pasan las dos.
//  - Solo attestation "none": no se pide ni se guarda información del fabricante.
//  - Registrar o quitar una llave exige contraseña + un segundo factor ya existente (lo comprueba el controlador): una sesión
//    robada no puede añadir su propia llave para quedarse.
//
//  WEBAUTHN_RP_ID            dominio (sin esquema ni puerto), p. ej. "app.ejemplo.com". Sin él, WebAuthn queda desactivado.
//  WEBAUTHN_ORIGINS          orígenes permitidos separados por comas, p. ej. "https://app.ejemplo.com". En producción, https.
//  WEBAUTHN_RP_NAME          nombre que ve el usuario al registrar
//  WEBAUTHN_USER_VERIFICATION required | preferred (por defecto) | discouraged: PIN/huella en la llave

const CHALLENGE_TTL_SECONDS = 5 * 60;
const MAX_CREDENTIALS = 10;

class WebauthnError extends Error {
    constructor(code, message, status = 400) {
        super(message);
        this.code = code;
        this.status = status;
    }
}

function config() {
    const rpId = (process.env.WEBAUTHN_RP_ID || '').trim().toLowerCase();
    const origins = (process.env.WEBAUTHN_ORIGINS || '').split(',').map(o => o.trim()).filter(Boolean);
    if (!rpId || origins.length === 0) return null;

    const production = process.env.NODE_ENV === 'production';
    for (const origin of origins) {
        let url;
        try { url = new URL(origin); } catch { throw new Error(`WEBAUTHN_ORIGINS: "${origin}" no es una URL`); }
        const local = url.hostname === 'localhost' || url.hostname === '127.0.0.1';
        if (url.origin !== origin) throw new Error(`WEBAUTHN_ORIGINS: usa solo el origen (esquema://host[:puerto]), no "${origin}"`);
        if (url.protocol !== 'https:' && !(local && !production)) throw new Error(`WEBAUTHN_ORIGINS: "${origin}" debe ser https://`);
        if (url.hostname !== rpId && !url.hostname.endsWith(`.${rpId}`)) throw new Error(`WEBAUTHN_ORIGINS: "${origin}" no pertenece al RP ID "${rpId}"`);
    }
    const uv = ['required', 'preferred', 'discouraged'].includes(process.env.WEBAUTHN_USER_VERIFICATION) ? process.env.WEBAUTHN_USER_VERIFICATION : 'preferred';
    return { rpId, origins, rpName: process.env.WEBAUTHN_RP_NAME || 'Secure Server', userVerification: uv };
}
const enabled = () => { try { return config() !== null; } catch { return false; } };

function requireConfig() {
    let cfg;
    try { cfg = config(); } catch (error) { console.error('❌ WebAuthn mal configurado:', error.message); throw new WebauthnError('WEBAUTHN_MISCONFIGURED', 'WebAuthn está mal configurado', 503); }
    if (!cfg) throw new WebauthnError('WEBAUTHN_NOT_CONFIGURED', 'WebAuthn no está activado en este servidor', 404);
    return cfg;
}

// Identificador opaco y estable del usuario para el autenticador: NO es un dato personal ni el id de la BD
const userHandle = (userId) => crypto.createHash('sha256').update(`webauthn-user|${userId}|${process.env.BASE_SEED || ''}`).digest();

// Nombre que pone el usuario a su llave: sin controles, caracteres invisibles/bidireccionales ni < >. La clase se construye con
// códigos numéricos en vez de escribir los caracteres en el fuente (un fuente con bidi literales es un ataque de "trojan source").
const NAME_STRIP_RANGES = [[0x00, 0x1f], [0x7f, 0x9f], [0x200b, 0x200f], [0x202a, 0x202e], [0x2066, 0x2069]];
// eslint-disable-next-line security/detect-non-literal-regexp -- se construye SOLO con las constantes de arriba, nunca con entrada del usuario
const NAME_STRIP = new RegExp(`[${NAME_STRIP_RANGES.map(([a, b]) => `${String.fromCodePoint(a)}-${String.fromCodePoint(b)}`).join('')}<>]`, 'g');
const cleanName = (value) => String(value || '').replace(NAME_STRIP, '').trim().slice(0, 60) || 'Llave de seguridad';

// ------------------------------------------------------------------ retos
async function storeChallenge(userId, purpose, challenge) {
    await db.query(
        'INSERT INTO webauthn_challenges (challenge, purpose, user_id, expires_at) VALUES (?, ?, ?, DATE_ADD(NOW(), INTERVAL ? SECOND))',
        [challenge, purpose, userId, CHALLENGE_TTL_SECONDS]
    );
}

// El reto que el navegador firmó viene dentro de clientDataJSON. Se consume ATÓMICAMENTE (uno solo gana) y solo si es de
// este usuario y de este propósito y no ha caducado.
function claimedChallenge(response) {
    try {
        const json = JSON.parse(Buffer.from(String(response?.response?.clientDataJSON), 'base64url').toString('utf8'));
        return typeof json.challenge === 'string' && json.challenge.length <= 128 ? json.challenge : null;
    } catch { return null; }
}
async function consumeChallenge(userId, purpose, response) {
    const challenge = claimedChallenge(response);
    if (!challenge) return null;
    const [result] = await db.query(
        'DELETE FROM webauthn_challenges WHERE challenge = ? AND purpose = ? AND user_id = ? AND expires_at > NOW()',
        [challenge, purpose, userId]
    );
    return result.affectedRows === 1 ? challenge : null;
}

// ------------------------------------------------------------------ credenciales
async function listCredentials(userId) {
    const [rows] = await db.query(
        'SELECT id, credential_id, transports, device_type, backed_up, name, created_at, last_used_at FROM webauthn_credentials WHERE user_id = ? ORDER BY id LIMIT 50', [userId]);
    return rows;
}
const publicCredential = (row) => ({
    id: Number(row.id), name: row.name, deviceType: row.device_type, backedUp: Boolean(row.backed_up),
    transports: row.transports ? row.transports.split(',') : [], createdAt: row.created_at, lastUsedAt: row.last_used_at
});
const countCredentials = async (userId) => Number((await db.query('SELECT COUNT(*) AS n FROM webauthn_credentials WHERE user_id = ?', [userId]))[0][0].n);

async function beginRegistration(userId, username) {
    const cfg = requireConfig();
    const existing = await listCredentials(userId);
    if (existing.length >= MAX_CREDENTIALS) throw new WebauthnError('TOO_MANY_CREDENTIALS', `Máximo ${MAX_CREDENTIALS} llaves por usuario`, 409);

    const options = await webauthn.generateRegistrationOptions({
        rpName: cfg.rpName, rpID: cfg.rpId, userName: username, userID: userHandle(userId), attestationType: 'none',
        excludeCredentials: existing.map(c => ({ id: c.credential_id, transports: c.transports ? c.transports.split(',') : undefined })),
        authenticatorSelection: { residentKey: 'preferred', userVerification: cfg.userVerification },
        timeout: CHALLENGE_TTL_SECONDS * 1000
    });
    await storeChallenge(userId, 'register', options.challenge);
    return options;
}

async function finishRegistration(userId, response, name) {
    const cfg = requireConfig();
    const expectedChallenge = await consumeChallenge(userId, 'register', response);
    if (!expectedChallenge) throw new WebauthnError('INVALID_CHALLENGE', 'El reto no es válido o caducó: vuelve a empezar', 400);

    let verification;
    try {
        verification = await webauthn.verifyRegistrationResponse({
            response, expectedChallenge, expectedOrigin: cfg.origins, expectedRPID: cfg.rpId,
            requireUserVerification: cfg.userVerification === 'required'
        });
    } catch (error) {
        await events.record({ type: 'WEBAUTHN_REGISTRATION_FAILED', severity: 'medium', riskScore: 30, userId, details: { error: String(error.message).slice(0, 120) } });
        throw new WebauthnError('WEBAUTHN_VERIFICATION_FAILED', 'No se pudo verificar la llave', 400);
    }
    if (!verification.verified) throw new WebauthnError('WEBAUTHN_VERIFICATION_FAILED', 'No se pudo verificar la llave', 400);

    const { credential, credentialDeviceType, credentialBackedUp, aaguid } = verification.registrationInfo;
    if (await countCredentials(userId) >= MAX_CREDENTIALS) throw new WebauthnError('TOO_MANY_CREDENTIALS', `Máximo ${MAX_CREDENTIALS} llaves por usuario`, 409);

    try {
        const [result] = await db.query(
            `INSERT INTO webauthn_credentials (user_id, credential_id, public_key, counter, transports, device_type, backed_up, aaguid, name)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [userId, credential.id, Buffer.from(credential.publicKey).toString('base64url'), credential.counter,
                (credential.transports || response.response?.transports || []).filter(t => /^[a-z-]{2,16}$/.test(t)).join(',').slice(0, 100) || null,
                credentialDeviceType, credentialBackedUp ? 1 : 0, /^[0-9a-f-]{36}$/.test(aaguid) ? aaguid : null, cleanName(name)]
        );
        return { id: Number(result.insertId) };
    } catch (error) {
        if (error.code === 'ER_DUP_ENTRY') throw new WebauthnError('CREDENTIAL_EXISTS', 'Esa llave ya está registrada', 409);
        throw error;
    }
}

// ------------------------------------------------------------------ inicio de sesión (segundo factor)
async function beginAuthentication(userId) {
    const cfg = requireConfig();
    const credentials = await listCredentials(userId);
    if (credentials.length === 0) throw new WebauthnError('NO_CREDENTIALS', 'Este usuario no tiene llaves registradas', 400);

    const options = await webauthn.generateAuthenticationOptions({
        rpID: cfg.rpId, userVerification: cfg.userVerification, timeout: CHALLENGE_TTL_SECONDS * 1000,
        allowCredentials: credentials.map(c => ({ id: c.credential_id, transports: c.transports ? c.transports.split(',') : undefined }))
    });
    await storeChallenge(userId, 'login', options.challenge);
    return options;
}

// Devuelve { ok: true } o { ok: false, rule }. Nunca lanza por una respuesta mala: el llamador la cuenta como fallo de login.
async function verifyAuthentication(userId, response) {
    const cfg = requireConfig();
    const credentialId = typeof response?.id === 'string' && response.id.length <= 512 ? response.id : null;
    if (!credentialId) return { ok: false, rule: 'BAD_WEBAUTHN' };

    const [rows] = await db.query('SELECT id, public_key, counter, transports FROM webauthn_credentials WHERE credential_id = ? AND user_id = ?', [credentialId, userId]);
    const stored = rows[0];
    const expectedChallenge = await consumeChallenge(userId, 'login', response);   // se consume SIEMPRE: un intento fallido gasta el reto
    if (!stored || !expectedChallenge) return { ok: false, rule: 'BAD_WEBAUTHN' };

    let verification;
    try {
        verification = await webauthn.verifyAuthenticationResponse({
            response, expectedChallenge, expectedOrigin: cfg.origins, expectedRPID: cfg.rpId,
            requireUserVerification: cfg.userVerification === 'required',
            credential: { id: credentialId, publicKey: Buffer.from(stored.public_key, 'base64url'), counter: Number(stored.counter), transports: stored.transports ? stored.transports.split(',') : undefined }
        });
    } catch (error) {
        const rollback = /counter/i.test(String(error.message));
        if (rollback) {
            // Una llave clonada: la copia y el original comparten contador. Se avisa en alto.
            await events.record({
                type: 'WEBAUTHN_COUNTER_ROLLBACK', rule: 'WEBAUTHN_CLONE_SUSPECTED', severity: 'critical', riskScore: 85, userId,
                details: { credentialRow: Number(stored.id), storedCounter: Number(stored.counter) }
            });
        }
        return { ok: false, rule: rollback ? 'WEBAUTHN_CLONE_SUSPECTED' : 'BAD_WEBAUTHN' };
    }
    if (!verification.verified) return { ok: false, rule: 'BAD_WEBAUTHN' };

    // Actualización optimista del contador: si otra firma lo cambió mientras tanto, esta no pasa
    const [updated] = await db.query(
        'UPDATE webauthn_credentials SET counter = ?, last_used_at = NOW() WHERE id = ? AND counter = ?',
        [verification.authenticationInfo.newCounter, stored.id, stored.counter]
    );
    if (updated.affectedRows !== 1) return { ok: false, rule: 'BAD_WEBAUTHN' };
    return { ok: true, method: 'hwk', userVerified: verification.authenticationInfo.userVerified };
}

async function removeCredential(userId, credentialRowId) {
    const [result] = await db.query('DELETE FROM webauthn_credentials WHERE id = ? AND user_id = ?', [credentialRowId, userId]);
    return result.affectedRows === 1;
}

async function purgeExpired() {
    const [result] = await db.query('DELETE FROM webauthn_challenges WHERE expires_at < NOW() LIMIT 5000');
    return result.affectedRows;
}

module.exports = {
    enabled, config, beginRegistration, finishRegistration, beginAuthentication, verifyAuthentication,
    listCredentials, publicCredential, countCredentials, removeCredential, purgeExpired, WebauthnError, MAX_CREDENTIALS
};
