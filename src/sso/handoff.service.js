// Entrega de un login SSO (OIDC o SAML) a la interfaz web por CÓDIGO DE UN SOLO USO ligado al navegador (patrón PKCE).
// Ver database/migrations/017_sso_handoff.sql. Se activa con SSO_HANDOFF_URL (p. ej. https://ops.ejemplo.com/session/sso/callback).
//
//   inicio    BFF: verificador aleatorio → cookie httpOnly;  /api/{sso,saml}/login?format=json&handoff=<base64url(sha256(verificador))>
//   vuelta    API: tras validar al proveedor, guarda los tokens CIFRADOS (60 s) y redirige a SSO_HANDOFF_URL?code=<código>
//   canje     BFF: POST /api/sso/exchange { code, verifier } (servidor a servidor) → tokens. Un solo uso.
//
// Garantías: los tokens no tocan la URL ni el JavaScript; el código (que sí pasa por la URL y puede quedar en el historial o en
// el registro de un proxy) caduca en 60 s, vale una vez y NO sirve sin el verificador que solo tiene el navegador que empezó.
// Un canje con el verificador equivocado QUEMA el código (y queda un evento crítico): quien lo robó no puede reintentar.

const crypto = require('crypto');
const db = require('../config/database');
const tripleEncryptor = require('../crypto/tripleEncryptor');
const { SsoError } = require('./errors');

const BEGIN_TTL_MINUTES = 10;
const CODE_TTL_SECONDS = 60;
const CHALLENGE = /^[A-Za-z0-9_-]{43}$/;          // base64url(sha256) sin relleno
const CODE = /^[A-Za-z0-9_-]{43}$/;               // 32 bytes aleatorios en base64url
const VERIFIER = /^[A-Za-z0-9_-]{43,128}$/;       // como el code_verifier de PKCE (RFC 7636)

const sha256hex = (value) => crypto.createHash('sha256').update(String(value)).digest('hex');
const challengeOf = (verifier) => crypto.createHash('sha256').update(String(verifier)).digest('base64url');

function handoffUrl() {
    const raw = process.env.SSO_HANDOFF_URL;
    if (!raw) return null;
    const url = new URL(raw);
    if (url.protocol !== 'https:' && process.env.NODE_ENV === 'production' && process.env.SSO_HANDOFF_ALLOW_HTTP !== 'true') {
        throw new SsoError('SSO_HANDOFF_MISCONFIGURED', 'SSO_HANDOFF_URL debe ser https:// en producción', { status: 500 });
    }
    return url;
}

class SsoHandoffService {
    isEnabled() { return Boolean(process.env.SSO_HANDOFF_URL); }
    isValidChallenge(value) { return typeof value === 'string' && CHALLENGE.test(value); }

    // Paso 1: registrar el inicio. `beginHandle` es el valor aleatorio que vuelve con el proveedor (state de OIDC, RelayState de SAML)
    async begin({ provider, beginHandle, challenge }) {
        if (!this.isEnabled()) throw new SsoError('SSO_HANDOFF_NOT_CONFIGURED', 'La entrega a la interfaz web no está configurada (SSO_HANDOFF_URL)', { status: 404 });
        if (!this.isValidChallenge(challenge)) throw new SsoError('SSO_BAD_HANDOFF', 'handoff no válido', { rule: 'SSO_BAD_HANDOFF' });
        handoffUrl(); // valida la configuración ANTES de mandar al usuario al proveedor
        await db.query(
            'INSERT INTO sso_handoffs (begin_hash, provider, challenge, expires_at) VALUES (?, ?, ?, DATE_ADD(NOW(), INTERVAL ? MINUTE))',
            [sha256hex(beginHandle), provider, challenge, BEGIN_TTL_MINUTES]
        );
    }

    // Paso 2: el login con el proveedor fue bien. Si ese inicio pidió entrega a la web, guarda los tokens y devuelve la URL de
    // redirección con el código; si no (login directo contra el API), devuelve null y el controlador responde como siempre.
    async complete({ beginHandle, result }) {
        if (!this.isEnabled() || !beginHandle) return null;
        const code = crypto.randomBytes(32).toString('base64url');
        const payload = JSON.stringify({
            token: result.token, refreshToken: result.refreshToken, expiresAt: result.expiresAt, expiresIn: result.expiresIn,
            refreshExpiresAt: result.refreshExpiresAt, sessionExpiresAt: result.sessionExpiresAt, riskLevel: result.riskLevel, authMethods: result.amr
        });
        const [updated] = await db.query(
            `UPDATE sso_handoffs SET code_hash = ?, payload_encrypted = ?, user_id = ?, code_expires_at = DATE_ADD(NOW(), INTERVAL ? SECOND)
             WHERE begin_hash = ? AND code_hash IS NULL AND expires_at > NOW()`,
            [sha256hex(code), tripleEncryptor.encrypt(payload), result.userId ?? null, CODE_TTL_SECONDS, sha256hex(beginHandle)]
        );
        if (updated.affectedRows !== 1) return null;
        const url = handoffUrl();
        url.search = new URLSearchParams({ code }).toString();
        url.hash = '';
        return url.toString();
    }

    // Paso 3: canje (lo llama el BFF). Primero se CONSUME el código (atómico); después se compara el verificador.
    async exchange({ code, verifier }) {
        const invalid = (rule) => new SsoError('SSO_HANDOFF_INVALID', 'El inicio de sesión caducó o ya se usó: vuelve a empezar', { status: 401, rule });
        if (typeof code !== 'string' || !CODE.test(code) || typeof verifier !== 'string' || !VERIFIER.test(verifier)) throw invalid('SSO_HANDOFF_BAD_INPUT');

        const codeHash = sha256hex(code);
        const [consumed] = await db.query(
            'UPDATE sso_handoffs SET used_at = NOW() WHERE code_hash = ? AND used_at IS NULL AND code_expires_at > NOW()', [codeHash]
        );
        if (consumed.affectedRows !== 1) throw invalid('SSO_HANDOFF_INVALID');

        const [[row]] = await db.query('SELECT id, challenge, payload_encrypted, user_id FROM sso_handoffs WHERE code_hash = ?', [codeHash]);
        // El payload no se guarda más de lo necesario: tras el canje (bueno o malo) se borra
        await db.query('UPDATE sso_handoffs SET payload_encrypted = NULL WHERE id = ?', [row.id]);

        const expected = Buffer.from(row.challenge);
        const actual = Buffer.from(challengeOf(verifier));
        if (expected.length !== actual.length || !crypto.timingSafeEqual(expected, actual)) {
            const error = new SsoError('SSO_HANDOFF_INVALID', 'El inicio de sesión caducó o ya se usó: vuelve a empezar', { status: 401, rule: 'SSO_HANDOFF_VERIFIER_MISMATCH' });
            error.critical = true;   // alguien presentó un código válido sin el verificador: código robado
            error.userId = row.user_id;
            throw error;
        }
        return JSON.parse(tripleEncryptor.decrypt(row.payload_encrypted));
    }

    async purgeExpired() {
        const [result] = await db.query('DELETE FROM sso_handoffs WHERE expires_at < DATE_SUB(NOW(), INTERVAL 1 HOUR) LIMIT 5000');
        return result.affectedRows;
    }
}

module.exports = new SsoHandoffService();
module.exports.challengeOf = challengeOf;
