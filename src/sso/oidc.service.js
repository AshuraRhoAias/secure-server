const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const { createRemoteJWKSet, jwtVerify } = require('jose');
const db = require('../config/database');
const tripleEncryptor = require('../crypto/tripleEncryptor');
const secureAuth = require('../security/secure-auth.service');
const { ipSubject } = require('../security/ip');

// SSO por OpenID Connect (flujo "authorization code" + PKCE). Funciona con cualquier proveedor que
// publique /.well-known/openid-configuration: Microsoft Entra ID (Azure AD), Okta, Auth0, Keycloak,
// Google Workspace, etc.
//
// Lo que se comprueba (cada punto tiene una prueba contra un proveedor simulado en test_sso.js):
//   - state aleatorio de un solo uso (en la BD, 10 min) → defensa contra CSRF de login
//   - nonce ligado al id_token → defensa contra repetición de tokens
//   - PKCE (S256) en todos los casos, también con cliente confidencial
//   - el metadato de descubrimiento declara el MISMO issuer que el configurado → defensa contra "mix-up"
//   - firma del id_token con las claves publicadas por el proveedor (JWKS) y SOLO algoritmos asimétricos:
//     se rechazan "none" y HS* (ataque de confusión de algoritmo)
//   - iss, aud (y azp si hay varias), exp y sub obligatorios; email_verified si está configurado
//   - nunca se enlaza por email con una cuenta local existente (vector clásico de toma de cuentas)
//
// Configuración (variables de entorno): ver docs/SEGURIDAD.md §SSO.

const ASYMMETRIC_ALGS = ['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512', 'ES256', 'ES384', 'ES512', 'EdDSA'];
const STATE_TTL_MINUTES = 10;
const HTTP_TIMEOUT_MS = 8000;
const MAX_RESPONSE_BYTES = 256 * 1024;

class SsoError extends Error {
    constructor(code, message, { status = 400, rule = code } = {}) {
        super(message);
        this.code = code;
        this.status = status;
        this.rule = rule;
    }
}

const sha256 = (text) => crypto.createHash('sha256').update(text).digest('hex');
const b64url = (buffer) => Buffer.from(buffer).toString('base64url');

const config = () => ({
    issuer: (process.env.SSO_ISSUER || '').replace(/\/$/, ''),
    clientId: process.env.SSO_CLIENT_ID || '',
    clientSecret: process.env.SSO_CLIENT_SECRET || '',
    redirectUri: process.env.SSO_REDIRECT_URI || '',
    scopes: process.env.SSO_SCOPES || 'openid email profile',
    allowedDomains: (process.env.SSO_ALLOWED_EMAIL_DOMAINS || '').split(',').map(d => d.trim().toLowerCase()).filter(Boolean),
    autoProvision: process.env.SSO_AUTO_PROVISION !== 'false',
    requireEmailVerified: process.env.SSO_REQUIRE_EMAIL_VERIFIED !== 'false',
    adminClaim: process.env.SSO_ADMIN_CLAIM || '',
    adminValue: process.env.SSO_ADMIN_VALUE || ''
});

const isConfigured = () => {
    const c = config();
    return Boolean(c.issuer && c.clientId && c.redirectUri);
};

// HTTPS obligatorio salvo fuera de producción (o SSO_ALLOW_INSECURE_HTTP=true, solo para pruebas locales)
function assertSecureUrl(url, what) {
    const parsed = new URL(url);
    const insecureOk = process.env.NODE_ENV !== 'production' || process.env.SSO_ALLOW_INSECURE_HTTP === 'true';
    if (parsed.protocol !== 'https:' && !(insecureOk && parsed.protocol === 'http:')) {
        throw new SsoError('SSO_INSECURE_ENDPOINT', `${what} debe usar HTTPS`, { status: 502 });
    }
    return parsed;
}

async function fetchLimited(url, options = {}) {
    const response = await fetch(url, { ...options, redirect: 'error', signal: AbortSignal.timeout(HTTP_TIMEOUT_MS) });
    const reader = response.body?.getReader();
    const chunks = [];
    let total = 0;
    while (reader) {
        const { done, value } = await reader.read();
        if (done) break;
        total += value.length;
        if (total > MAX_RESPONSE_BYTES) { await reader.cancel(); throw new SsoError('SSO_RESPONSE_TOO_LARGE', 'Respuesta del proveedor demasiado grande', { status: 502 }); }
        chunks.push(value);
    }
    return { status: response.status, text: Buffer.concat(chunks).toString('utf8') };
}

// Metadatos públicos del proveedor (cacheados unos minutos: es configuración, no estado de seguridad)
const metadataCache = { value: null, expires: 0, issuer: null };
const jwksCache = new Map();

async function getMetadata({ force = false } = {}) {
    const { issuer } = config();
    if (!force && metadataCache.value && metadataCache.issuer === issuer && Date.now() < metadataCache.expires) return metadataCache.value;

    assertSecureUrl(issuer, 'El issuer');
    const { status, text } = await fetchLimited(`${issuer}/.well-known/openid-configuration`, { headers: { Accept: 'application/json' } });
    if (status !== 200) throw new SsoError('SSO_DISCOVERY_FAILED', 'No se pudo leer la configuración del proveedor', { status: 502 });

    let metadata;
    try { metadata = JSON.parse(text); } catch { throw new SsoError('SSO_DISCOVERY_FAILED', 'Configuración del proveedor inválida', { status: 502 }); }

    // Defensa contra "mix-up": el documento debe declarar exactamente el issuer que configuramos
    if (String(metadata.issuer || '').replace(/\/$/, '') !== issuer) {
        throw new SsoError('SSO_ISSUER_MISMATCH', 'El issuer del proveedor no coincide con el configurado', { status: 502, rule: 'SSO_ISSUER_MISMATCH' });
    }
    for (const field of ['authorization_endpoint', 'token_endpoint', 'jwks_uri']) {
        if (!metadata[field]) throw new SsoError('SSO_DISCOVERY_FAILED', `Falta ${field} en la configuración del proveedor`, { status: 502 });
        assertSecureUrl(metadata[field], field);
    }

    Object.assign(metadataCache, { value: metadata, expires: Date.now() + 10 * 60 * 1000, issuer });
    return metadata;
}

const jwksFor = (uri) => {
    if (!jwksCache.has(uri)) jwksCache.set(uri, createRemoteJWKSet(new URL(uri), { timeoutDuration: HTTP_TIMEOUT_MS, cooldownDuration: 30_000 }));
    return jwksCache.get(uri);
};

class OidcService {
    isConfigured() { return isConfigured(); }

    // Paso 1: prepara el estado y devuelve la URL del proveedor a la que enviar al usuario
    async beginLogin({ ip }) {
        const c = config();
        const metadata = await getMetadata();

        const state = b64url(crypto.randomBytes(32));
        const nonce = b64url(crypto.randomBytes(24));
        const verifier = b64url(crypto.randomBytes(48));
        const challenge = b64url(crypto.createHash('sha256').update(verifier).digest());

        await db.query(
            `INSERT INTO oidc_login_state (state_hash, nonce, code_verifier_encrypted, ip_subject, expires_at)
             VALUES (?, ?, ?, ?, DATE_ADD(NOW(), INTERVAL ? MINUTE))`,
            [sha256(state), nonce, tripleEncryptor.encrypt(verifier), ipSubject(ip), STATE_TTL_MINUTES]
        );

        const url = new URL(metadata.authorization_endpoint);
        url.search = new URLSearchParams({
            response_type: 'code', client_id: c.clientId, redirect_uri: c.redirectUri, scope: c.scopes,
            state, nonce, code_challenge: challenge, code_challenge_method: 'S256'
        }).toString();
        return { url: url.toString() };
    }

    // Paso 2: el proveedor devuelve al usuario aquí con ?code&state
    async handleCallback({ code, state, error, ip, userAgent }) {
        const c = config();
        if (error) throw new SsoError('SSO_PROVIDER_ERROR', 'El proveedor rechazó el inicio de sesión', { status: 401, rule: 'SSO_PROVIDER_ERROR' });
        if (!code || !state) throw new SsoError('SSO_BAD_CALLBACK', 'Faltan code o state', { rule: 'SSO_BAD_CALLBACK' });

        // El state se consume de forma atómica: un state solo vale una vez, y solo mientras no caduque
        const [consumed] = await db.query(
            'UPDATE oidc_login_state SET used_at = NOW() WHERE state_hash = ? AND used_at IS NULL AND expires_at > NOW()',
            [sha256(state)]
        );
        if (consumed.affectedRows !== 1) {
            throw new SsoError('SSO_STATE_INVALID', 'El inicio de sesión caducó o ya se usó: vuelve a empezar', { status: 401, rule: 'SSO_STATE_INVALID' });
        }
        const [[saved]] = await db.query('SELECT nonce, code_verifier_encrypted FROM oidc_login_state WHERE state_hash = ?', [sha256(state)]);
        const verifier = tripleEncryptor.decrypt(saved.code_verifier_encrypted);

        const metadata = await getMetadata();
        const idToken = await this.exchangeCode(metadata, { code, verifier });
        const claims = await this.verifyIdToken(metadata, idToken, saved.nonce);

        const user = await this.resolveUser(claims);

        const deviceInfo = { ipAddress: ip, userAgent };
        const result = await secureAuth.completeLogin({
            user, usernameHash: secureAuth.generateUsernameHash(user.username), deviceInfo, amr: ['sso']
        });
        return { ...result, email: claims.email || null, role: user.role, provisioned: user.provisioned };
    }

    async exchangeCode(metadata, { code, verifier }) {
        const c = config();
        const body = new URLSearchParams({
            grant_type: 'authorization_code', code, redirect_uri: c.redirectUri, client_id: c.clientId, code_verifier: verifier
        });
        const headers = { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' };

        if (c.clientSecret) {
            const methods = metadata.token_endpoint_auth_methods_supported;
            if (Array.isArray(methods) && methods.includes('client_secret_basic') && !methods.includes('client_secret_post')) {
                headers.Authorization = `Basic ${Buffer.from(`${encodeURIComponent(c.clientId)}:${encodeURIComponent(c.clientSecret)}`).toString('base64')}`;
            } else {
                body.set('client_secret', c.clientSecret);
            }
        }

        let response;
        try {
            response = await fetchLimited(metadata.token_endpoint, { method: 'POST', headers, body });
        } catch (error) {
            if (error instanceof SsoError) throw error;
            throw new SsoError('SSO_TOKEN_EXCHANGE_FAILED', 'No se pudo contactar con el proveedor', { status: 502 });
        }

        let parsed;
        try { parsed = JSON.parse(response.text); } catch { parsed = {}; }
        if (response.status !== 200 || typeof parsed.id_token !== 'string') {
            throw new SsoError('SSO_TOKEN_EXCHANGE_FAILED', 'El proveedor no aceptó el código', { status: 401, rule: 'SSO_TOKEN_EXCHANGE_FAILED' });
        }
        return parsed.id_token;
    }

    async verifyIdToken(metadata, idToken, expectedNonce) {
        const c = config();
        let payload;
        try {
            ({ payload } = await jwtVerify(idToken, jwksFor(metadata.jwks_uri), {
                issuer: c.issuer, audience: c.clientId, algorithms: ASYMMETRIC_ALGS, clockTolerance: 60,
                requiredClaims: ['sub', 'exp', 'iat']
            }));
        } catch (error) {
            throw new SsoError('SSO_ID_TOKEN_INVALID', 'El id_token no es válido', { status: 401, rule: `SSO_ID_TOKEN_${String(error.code || 'INVALID').replace(/^ERR_/, '')}`.slice(0, 64) });
        }

        // Con varias audiencias, la autorizada debe ser nuestro client_id (OIDC Core 3.1.3.7)
        if (Array.isArray(payload.aud) && payload.aud.length > 1 && payload.azp !== c.clientId) {
            throw new SsoError('SSO_ID_TOKEN_INVALID', 'El id_token no es válido', { status: 401, rule: 'SSO_AZP_MISMATCH' });
        }

        // El nonce liga el id_token a ESTE inicio de login (comparación en tiempo constante)
        const a = Buffer.from(String(payload.nonce || ''));
        const b = Buffer.from(expectedNonce);
        if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
            throw new SsoError('SSO_ID_TOKEN_INVALID', 'El id_token no es válido', { status: 401, rule: 'SSO_NONCE_MISMATCH' });
        }

        if (c.requireEmailVerified && payload.email && payload.email_verified !== true) {
            throw new SsoError('SSO_EMAIL_UNVERIFIED', 'El proveedor no ha verificado tu email', { status: 403, rule: 'SSO_EMAIL_UNVERIFIED' });
        }
        if (typeof payload.sub !== 'string' || payload.sub.length === 0 || payload.sub.length > 255) {
            throw new SsoError('SSO_ID_TOKEN_INVALID', 'El id_token no es válido', { status: 401, rule: 'SSO_SUB_INVALID' });
        }
        return payload;
    }

    roleFromClaims(claims) {
        const c = config();
        if (!c.adminClaim || !c.adminValue) return null; // el rol se gestiona en la BD
        const value = claims[c.adminClaim];
        const isAdmin = Array.isArray(value) ? value.includes(c.adminValue) : value === c.adminValue;
        return isAdmin ? 'admin' : 'user';
    }

    // Busca el usuario local de esta identidad o lo crea. NUNCA se enlaza por email con una cuenta existente.
    async resolveUser(claims) {
        const c = config();
        const identityHash = sha256(`${c.issuer}|${claims.sub}`);
        const claimedRole = this.roleFromClaims(claims);

        const [found] = await db.query(
            `SELECT u.id, u.username_encrypted, u.role FROM user_identities i JOIN users u ON u.id = i.user_id WHERE i.identity_hash = ?`,
            [identityHash]
        );
        if (found.length > 0) {
            await db.query('UPDATE user_identities SET last_login_at = NOW() WHERE identity_hash = ?', [identityHash]);
            // El proveedor solo concede o retira 'admin'; los roles auditor/operator (asignados con set-role) no se degradan
            const roleNow = found[0].role;
            const nextRole = claimedRole === 'admin' ? 'admin' : (roleNow === 'admin' ? 'user' : roleNow);
            if (claimedRole && nextRole !== roleNow) await db.query('UPDATE users SET role = ? WHERE id = ?', [nextRole, found[0].id]);
            return { id: found[0].id, username: tripleEncryptor.decrypt(found[0].username_encrypted), role: claimedRole ? nextRole : roleNow, provisioned: false };
        }

        if (!c.autoProvision) throw new SsoError('SSO_USER_NOT_PROVISIONED', 'Tu usuario no está dado de alta', { status: 403, rule: 'SSO_USER_NOT_PROVISIONED' });

        const email = typeof claims.email === 'string' ? claims.email.toLowerCase() : '';
        if (c.allowedDomains.length > 0 && !c.allowedDomains.includes(email.split('@')[1] || '')) {
            throw new SsoError('SSO_DOMAIN_NOT_ALLOWED', 'Tu dominio no tiene acceso', { status: 403, rule: 'SSO_DOMAIN_NOT_ALLOWED' });
        }

        const username = `sso_${identityHash.slice(0, 20)}`;
        const usernameHash = secureAuth.generateUsernameHash(username);
        const role = claimedRole || 'user';

        try {
            const created = await db.transaction(async (tx) => {
                const [result] = await tx.query(
                    `INSERT INTO users (username_encrypted, username_hash, email_encrypted, password_hash, device_fingerprint,
                                        risk_level_encrypted, encrypted_metadata, encryption_version, role, created_at, updated_at)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW())`,
                    [
                        tripleEncryptor.encrypt(username), usernameHash, tripleEncryptor.encrypt(email),
                        // Contraseña imposible de adivinar: esta cuenta solo entra por SSO
                        await bcrypt.hash(crypto.randomBytes(32).toString('hex'), 10),
                        '', tripleEncryptor.encrypt('low'),
                        tripleEncryptor.encrypt(JSON.stringify({ provisionedBy: 'sso', issuer: c.issuer, at: new Date().toISOString() })),
                        'v4.0.0', role
                    ]
                );
                await tx.query('INSERT INTO user_identities (user_id, issuer, identity_hash, last_login_at) VALUES (?, ?, ?, NOW())', [result.insertId, c.issuer.slice(0, 255), identityHash]);
                return result.insertId;
            });
            return { id: created, username, role, provisioned: true };
        } catch (error) {
            if (error.code === 'ER_DUP_ENTRY') return this.resolveUser(claims); // dos primeros logins a la vez: gana uno
            throw error;
        }
    }

    // Borra estados caducados (la limpieza periódica lo llama)
    async purgeExpired() {
        const [result] = await db.query('DELETE FROM oidc_login_state WHERE expires_at < DATE_SUB(NOW(), INTERVAL 1 DAY) LIMIT 5000');
        return result.affectedRows;
    }

    _resetCachesForTests() { metadataCache.value = null; jwksCache.clear(); }
}

module.exports = new OidcService();
module.exports.SsoError = SsoError;
