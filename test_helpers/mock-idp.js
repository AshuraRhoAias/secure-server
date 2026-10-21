// Proveedor OpenID Connect SIMULADO para las pruebas de SSO. Implementa lo justo del protocolo (descubrimiento,
// JWKS, endpoint de token con PKCE y autenticación de cliente) y permite fabricar id_token válidos y también
// inválidos de todas las formas que un atacante intentaría.

const http = require('http');
const crypto = require('crypto');
const { generateKeyPair, exportJWK, SignJWT } = require('jose');

async function createMockIdp({ clientId, clientSecret }) {
    const good = await generateKeyPair('ES256');
    const evil = await generateKeyPair('ES256'); // clave del atacante: NO está en el JWKS
    const goodJwk = { ...(await exportJWK(good.publicKey)), kid: 'good-key', alg: 'ES256', use: 'sig' };

    const codes = new Map();
    const idp = {
        issuer: null,
        behaviors: { issuerOverride: null, jwksOverride: null, tokenStatus: null },
        codes,
        tokenRequests: []
    };

    const server = http.createServer(async (req, res) => {
        const url = new URL(req.url, 'http://x');
        const send = (status, body) => { res.writeHead(status, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(body)); };

        if (url.pathname === '/.well-known/openid-configuration') {
            return send(200, {
                issuer: idp.behaviors.issuerOverride || idp.issuer,
                authorization_endpoint: `${idp.issuer}/authorize`,
                token_endpoint: `${idp.issuer}/token`,
                jwks_uri: `${idp.issuer}/jwks`,
                id_token_signing_alg_values_supported: ['ES256'],
                token_endpoint_auth_methods_supported: ['client_secret_post', 'client_secret_basic'],
                code_challenge_methods_supported: ['S256']
            });
        }
        if (url.pathname === '/jwks') return send(200, idp.behaviors.jwksOverride || { keys: [goodJwk] });

        if (url.pathname === '/token' && req.method === 'POST') {
            let raw = '';
            for await (const chunk of req) raw += chunk;
            const form = new URLSearchParams(raw);
            idp.tokenRequests.push({ form: Object.fromEntries(form), authorization: req.headers.authorization || null });

            if (idp.behaviors.tokenStatus) return send(idp.behaviors.tokenStatus, { error: 'server_error' });

            const record = codes.get(form.get('code'));
            if (!record || record.used) return send(400, { error: 'invalid_grant' });
            record.used = true;

            // Autenticación del cliente (en el cuerpo o con Basic)
            let secret = form.get('client_secret');
            if (req.headers.authorization?.startsWith('Basic ')) {
                const [, value] = Buffer.from(req.headers.authorization.slice(6), 'base64').toString().split(':');
                secret = decodeURIComponent(value);
            }
            if (form.get('client_id') !== clientId || secret !== clientSecret) return send(401, { error: 'invalid_client' });
            if (form.get('redirect_uri') !== record.redirectUri) return send(400, { error: 'invalid_grant' });

            // PKCE: el verificador debe corresponder al desafío del inicio
            const challenge = crypto.createHash('sha256').update(form.get('code_verifier') || '').digest('base64url');
            if (challenge !== record.codeChallenge) return send(400, { error: 'invalid_grant', error_description: 'PKCE' });

            const now = Math.floor(Date.now() / 1000);
            const claims = {
                iss: idp.issuer, aud: clientId, sub: record.sub, email: record.email, email_verified: true,
                nonce: record.nonce, iat: now, exp: now + 300, ...record.claims
            };
            for (const key of Object.keys(claims)) if (claims[key] === undefined) delete claims[key];
            return send(200, { access_token: 'at-' + crypto.randomUUID(), token_type: 'Bearer', id_token: await sign(claims, record.sign) });
        }
        send(404, { error: 'not_found' });
    });

    async function sign(claims, mode = 'normal') {
        const jwt = new SignJWT(claims);
        switch (mode) {
            case 'normal': return jwt.setProtectedHeader({ alg: 'ES256', kid: 'good-key' }).sign(good.privateKey);
            case 'evil-key': return jwt.setProtectedHeader({ alg: 'ES256', kid: 'good-key' }).sign(evil.privateKey); // mismo kid, otra clave
            case 'unknown-kid': return jwt.setProtectedHeader({ alg: 'ES256', kid: 'otra' }).sign(good.privateKey);
            case 'hs256': return jwt.setProtectedHeader({ alg: 'HS256' }).sign(Buffer.from(clientSecret)); // confusión de algoritmo
            case 'none': {
                const enc = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
                return `${enc({ alg: 'none', typ: 'JWT' })}.${enc(claims)}.`;
            }
            case 'tampered': {
                const [h, p, s] = (await jwt.setProtectedHeader({ alg: 'ES256', kid: 'good-key' }).sign(good.privateKey)).split('.');
                const payload = JSON.parse(Buffer.from(p, 'base64url'));
                payload.sub = 'admin-takeover';
                return `${h}.${Buffer.from(JSON.stringify(payload)).toString('base64url')}.${s}`;
            }
            default: throw new Error('modo desconocido ' + mode);
        }
    }

    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    idp.issuer = `http://127.0.0.1:${server.address().port}`;
    idp.close = () => new Promise(resolve => server.close(resolve));

    // Simula lo que hace el navegador del usuario: toma la URL de autorización que devolvió nuestro /login,
    // comprueba que es correcta, y devuelve la ruta de callback (con code y state) a la que redirigiría el proveedor.
    idp.authorize = (authUrl, { sub = 'user-' + crypto.randomUUID(), email = `${sub}@acme.com`, claims = {}, sign: signMode = 'normal', stateOverride, codeChallengeOverride } = {}) => {
        const url = new URL(authUrl);
        const p = url.searchParams;
        if (url.origin !== idp.issuer || url.pathname !== '/authorize') throw new Error('la URL de autorización no apunta al proveedor');
        if (p.get('response_type') !== 'code' || p.get('client_id') !== clientId || p.get('code_challenge_method') !== 'S256') throw new Error('parámetros de autorización incorrectos');

        const code = crypto.randomBytes(16).toString('hex');
        codes.set(code, {
            sub, email, claims, sign: signMode, nonce: p.get('nonce'), codeChallenge: codeChallengeOverride || p.get('code_challenge'),
            redirectUri: p.get('redirect_uri'), used: false
        });
        const callback = new URL(p.get('redirect_uri'));
        callback.searchParams.set('code', code);
        callback.searchParams.set('state', stateOverride ?? p.get('state'));
        return { code, callbackPath: callback.pathname + callback.search, params: Object.fromEntries(p) };
    };

    return idp;
}

module.exports = { createMockIdp };
