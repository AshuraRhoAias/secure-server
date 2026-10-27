const fs = require('fs');
const { SAML, ValidateInResponseTo } = require('@node-saml/node-saml');
const { DOMParser } = require('@xmldom/xmldom');
const db = require('../config/database');
const secureAuth = require('../security/secure-auth.service');
const { SsoError } = require('./errors');
const { resolveFederatedUser } = require('./federated-users');

// SSO por SAML 2.0 (proveedor de servicio, SP). Funciona con Entra ID, Okta, ADFS, Keycloak, Google Workspace, etc.
// La verificación XML (firma, audiencia, ventanas de validez, InResponseTo) la hace @node-saml/node-saml; aquí van las
// reglas del sistema, todas con prueba en test_saml.js contra un IdP simulado que firma de verdad:
//
//   - Solo SP-initiated: la respuesta debe contestar a una AuthnRequest NUESTRA (InResponseTo, guardada en BD y de un
//     solo uso). El inicio "IdP-initiated" no se admite (es la puerta de la repetición y de la inyección de aserciones).
//   - Firma obligatoria sobre la aserción (por defecto), la respuesta o ambas (SAML_REQUIRE_SIGNED=assertion|response|both),
//     con el certificado del IdP configurado. Nada sin firmar se acepta jamás.
//   - Emisor, audiencia (nuestro entityID), destinatario (nuestra URL ACS) y ventanas NotBefore/NotOnOrAfter con tolerancia
//     de reloj acotada. Una aserción ya aceptada no se acepta dos veces (rejectReplayedAssertions).
//   - Misma política de identidad que OIDC: nunca se enlaza por email; el proveedor solo concede o retira 'admin'.
//
// Configuración (variables de entorno):
//   SAML_IDP_SSO_URL (obligatoria)   URL de inicio de sesión del IdP
//   SAML_IDP_ENTITY_ID (obligatoria) el Issuer que el IdP pone en sus respuestas
//   SAML_IDP_CERT (obligatoria)      certificado(s) PEM del IdP, o ruta(s) a archivos separadas por comas (rotación: varios)
//   SAML_CALLBACK_URL (obligatoria)  la URL ACS: https://tu-api/api/saml/acs
//   SAML_SP_ENTITY_ID                nuestro entityID (por defecto, la URL de metadatos)
//   SAML_EMAIL_ATTRIBUTE (email)     atributo con el email
//   SAML_ALLOWED_EMAIL_DOMAINS, SAML_AUTO_PROVISION (true), SAML_ADMIN_ATTRIBUTE + SAML_ADMIN_VALUE, SAML_POST_LOGIN_URL
//   SAML_REQUIRE_SIGNED (assertion), SAML_CLOCK_SKEW_SECONDS (60), SAML_FORCE_AUTHN (false)
//   SAML_SP_PRIVATE_KEY + SAML_SP_CERT   firmar nuestras AuthnRequest y publicar el certificado en los metadatos (opcional)

const REQUEST_TTL_SECONDS = 10 * 60;
const MAX_RESPONSE_CHARS = 512 * 1024;
const insecureOk = () => process.env.NODE_ENV !== 'production' || process.env.SAML_ALLOW_INSECURE_HTTP === 'true';

const pemBlocks = (text) => text.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) || [];
function readCerts(raw) {
    const text = String(raw || '').replace(/\\n/g, '\n');
    if (text.includes('BEGIN CERTIFICATE')) return pemBlocks(text);
    return text.split(',').map(f => f.trim()).filter(Boolean).flatMap(file => pemBlocks(fs.readFileSync(file, 'utf8')));
}

const config = () => {
    const callbackUrl = process.env.SAML_CALLBACK_URL || '';
    let defaultEntity = '';
    try { defaultEntity = callbackUrl ? `${new URL(callbackUrl).origin}/api/saml/metadata` : ''; } catch { /* callbackUrl inválida: isConfigured lo detecta */ }
    const signed = ['assertion', 'response', 'both'].includes(process.env.SAML_REQUIRE_SIGNED) ? process.env.SAML_REQUIRE_SIGNED : 'assertion';
    return {
        entryPoint: process.env.SAML_IDP_SSO_URL || '',
        idpEntityId: process.env.SAML_IDP_ENTITY_ID || '',
        idpCerts: readCerts(process.env.SAML_IDP_CERT),
        callbackUrl,
        spEntityId: process.env.SAML_SP_ENTITY_ID || defaultEntity,
        emailAttribute: process.env.SAML_EMAIL_ATTRIBUTE || 'email',
        allowedDomains: (process.env.SAML_ALLOWED_EMAIL_DOMAINS || '').split(',').map(d => d.trim().toLowerCase()).filter(Boolean),
        autoProvision: process.env.SAML_AUTO_PROVISION !== 'false',
        adminAttribute: process.env.SAML_ADMIN_ATTRIBUTE || '',
        adminValue: process.env.SAML_ADMIN_VALUE || '',
        signed,
        clockSkewMs: Math.min(Math.max(Number(process.env.SAML_CLOCK_SKEW_SECONDS ?? 60), 0), 300) * 1000,
        forceAuthn: process.env.SAML_FORCE_AUTHN === 'true',
        spPrivateKey: (process.env.SAML_SP_PRIVATE_KEY || '').replace(/\\n/g, '\n'),
        spCert: (process.env.SAML_SP_CERT || '').replace(/\\n/g, '\n')
    };
};

const isConfigured = () => {
    try {
        const c = config();
        return Boolean(c.entryPoint && c.idpEntityId && c.idpCerts.length > 0 && c.callbackUrl && c.spEntityId);
    } catch { return false; }
};

function assertSecureConfig(c) {
    for (const [name, value] of [['SAML_IDP_SSO_URL', c.entryPoint], ['SAML_CALLBACK_URL', c.callbackUrl]]) {
        let url;
        try { url = new URL(value); } catch { throw new SsoError('SAML_MISCONFIGURED', `${name} no es una URL`, { status: 503 }); }
        if (url.protocol !== 'https:' && !(url.protocol === 'http:' && insecureOk())) {
            throw new SsoError('SAML_MISCONFIGURED', `${name} debe ser https://`, { status: 503 });
        }
    }
}

// ------------------------------------------------------------------ caché en BD (InResponseTo y aserciones usadas)
class DbCacheProvider {
    async saveAsync(key, value) {
        await db.query(
            `INSERT INTO saml_cache (cache_key, cache_value, expires_at) VALUES (?, ?, DATE_ADD(NOW(), INTERVAL ? SECOND))
             ON DUPLICATE KEY UPDATE cache_value = VALUES(cache_value), expires_at = VALUES(expires_at)`,
            [String(key).slice(0, 190), String(value).slice(0, 512), REQUEST_TTL_SECONDS]
        );
        return { value, createdAt: Date.now() };
    }

    async getAsync(key) {
        const [rows] = await db.query('SELECT cache_value FROM saml_cache WHERE cache_key = ? AND expires_at > NOW()', [String(key).slice(0, 190)]);
        return rows[0]?.cache_value ?? null;
    }

    async removeAsync(key) {
        if (key == null) return null;
        const value = await this.getAsync(key);
        await db.query('DELETE FROM saml_cache WHERE cache_key = ?', [String(key).slice(0, 190)]);
        return value;
    }

    // Atómico: de dos copias simultáneas de una respuesta, solo una consigue borrar la fila
    async consumeAsync(key) {
        const value = await this.getAsync(key);
        if (value === null) return null;
        const [result] = await db.query('DELETE FROM saml_cache WHERE cache_key = ? AND expires_at > NOW()', [String(key).slice(0, 190)]);
        return result.affectedRows === 1 ? value : null;
    }

    // Atómico: true si la guardó, false si ya estaba (una aserción repetida)
    async saveIfAbsentAsync(key, value, expiresAtMs) {
        const k = String(key).slice(0, 190);
        await db.query('DELETE FROM saml_cache WHERE cache_key = ? AND expires_at <= NOW()', [k]);
        try {
            await db.query(
                'INSERT INTO saml_cache (cache_key, cache_value, expires_at) VALUES (?, ?, FROM_UNIXTIME(?))',
                [k, String(value).slice(0, 512), Math.max(Math.ceil(expiresAtMs / 1000), Math.ceil(Date.now() / 1000) + 60)]
            );
            return true;
        } catch (error) {
            if (error.code === 'ER_DUP_ENTRY') return false;
            throw error;
        }
    }
}

function buildSaml(c) {
    const signing = c.spPrivateKey ? { privateKey: c.spPrivateKey, publicCert: c.spCert || undefined, signatureAlgorithm: 'sha256', digestAlgorithm: 'sha256' } : {};
    return new SAML({
        entryPoint: c.entryPoint,
        callbackUrl: c.callbackUrl,
        issuer: c.spEntityId,
        idpIssuer: c.idpEntityId,
        idpCert: c.idpCerts,
        audience: c.spEntityId,
        // Firmas: nada sin firmar. La aserción por defecto (Entra, Okta, ADFS firman la aserción); la respuesta o ambas, a elección.
        wantAssertionsSigned: c.signed !== 'response',
        wantAuthnResponseSigned: c.signed !== 'assertion',
        // Solo SP-initiated y de un solo uso; y una aserción no se acepta dos veces
        validateInResponseTo: ValidateInResponseTo.always,
        rejectReplayedAssertions: true,
        requestIdExpirationPeriodMs: REQUEST_TTL_SECONDS * 1000,
        cacheProvider: new DbCacheProvider(),
        acceptedClockSkewMs: c.clockSkewMs,
        maxAssertionAgeMs: 10 * 60 * 1000,
        forceAuthn: c.forceAuthn,
        disableRequestedAuthnContext: true,   // no se exige un método concreto: la política de autenticación es del IdP
        identifierFormat: null,
        signMetadata: Boolean(c.spPrivateKey),
        ...signing
    });
}

const first = (value) => (Array.isArray(value) ? value[0] : value);
const asList = (value) => (Array.isArray(value) ? value : value == null ? [] : [value]);

class SamlService {
    isConfigured() { return isConfigured(); }

    // Paso 1: la URL del IdP con nuestra AuthnRequest (su ID queda guardado para validar la respuesta)
    async beginLogin() {
        const c = config();
        assertSecureConfig(c);
        const url = await buildSaml(c).getAuthorizeUrlAsync('', undefined, {});
        return { url };
    }

    async metadata() {
        const c = config();
        assertSecureConfig(c);
        return buildSaml(c).generateServiceProviderMetadata(null, c.spCert || null);
    }

    roleFromAttributes(attributes) {
        const c = config();
        if (!c.adminAttribute || !c.adminValue) return null;
        return asList(attributes[c.adminAttribute]).map(String).includes(c.adminValue) ? 'admin' : 'user';
    }

    // Paso 2: la respuesta POST del IdP (ACS)
    async handleResponse({ samlResponse, ip, userAgent }) {
        const c = config();
        assertSecureConfig(c);
        if (typeof samlResponse !== 'string' || samlResponse.length === 0 || samlResponse.length > MAX_RESPONSE_CHARS || !/^[A-Za-z0-9+/=\s]+$/.test(samlResponse)) {
            throw new SsoError('SAML_BAD_RESPONSE', 'Respuesta SAML no válida', { rule: 'SAML_BAD_RESPONSE' });
        }

        let profile;
        try {
            ({ profile } = await buildSaml(c).validatePostResponseAsync({ SAMLResponse: samlResponse }));
        } catch (error) {
            // El motivo exacto (firma, audiencia, caducidad, repetición...) va al evento, no al cliente
            throw new SsoError('SAML_RESPONSE_INVALID', 'La respuesta del proveedor no es válida', {
                status: 401, rule: `SAML_${classify(error.message)}`
            });
        }
        this.assertProfileBindings(c, samlResponse, profile);
        if (!profile?.nameID || String(profile.nameID).length > 255) {
            throw new SsoError('SAML_RESPONSE_INVALID', 'La respuesta del proveedor no es válida', { status: 401, rule: 'SAML_NO_NAMEID' });
        }

        const attributes = profile.attributes || {};
        const email = String(first(attributes[c.emailAttribute]) ?? (/@/.test(profile.nameID) ? profile.nameID : '')).slice(0, 254);
        const user = await resolveFederatedUser({
            issuerKey: `saml:${c.idpEntityId}`, subject: String(profile.nameID), email,
            claimedRole: this.roleFromAttributes(attributes), autoProvision: c.autoProvision, allowedDomains: c.allowedDomains, provisionedBy: 'saml'
        });

        const result = await secureAuth.completeLogin({
            user, usernameHash: secureAuth.generateUsernameHash(user.username), deviceInfo: { ipAddress: ip, userAgent }, amr: ['saml']
        });
        return { ...result, email: email || null, role: user.role, provisioned: user.provisioned };
    }

    // Comprobaciones del perfil Web SSO que la librería no hace (descubiertas con el IdP simulado). Solo pueden RECHAZAR más:
    //  - Status Success: una respuesta de error no abre sesión aunque lleve una aserción.
    //  - Destination (si la respuesta lo trae) = nuestra URL ACS.
    //  - Recipient de la confirmación "bearer" de la aserción FIRMADA = nuestra URL ACS: una aserción emitida para el ACS de
    //    otro proveedor no vale aquí aunque la firma sea buena.
    assertProfileBindings(c, samlResponse, profile) {
        const reject = (why) => new SsoError('SAML_RESPONSE_INVALID', 'La respuesta del proveedor no es válida', { status: 401, rule: `SAML_${why}` });
        const parse = (xml) => new DOMParser({ onError: () => {} }).parseFromString(xml, 'text/xml');
        const SAMLP = 'urn:oasis:names:tc:SAML:2.0:protocol';
        const SAML_NS = 'urn:oasis:names:tc:SAML:2.0:assertion';

        let response;
        try { response = parse(Buffer.from(samlResponse.replace(/\s+/g, ''), 'base64').toString('utf8')).documentElement; } catch { throw reject('BAD_XML'); }
        const statusCode = response.getElementsByTagNameNS(SAMLP, 'StatusCode')[0];
        if (statusCode && statusCode.getAttribute('Value') !== 'urn:oasis:names:tc:SAML:2.0:status:Success') throw reject('IDP_ERROR');
        const destination = response.getAttribute('Destination');
        if (destination && destination !== c.callbackUrl) throw reject('BAD_DESTINATION');

        const assertionXml = typeof profile?.getAssertionXml === 'function' ? profile.getAssertionXml() : '';
        if (!assertionXml) throw reject('NO_ASSERTION');
        const confirmations = parse(assertionXml).getElementsByTagNameNS(SAML_NS, 'SubjectConfirmationData');
        const recipients = Array.from({ length: confirmations.length }, (_, i) => confirmations[i].getAttribute('Recipient'));
        if (!recipients.includes(c.callbackUrl)) throw reject('BAD_RECIPIENT');
    }

    async purgeExpired() {
        const [result] = await db.query('DELETE FROM saml_cache WHERE expires_at < NOW() LIMIT 5000');
        return result.affectedRows;
    }
}

// Etiqueta corta y de lista cerrada del motivo del rechazo (para el evento de seguridad)
function classify(message) {
    const text = String(message || '').toLowerCase();
    if (text.includes('signature')) return 'BAD_SIGNATURE';
    if (text.includes('audience')) return 'BAD_AUDIENCE';
    if (text.includes('inresponseto') || text.includes('in response to')) return 'BAD_IN_RESPONSE_TO';
    if (text.includes('replay') || text.includes('already')) return 'REPLAYED';
    if (text.includes('notonorafter') || text.includes('expired') || text.includes('not valid') || text.includes('not yet valid') || text.includes('subject confirmation') || text.includes('notbefore') || text.includes('too old')) return 'BAD_TIME_WINDOW';
    if (text.includes('issuer')) return 'BAD_ISSUER';
    if (text.includes('destination') || text.includes('recipient')) return 'BAD_DESTINATION';
    if (text.includes('status')) return 'IDP_ERROR';
    return 'INVALID';
}

module.exports = new SamlService();
module.exports.SsoError = SsoError;
module.exports.classify = classify;
