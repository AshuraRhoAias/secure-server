// Proveedor de identidad SAML SIMULADO para las pruebas. Firma de verdad (XML-DSig RSA-SHA256, c14n exclusiva) con una clave
// que genera `openssl` al arrancar, de modo que el servidor verifica criptografía real, no un doble. Con opciones para
// fabricar respuestas MALAS: sin firma, firmadas con otra clave, manipuladas tras firmar, "signature wrapping", audiencia o
// destinatario falsos, caducadas, repetidas, sin InResponseTo (IdP-initiated)...

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const zlib = require('zlib');
const { execFileSync } = require('child_process');
const { SignedXml } = require('xml-crypto');

const C14N = 'http://www.w3.org/2001/10/xml-exc-c14n#';
const ENVELOPED = 'http://www.w3.org/2000/09/xmldsig#enveloped-signature';

function newKeyPair(commonName) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mock-idp-'));
    try {
        execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', path.join(dir, 'key.pem'), '-out', path.join(dir, 'cert.pem'),
            '-days', '2', '-subj', `/CN=${commonName}`], { stdio: 'ignore' });
        return { privateKey: fs.readFileSync(path.join(dir, 'key.pem'), 'utf8'), cert: fs.readFileSync(path.join(dir, 'cert.pem'), 'utf8') };
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
}

const iso = (ms) => new Date(ms).toISOString();
const xmlEscape = (value) => String(value).replace(/[<>&"']/g, c => ({ '<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;', "'": '&apos;' }[c]));

class MockSamlIdp {
    constructor({ entityId = 'https://idp.test/metadata', ssoUrl = 'https://idp.test/sso' } = {}) {
        this.entityId = entityId;
        this.ssoUrl = ssoUrl;
        this.key = newKeyPair('mock-idp');
        this.rogue = newKeyPair('atacante');        // otra clave: quien NO es el IdP
    }

    get cert() { return this.key.cert; }

    // Lo que el SP mandó al IdP: ?SAMLRequest=<deflate+base64>
    parseAuthnRequest(location) {
        const url = new URL(location);
        const xml = zlib.inflateRawSync(Buffer.from(url.searchParams.get('SAMLRequest'), 'base64')).toString('utf8');
        return {
            xml,
            id: /\bID="([^"]+)"/.exec(xml)?.[1],
            acs: /AssertionConsumerServiceURL="([^"]+)"/.exec(xml)?.[1],
            issuer: /<saml:Issuer[^>]*>([^<]+)<\/saml:Issuer>/.exec(xml)?.[1],
            url
        };
    }

    sign(xml, xpath, keyPair, locationRef) {
        const sig = new SignedXml({ privateKey: keyPair.privateKey, publicCert: keyPair.cert, canonicalizationAlgorithm: C14N, signatureAlgorithm: 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256' });
        sig.addReference({ xpath, transforms: [ENVELOPED, C14N], digestAlgorithm: 'http://www.w3.org/2001/04/xmlenc#sha256' });
        sig.computeSignature(xml, { location: { reference: locationRef, action: 'after' } });
        return sig.getSignedXml();
    }

    // Construye una respuesta. `request` = { id, acs } de parseAuthnRequest. Devuelve el XML y su base64.
    response(request, o = {}) {
        const now = Date.now();
        const acs = o.recipient ?? request?.acs;
        const inResponseTo = o.inResponseTo === undefined ? request?.id : o.inResponseTo;
        const issuer = o.issuer ?? this.entityId;
        const attrs = { email: o.email ?? 'persona@ejemplo.com', ...(o.attributes || {}) };
        const assertionId = o.assertionId ?? `_a${crypto.randomBytes(8).toString('hex')}`;
        const responseId = `_r${crypto.randomBytes(8).toString('hex')}`;
        const statusCode = o.statusCode ?? 'urn:oasis:names:tc:SAML:2.0:status:Success';
        const attributeXml = Object.entries(attrs).map(([name, value]) =>
            `<saml:Attribute Name="${xmlEscape(name)}">${(Array.isArray(value) ? value : [value]).map(v => `<saml:AttributeValue xsi:type="xs:string">${xmlEscape(v)}</saml:AttributeValue>`).join('')}</saml:Attribute>`).join('');

        const assertion = `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" ID="${assertionId}" Version="2.0" IssueInstant="${iso(o.issueInstant ?? now)}">` +
            `<saml:Issuer>${xmlEscape(o.assertionIssuer ?? issuer)}</saml:Issuer>` +
            `<saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">${xmlEscape(o.nameId ?? 'usuario-0001')}</saml:NameID>` +
            `<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="${iso(o.confirmationNotOnOrAfter ?? now + 5 * 60_000)}" Recipient="${xmlEscape(acs)}"${inResponseTo ? ` InResponseTo="${xmlEscape(inResponseTo)}"` : ''}/></saml:SubjectConfirmation></saml:Subject>` +
            `<saml:Conditions NotBefore="${iso(o.notBefore ?? now - 30_000)}" NotOnOrAfter="${iso(o.notOnOrAfter ?? now + 5 * 60_000)}"><saml:AudienceRestriction><saml:Audience>${xmlEscape(o.audience)}</saml:Audience></saml:AudienceRestriction></saml:Conditions>` +
            `<saml:AuthnStatement AuthnInstant="${iso(o.authnInstant ?? now - 5_000)}" SessionIndex="_s${assertionId}"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>` +
            `<saml:AttributeStatement>${attributeXml}</saml:AttributeStatement></saml:Assertion>`;

        const wrap = (inner) => `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${responseId}" Version="2.0" IssueInstant="${iso(now)}" Destination="${xmlEscape(o.destination ?? acs)}"${inResponseTo ? ` InResponseTo="${xmlEscape(inResponseTo)}"` : ''}>` +
            `<saml:Issuer>${xmlEscape(issuer)}</saml:Issuer><samlp:Status><samlp:StatusCode Value="${statusCode}"/></samlp:Status>${inner}</samlp:Response>`;

        const signer = o.signWith === 'rogue' ? this.rogue : this.key;
        const mode = o.sign ?? 'assertion';   // assertion | response | both | none

        let signedAssertion = assertion;
        if (mode === 'assertion' || mode === 'both') {
            signedAssertion = this.sign(assertion, "//*[local-name(.)='Assertion']", signer, "//*[local-name(.)='Assertion']/*[local-name(.)='Issuer']");
        }
        let xml = wrap(signedAssertion);
        if (mode === 'response' || mode === 'both') {
            xml = this.sign(xml, "/*[local-name(.)='Response']", signer, "/*[local-name(.)='Response']/*[local-name(.)='Issuer']");
        }

        // Manipulaciones DESPUÉS de firmar
        if (o.tamper) xml = o.tamper(xml);
        return { xml, base64: Buffer.from(xml, 'utf8').toString('base64'), assertionId, assertion };
    }
}

module.exports = { MockSamlIdp };
