// Autenticador WebAuthn SOFTWARE para las pruebas: hace exactamente lo que una llave de seguridad o una passkey
// (CBOR, clave COSE, datos del autenticador, firma ES256 sobre authData || SHA-256(clientDataJSON)), de modo que el
// servidor verifica criptografía real, no un doble. Con parámetros para fabricar respuestas MALAS (origen falso,
// reto ajeno, contador que retrocede, firma manipulada...).

const crypto = require('crypto');

const sha256 = (data) => crypto.createHash('sha256').update(data).digest();
const b64u = (buffer) => Buffer.from(buffer).toString('base64url');

// CBOR mínimo (enteros, bytes, texto, arrays, mapas): lo que necesitan attestationObject y la clave COSE
function cbor(value) {
    const head = (major, n) => {
        if (n < 24) return Buffer.from([(major << 5) | n]);
        if (n < 256) return Buffer.from([(major << 5) | 24, n]);
        if (n < 65536) { const b = Buffer.alloc(3); b[0] = (major << 5) | 25; b.writeUInt16BE(n, 1); return b; }
        const b = Buffer.alloc(5); b[0] = (major << 5) | 26; b.writeUInt32BE(n, 1); return b;
    };
    if (Buffer.isBuffer(value) || value instanceof Uint8Array) return Buffer.concat([head(2, value.length), Buffer.from(value)]);
    if (typeof value === 'string') { const b = Buffer.from(value, 'utf8'); return Buffer.concat([head(3, b.length), b]); }
    if (Number.isInteger(value)) return value >= 0 ? head(0, value) : head(1, -1 - value);
    if (Array.isArray(value)) return Buffer.concat([head(4, value.length), ...value.map(cbor)]);
    const entries = value instanceof Map ? [...value] : Object.entries(value);
    return Buffer.concat([head(5, entries.length), ...entries.flatMap(([k, v]) => [cbor(k), cbor(v)])]);
}

const FLAG = { UP: 0x01, UV: 0x04, BE: 0x08, BS: 0x10, AT: 0x40 };

class SoftAuthenticator {
    constructor({ origin = 'http://localhost:5173', rpId = 'localhost', userVerified = true, multiDevice = false, backedUp = false } = {}) {
        this.origin = origin;
        this.rpId = rpId;
        this.userVerified = userVerified;
        this.multiDevice = multiDevice;
        this.backedUp = backedUp;
        this.counter = 0;
        this.credentialId = crypto.randomBytes(32);
        const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    get id() { return b64u(this.credentialId); }

    coseKey() {
        const jwk = this.publicKey.export({ format: 'jwk' });
        return cbor(new Map([[1, 2], [3, -7], [-1, 1], [-2, Buffer.from(jwk.x, 'base64url')], [-3, Buffer.from(jwk.y, 'base64url')]]));
    }

    flags({ uv = this.userVerified, attested = false } = {}) {
        return FLAG.UP | (uv ? FLAG.UV : 0) | (attested ? FLAG.AT : 0) | (this.multiDevice ? FLAG.BE : 0) | (this.multiDevice && this.backedUp ? FLAG.BS : 0);
    }

    clientData(type, challenge, origin) {
        return Buffer.from(JSON.stringify({ type, challenge, origin, crossOrigin: false }));
    }

    // options: lo que devolvió el servidor (PublicKeyCredentialCreationOptionsJSON)
    register(options, { origin = this.origin, rpId = this.rpId, challenge = options.challenge, uv } = {}) {
        const rpIdHash = sha256(rpId);
        const counter = Buffer.alloc(4);
        counter.writeUInt32BE(this.counter);
        const credentialData = Buffer.concat([Buffer.alloc(16), Buffer.from([this.credentialId.length >> 8, this.credentialId.length & 255]), this.credentialId, this.coseKey()]);
        const authData = Buffer.concat([rpIdHash, Buffer.from([this.flags({ uv, attested: true })]), counter, credentialData]);
        const attestationObject = cbor(new Map([['fmt', 'none'], ['attStmt', new Map()], ['authData', authData]]));

        return {
            id: this.id, rawId: this.id, type: 'public-key', authenticatorAttachment: 'platform', clientExtensionResults: {},
            response: { clientDataJSON: b64u(this.clientData('webauthn.create', challenge, origin)), attestationObject: b64u(attestationObject), transports: ['internal'] }
        };
    }

    // options: PublicKeyCredentialRequestOptionsJSON. `counter`: fuerza el contador que se declara (para simular una copia).
    assert(options, { origin = this.origin, rpId = this.rpId, challenge = options.challenge, uv, counter, tamper = false, credentialId = this.credentialId } = {}) {
        if (counter === undefined) this.counter += 1; else this.counter = counter;
        const counterBuf = Buffer.alloc(4);
        counterBuf.writeUInt32BE(this.counter);
        const authData = Buffer.concat([sha256(rpId), Buffer.from([this.flags({ uv })]), counterBuf]);
        const clientDataJSON = this.clientData('webauthn.get', challenge, origin);
        let signature = crypto.sign('sha256', Buffer.concat([authData, sha256(clientDataJSON)]), this.privateKey);
        if (tamper) { signature = Buffer.from(signature); signature[signature.length - 1] ^= 0xff; }

        return {
            id: b64u(credentialId), rawId: b64u(credentialId), type: 'public-key', clientExtensionResults: {},
            response: { clientDataJSON: b64u(clientDataJSON), authenticatorData: b64u(authData), signature: b64u(signature) }
        };
    }
}

module.exports = { SoftAuthenticator, cbor, b64u };
