const crypto = require('crypto');

// TOTP (RFC 6238) sobre HOTP (RFC 4226), HMAC-SHA1, sin dependencias. Compatible con Google Authenticator,
// Microsoft Authenticator, Authy, 1Password, Bitwarden, etc. Verificado con los vectores de prueba del RFC.

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32Encode(buffer) {
    let bits = 0, value = 0, out = '';
    for (const byte of buffer) {
        value = (value << 8) | byte;
        bits += 8;
        while (bits >= 5) { out += ALPHABET[(value >>> (bits - 5)) & 31]; bits -= 5; }
    }
    if (bits > 0) out += ALPHABET[(value << (5 - bits)) & 31];
    return out;
}

function base32Decode(text) {
    const clean = String(text).toUpperCase().replace(/[\s=-]/g, '');
    let bits = 0, value = 0;
    const out = [];
    for (const char of clean) {
        const index = ALPHABET.indexOf(char);
        if (index === -1) throw new Error('Base32 inválido');
        value = (value << 5) | index;
        bits += 5;
        if (bits >= 8) { out.push((value >>> (bits - 8)) & 255); bits -= 8; }
    }
    return Buffer.from(out);
}

// 160 bits (el tamaño que recomienda el RFC 4226) codificados en base32
const generateSecret = () => base32Encode(crypto.randomBytes(20));

function hotp(secretBase32, counter, digits = 6) {
    const message = Buffer.alloc(8);
    message.writeBigUInt64BE(BigInt(counter));
    const hmac = crypto.createHmac('sha1', base32Decode(secretBase32)).update(message).digest();
    const offset = hmac[hmac.length - 1] & 0x0f;
    const code = ((hmac[offset] & 0x7f) << 24) | (hmac[offset + 1] << 16) | (hmac[offset + 2] << 8) | hmac[offset + 3];
    return String(code % 10 ** digits).padStart(digits, '0');
}

const stepOf = (timeMs = Date.now(), stepSeconds = 30) => Math.floor(timeMs / 1000 / stepSeconds);
const totp = (secret, { timeMs = Date.now(), stepSeconds = 30, digits = 6 } = {}) => hotp(secret, stepOf(timeMs, stepSeconds), digits);

// Comprueba un código admitiendo `window` pasos de desfase de reloj a cada lado (por defecto ±1 = ±30 s).
// `lastStep` es el último paso ya aceptado para ese usuario: un código de un paso igual o anterior se
// rechaza (anti-reutilización). Devuelve { ok, step } con el paso que coincidió.
function verifyTotp(secret, token, { timeMs = Date.now(), window = 1, stepSeconds = 30, digits = 6, lastStep = null } = {}) {
    if (typeof token !== 'string' || token.length !== digits || !/^\d+$/.test(token)) return { ok: false };

    const current = stepOf(timeMs, stepSeconds);
    let matched = null;
    // Se recorren TODOS los pasos sin cortar al primer acierto (tiempo constante frente al desfase)
    for (let step = current - window; step <= current + window; step++) {
        const expected = Buffer.from(hotp(secret, step, digits));
        if (crypto.timingSafeEqual(expected, Buffer.from(token)) && matched === null) matched = step;
    }
    if (matched === null) return { ok: false };
    if (lastStep !== null && lastStep !== undefined && matched <= Number(lastStep)) return { ok: false, replay: true };
    return { ok: true, step: matched };
}

const otpauthUrl = ({ secret, account, issuer }) =>
    `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(account)}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;

// Códigos de recuperación: 80 bits de entropía (XXXX-XXXX-XXXX-XXXX). Con tanta entropía basta un hash
// rápido: no se pueden adivinar ni por fuerza bruta offline.
function generateRecoveryCode() {
    const raw = base32Encode(crypto.randomBytes(10)); // 16 caracteres
    return raw.match(/.{4}/g).join('-');
}
const normalizeRecoveryCode = (code) => String(code).toUpperCase().replace(/[^A-Z2-7]/g, '');
const hashRecoveryCode = (code) => crypto.createHash('sha256').update(`recovery:${normalizeRecoveryCode(code)}`).digest('hex');

module.exports = {
    base32Encode, base32Decode, generateSecret, hotp, totp, verifyTotp, stepOf, otpauthUrl,
    generateRecoveryCode, normalizeRecoveryCode, hashRecoveryCode
};
