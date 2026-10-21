const net = require('net');

// Normalización de IPs para usarlas como clave de límites y bloqueos.
//
//  - "::ffff:1.2.3.4" (IPv4 dentro de IPv6) se convierte en "1.2.3.4".
//  - Un cliente IPv6 suele controlar un /64 entero y puede rotar de dirección a voluntad, así que
//    para limitar y bloquear se usa el prefijo /64 ("2001:db8:0:1::/64"), no la dirección suelta.

function normalizeIp(raw) {
    if (typeof raw !== 'string') return 'unknown';
    let ip = raw.trim().toLowerCase().split('%')[0]; // sin zona ("fe80::1%eth0")
    if (ip.startsWith('::ffff:') && net.isIPv4(ip.slice(7))) ip = ip.slice(7);
    return net.isIP(ip) ? ip : 'unknown';
}

function expandIpv6(ip) {
    const [head, tail = ''] = ip.split('::');
    const headParts = head ? head.split(':') : [];
    const tailParts = tail ? tail.split(':') : [];

    // IPv4 incrustada al final (::ffff:1.2.3.4 ya se trató; aquí cubrimos "64:ff9b::1.2.3.4")
    const last = (tailParts.length ? tailParts : headParts).at(-1);
    if (last && last.includes('.')) {
        const octets = last.split('.').map(Number);
        const converted = [((octets[0] << 8) | octets[1]).toString(16), ((octets[2] << 8) | octets[3]).toString(16)];
        (tailParts.length ? tailParts : headParts).splice(-1, 1, ...converted);
    }

    const missing = 8 - headParts.length - tailParts.length;
    const groups = ip.includes('::')
        ? [...headParts, ...Array(Math.max(missing, 0)).fill('0'), ...tailParts]
        : headParts;
    return groups.map(g => g.padStart(4, '0'));
}

// Clave estable por "origen": la IPv4 tal cual, o el /64 en IPv6
function ipSubject(raw) {
    const ip = normalizeIp(raw);
    if (net.isIPv6(ip)) {
        const groups = expandIpv6(ip);
        return `${groups.slice(0, 4).map(g => g.replace(/^0+(?=.)/, '')).join(':')}::/64`;
    }
    return ip;
}

function isLoopback(raw) {
    const ip = normalizeIp(raw);
    return ip === '::1' || ip.startsWith('127.');
}

// IPs que jamás se bloquean automáticamente: loopback y las de PROTECTION_ALLOWLIST (separadas por comas).
// Evita que un proxy mal configurado (todas las peticiones llegan con su IP) se bloquee a sí mismo.
function isNeverBlocked(raw) {
    if (isLoopback(raw)) return true;
    const allow = (process.env.PROTECTION_ALLOWLIST || '').split(',').map(s => s.trim()).filter(Boolean);
    return allow.includes(normalizeIp(raw)) || allow.includes(ipSubject(raw));
}

module.exports = { normalizeIp, ipSubject, isLoopback, isNeverBlocked };
