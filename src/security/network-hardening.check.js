const fs = require('fs');

// Evalúa la "postura de red" del proceso/host frente a canales encubiertos ICMP.
// Es solo lectura: reporta qué puede hacer este proceso, no cambia nada.
//
// Un atacante que ejecuta `ping -p` desde nuestro servidor necesita:
//   1. ejecutar el binario ping (o abrir un socket raw), y
//   2. que el kernel le deje hacer ping: CAP_NET_RAW, o net.ipv4.ping_group_range abierto.
// Quitar ambas cosas deja al proceso comprometido sin poder emitir ICMP.

const CAP_NET_RAW_BIT = 13;

function hasCapNetRaw(procStatusText) {
    const match = /^CapEff:\s*([0-9a-f]+)/im.exec(procStatusText || '');
    if (!match) return null;
    return ((BigInt('0x' + match[1]) >> BigInt(CAP_NET_RAW_BIT)) & 1n) === 1n;
}

// net.ipv4.ping_group_range = "lo hi": los gids en [lo, hi] pueden hacer ping sin privilegios.
// "1 0" (lo > hi) lo desactiva para todos.
function pingGroupRangeMode(text) {
    const parts = (text || '').trim().split(/\s+/).map(Number);
    if (parts.length !== 2 || parts.some(Number.isNaN)) return 'unknown';
    const [lo, hi] = parts;
    if (lo > hi) return 'disabled';
    if (lo <= 0 && hi >= 2147483647) return 'open_to_all';
    return 'restricted';
}

function readFileSafe(path) {
    try {
        return fs.readFileSync(path, 'utf8');
    } catch {
        return null;
    }
}

function getNetworkPosture({ platform = process.platform, read = readFileSafe, uid = process.getuid?.() } = {}) {
    if (platform !== 'linux') {
        return {
            platform,
            supported: false,
            recommendations: ['La comprobación de postura de red solo está implementada para Linux']
        };
    }

    const capNetRaw = hasCapNetRaw(read('/proc/self/status'));
    const pingRange = pingGroupRangeMode(read('/proc/sys/net/ipv4/ping_group_range'));
    const echoIgnoreAll = (read('/proc/sys/net/ipv4/icmp_echo_ignore_all') || '').trim() === '1';

    const recommendations = [];
    if (capNetRaw) {
        recommendations.push('El proceso tiene CAP_NET_RAW: quítala (docker --cap-drop NET_RAW, o CapabilityBoundingSet=~CAP_NET_RAW en systemd)');
    }
    if (pingRange === 'open_to_all') {
        recommendations.push('net.ipv4.ping_group_range permite ping a cualquier usuario: usa `sysctl -w net.ipv4.ping_group_range="1 0"`');
    }
    if (uid === 0) {
        recommendations.push('El servidor corre como root: usa un usuario sin privilegios');
    }

    return {
        platform,
        supported: true,
        runningAsRoot: uid === 0,
        capNetRaw,
        unprivilegedPing: pingRange,
        icmpEchoIgnoreAll: echoIgnoreAll,
        hardened: capNetRaw === false && pingRange === 'disabled',
        recommendations
    };
}

module.exports = { getNetworkPosture, hasCapNetRaw, pingGroupRangeMode };
