// Tests de la defensa contra canales encubiertos ICMP (ping -p). No necesitan red, BD ni privilegios.
//
//   npm run test:icmp

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

const { IcmpCovertChannelDetector, analyzePayload } = require('./src/security/icmp-covert-channel.service');
const { TcpdumpParser } = require('./src/security/tcpdump-parser');
const { getNetworkPosture, hasCapNetRaw, pingGroupRangeMode } = require('./src/security/network-hardening.check');

// ---------- Generadores de payloads (replican el relleno de iputils / Windows) ----------

// Ping estándar de Linux: timestamp de 16 bytes + 0x10..0x37
const linuxPayload = () => Buffer.concat([crypto.randomBytes(16), Buffer.from(Array.from({ length: 40 }, (_, i) => 0x10 + i))]);

// Ping estándar de BSD/macOS/Linux antiguo: timestamp de 8 bytes + 0x08..0x37
const bsdPayload = () => Buffer.concat([crypto.randomBytes(8), Buffer.from(Array.from({ length: 48 }, (_, i) => 0x08 + i))]);

const windowsPayload = () => Buffer.from('abcdefghijklmnopqrstuvwabcdefghi');

// `ping -p <hex>`: el patrón se repite sobre todo el payload y el timestamp pisa los primeros bytes
function pingPatternPayload(hexPattern, { size = 56, timestamp = 16 } = {}) {
    const pattern = Buffer.from(hexPattern, 'hex');
    const data = Buffer.alloc(size);
    for (let i = 0; i < size; i++) data[i] = pattern[i % pattern.length];
    crypto.randomBytes(timestamp).copy(data, 0);
    return data;
}

// Un "archivo" troceado en patrones de 16 bytes distintos, como haría la herramienta del atacante
const chunk = (n) => crypto.createHash('md5').update(`archivo-secreto-${n}`).digest('hex'); // 16 bytes

const LOCAL = '10.0.0.5';
const REMOTE = '203.0.113.7';
const T0 = 1_700_000_000_000;

function request(src, dst, payload, time, seq = 1) {
    return { time, src, dst, type: 'echo-request', id: 7, seq, payload };
}

function newDetector(options = {}) {
    return new IcmpCovertChannelDetector({ localIps: [LOCAL], ...options });
}

// ---------- analyzePayload ----------

test('el relleno estándar de Linux, BSD y Windows no se marca', () => {
    assert.strictEqual(analyzePayload(linuxPayload()).standard, 'linux');
    assert.strictEqual(analyzePayload(bsdPayload()).standard, 'linux');
    assert.strictEqual(analyzePayload(windowsPayload()).standard, 'windows');
    assert.strictEqual(analyzePayload(Buffer.alloc(0)).standard, 'empty');
});

test('un payload de `ping -p` se detecta con su periodo y patrón', () => {
    const a = analyzePayload(pingPatternPayload('deadbeefcafe0123'));
    assert.strictEqual(a.standard, null);
    assert.strictEqual(a.period, 8);
    assert.ok(a.patternKey);

    assert.strictEqual(analyzePayload(pingPatternPayload(chunk(1))).period, 16);
    assert.strictEqual(analyzePayload(pingPatternPayload('ff')).period, 1);
});

test('el mismo patrón da la misma clave con timestamp de 8 o 16 bytes y con desfase', () => {
    const a = analyzePayload(pingPatternPayload('aabbccddee', { size: 56, timestamp: 16 }));
    const b = analyzePayload(pingPatternPayload('aabbccddee', { size: 64, timestamp: 8 }));
    assert.strictEqual(a.period, 5);
    assert.strictEqual(a.patternKey, b.patternKey);
});

test('datos aleatorios (túnel ICMP, datos cifrados) se marcan como alta entropía', () => {
    const a = analyzePayload(crypto.randomBytes(56));
    assert.strictEqual(a.standard, null);
    assert.strictEqual(a.period, null);
    assert.strictEqual(a.highEntropy, true);
});

test('payloads diminutos usan el payload completo como patrón', () => {
    const a = analyzePayload(Buffer.from('c0ffee', 'hex'));
    assert.strictEqual(a.standard, null);
    assert.strictEqual(a.patternKey, 'c0ffee');
});

// ---------- Detector ----------

test('miles de pings normales no generan alertas', () => {
    const d = newDetector();
    for (let i = 0; i < 1000; i++) {
        assert.strictEqual(d.observe(request(LOCAL, '8.8.8.8', i % 2 ? linuxPayload() : windowsPayload(), T0 + i * 1000, i)), null);
    }
    assert.strictEqual(d.getStats().standard, 1000);
    assert.strictEqual(d.getStats().alerts, 0);
});

test('archivo troceado en patrones distintos: alerta high y luego critical (egress)', () => {
    const d = newDetector();
    const alerts = [];

    for (let i = 0; i < 24; i++) {
        const alert = d.observe(request(LOCAL, REMOTE, pingPatternPayload(chunk(i)), T0 + i * 1000, i));
        if (alert) alerts.push({ n: i + 1, alert });
    }

    assert.deepStrictEqual(alerts.map(a => [a.n, a.alert.level]), [[8, 'high'], [20, 'critical']]);
    assert.strictEqual(alerts[0].alert.direction, 'egress');
    assert.strictEqual(alerts[0].alert.reasons[0].code, 'PATTERN_STEPPING');
    assert.strictEqual(alerts[0].alert.samplePatterns.length, 5);
});

test('exfiltración lenta ("poco a poco"): un trozo cada 5 min acaba en alerta SLOW_PATTERN_STEPPING', () => {
    const d = newDetector();
    let alert = null;
    let n = 0;

    while (!alert && n < 200) {
        alert = d.observe(request(LOCAL, REMOTE, pingPatternPayload(chunk(n)), T0 + n * 5 * 60 * 1000, n));
        n++;
    }

    assert.ok(alert, 'debería haber alertado');
    assert.strictEqual(alert.level, 'high');
    assert.strictEqual(alert.reasons[0].code, 'SLOW_PATTERN_STEPPING');
    assert.strictEqual(n, 40);
});

test('el mismo patrón repetido en ráfaga es solo un flood (medium), no exfiltración', () => {
    const d = newDetector();
    const alerts = [];
    for (let i = 0; i < 100; i++) {
        const a = d.observe(request(LOCAL, REMOTE, pingPatternPayload('ff'), T0 + i * 100, i));
        if (a) alerts.push(a);
    }
    assert.strictEqual(alerts.length, 1);
    assert.strictEqual(alerts[0].level, 'medium');
    assert.strictEqual(alerts[0].reasons[0].code, 'NON_STANDARD_FLOOD');
});

test('payloads grandes y no estándar disparan OVERSIZED_PAYLOAD', () => {
    const d = newDetector();
    let alert = null;
    for (let i = 0; i < 3; i++) alert = d.observe(request(REMOTE, LOCAL, crypto.randomBytes(300), T0 + i * 1000, i)) || alert;

    assert.ok(alert);
    assert.strictEqual(alert.level, 'high');
    assert.strictEqual(alert.direction, 'ingress');
    assert.ok(alert.reasons.some(r => r.code === 'OVERSIZED_PAYLOAD'));
});

test('muchos payloads de alta entropía disparan HIGH_ENTROPY_PAYLOAD', () => {
    const d = newDetector();
    let alert = null;
    for (let i = 0; i < 5; i++) alert = d.observe(request(LOCAL, REMOTE, crypto.randomBytes(56), T0 + i * 1000, i)) || alert;

    assert.ok(alert);
    assert.ok(alert.reasons.some(r => r.code === 'HIGH_ENTROPY_PAYLOAD'));
});

test('las IPs de la allowlist (monitoreo legítimo) se ignoran', () => {
    const d = newDetector({ allowlist: [REMOTE] });
    for (let i = 0; i < 50; i++) {
        assert.strictEqual(d.observe(request(LOCAL, REMOTE, pingPatternPayload(chunk(i)), T0 + i * 1000, i)), null);
    }
    assert.strictEqual(d.getStats().alerts, 0);
});

test('un echo-reply que refleja el request no cuenta; uno alterado es sospechoso', () => {
    const d = newDetector();
    const payload = pingPatternPayload('deadbeefcafe0123');

    d.observe(request(LOCAL, REMOTE, payload, T0, 1));
    const mirrored = d.observe({ time: T0 + 10, src: REMOTE, dst: LOCAL, type: 'echo-reply', id: 7, seq: 1, payload });
    assert.strictEqual(mirrored, null);
    assert.strictEqual(d.getStats().tamperedReplies, 0);

    d.observe(request(LOCAL, REMOTE, linuxPayload(), T0 + 1000, 2));
    const tampered = d.observe({
        time: T0 + 1010, src: REMOTE, dst: LOCAL, type: 'echo-reply', id: 7, seq: 2,
        payload: pingPatternPayload(chunk(99))
    });
    assert.ok(tampered);
    assert.strictEqual(tampered.level, 'high');
    assert.strictEqual(tampered.reasons[0].code, 'MODIFIED_REPLY');
    assert.strictEqual(d.getStats().tamperedReplies, 1);
});

test('los patrones fuera de la ventana corta no se acumulan', () => {
    const d = newDetector();
    for (let i = 0; i < 7; i++) d.observe(request(LOCAL, REMOTE, pingPatternPayload(chunk(i)), T0 + i * 1000, i));

    const later = T0 + 11 * 60 * 1000;
    let alert = null;
    for (let i = 7; i < 14; i++) alert = d.observe(request(LOCAL, REMOTE, pingPatternPayload(chunk(i)), later + i * 1000, i)) || alert;

    assert.strictEqual(alert, null);
});

test('no repite la alerta del mismo nivel hasta pasar el cooldown', () => {
    const d = newDetector();
    const raised = [];
    const burst = (start, base) => {
        for (let i = 0; i < 8; i++) {
            const a = d.observe(request(LOCAL, REMOTE, pingPatternPayload(chunk(base + i)), start + i * 1000, base + i));
            if (a) raised.push(a.level);
        }
    };

    burst(T0, 0);                              // alerta high
    burst(T0 + 60 * 1000, 100);                // dentro del cooldown: nada (sigue siendo high)
    burst(T0 + 31 * 60 * 1000, 200);           // pasado el cooldown: vuelve a avisar

    assert.deepStrictEqual(raised, ['high', 'high']);
});

test('la memoria del detector está acotada (maxFlows)', () => {
    const d = newDetector({ maxFlows: 50 });
    for (let i = 0; i < 500; i++) {
        d.observe(request(`198.51.100.${i % 250}`, `192.0.2.${Math.floor(i / 250)}`, pingPatternPayload(chunk(i)), T0 + i, i));
        d.observe(request(`10.1.${Math.floor(i / 250)}.${i % 250}`, REMOTE, pingPatternPayload(chunk(i)), T0 + i, i));
    }
    assert.ok(d.getStats().trackedFlows <= 51, `flujos: ${d.getStats().trackedFlows}`);
});

// ---------- Parser de tcpdump ----------

function tcpdumpText({ header, payload }) {
    const ip = Buffer.from('4500005400004000400100007f0000017f000001', 'hex');
    const icmp = Buffer.from('0800000000070001', 'hex');
    const hex = Buffer.concat([ip, icmp, payload]).toString('hex');
    const lines = [];
    for (let off = 0; off < hex.length; off += 32) {
        const groups = hex.slice(off, off + 32).match(/.{1,4}/g).join(' ');
        lines.push(`\t0x${(off / 2).toString(16).padStart(4, '0')}:  ${groups}`);
    }
    return [header, ...lines].join('\n');
}

test('el parser reconstruye src, dst, tipo, id/seq y el payload', () => {
    const payload = pingPatternPayload('deadbeefcafe0123');
    const text = [
        tcpdumpText({ header: '1700000000.123456 IP 10.0.0.5 > 203.0.113.7: ICMP echo request, id 7, seq 1, length 64', payload }),
        tcpdumpText({ header: '1700000001.500000 eth0  Out IP 10.0.0.5 > 203.0.113.7: ICMP echo reply, id 7, seq 2, length 64', payload: linuxPayload() })
    ].join('\n');

    const packets = [];
    const parser = new TcpdumpParser(p => packets.push(p));
    text.split('\n').forEach(line => parser.push(line));
    parser.flush();

    assert.strictEqual(packets.length, 2);
    assert.deepStrictEqual(
        { ...packets[0], payload: undefined },
        { time: 1700000000123, src: '10.0.0.5', dst: '203.0.113.7', type: 'echo-request', id: 7, seq: 1, payload: undefined }
    );
    assert.ok(packets[0].payload.equals(payload));
    assert.strictEqual(packets[1].type, 'echo-reply');
    assert.strictEqual(packets[1].payload.length, 56);
});

test('parser + detector: una captura con exfiltración genera la alerta', () => {
    const text = Array.from({ length: 10 }, (_, i) => tcpdumpText({
        header: `${1700000000 + i}.000000 IP 10.0.0.5 > 203.0.113.7: ICMP echo request, id 7, seq ${i}, length 64`,
        payload: pingPatternPayload(chunk(i))
    })).join('\n');

    const d = newDetector();
    const alerts = [];
    const parser = new TcpdumpParser(p => { const a = d.observe(p); if (a) alerts.push(a); });
    text.split('\n').forEach(line => parser.push(line));
    parser.flush();

    assert.strictEqual(alerts.length, 1);
    assert.strictEqual(alerts[0].level, 'high');
});

// ---------- Postura de red del host ----------

test('hasCapNetRaw lee el bit 13 de CapEff', () => {
    assert.strictEqual(hasCapNetRaw('Name:\tnode\nCapEff:\t00000000a80425fb\n'), true);   // docker por defecto
    assert.strictEqual(hasCapNetRaw('Name:\tnode\nCapEff:\t00000000a80405fb\n'), false);  // con --cap-drop NET_RAW
    assert.strictEqual(hasCapNetRaw('Name:\tnode\nCapEff:\t0000000000000000\n'), false);
    assert.strictEqual(hasCapNetRaw('sin datos'), null);
});

test('pingGroupRangeMode interpreta net.ipv4.ping_group_range', () => {
    assert.strictEqual(pingGroupRangeMode('1\t0\n'), 'disabled');
    assert.strictEqual(pingGroupRangeMode('0 2147483647'), 'open_to_all');
    assert.strictEqual(pingGroupRangeMode('0 4294967294'), 'open_to_all');
    assert.strictEqual(pingGroupRangeMode('1000 1000'), 'restricted');
    assert.strictEqual(pingGroupRangeMode('basura'), 'unknown');
});

test('getNetworkPosture: endurecido vs. abierto', () => {
    const files = (cap, range) => (file) => ({
        '/proc/self/status': `CapEff:\t${cap}\n`,
        '/proc/sys/net/ipv4/ping_group_range': range,
        '/proc/sys/net/ipv4/icmp_echo_ignore_all': '0\n'
    })[file] ?? null;

    const hardened = getNetworkPosture({ platform: 'linux', uid: 1000, read: files('0000000000000000', '1 0') });
    assert.strictEqual(hardened.hardened, true);
    assert.deepStrictEqual(hardened.recommendations, []);

    const open = getNetworkPosture({ platform: 'linux', uid: 0, read: files('00000000a80425fb', '0 2147483647') });
    assert.strictEqual(open.hardened, false);
    assert.strictEqual(open.recommendations.length, 3);

    assert.strictEqual(getNetworkPosture({ platform: 'win32' }).supported, false);
});

// ---------- Guardas estáticas ----------

test('el servidor (src/) nunca ejecuta procesos externos: sin child_process', () => {
    const offenders = [];
    const walk = (dir) => {
        for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
            const full = path.join(dir, entry.name);
            if (entry.isDirectory()) walk(full);
            else if (entry.name.endsWith('.js') && /child_process|\bexecSync\b|\bspawnSync\b/.test(fs.readFileSync(full, 'utf8'))) {
                offenders.push(path.relative(__dirname, full));
            }
        }
    };
    walk(path.join(__dirname, 'src'));
    assert.deepStrictEqual(offenders, [], 'src/ no debe lanzar procesos (vector para ejecutar `ping -p`)');
});

// ---------- Monitor de punta a punta ----------

test('scripts/icmpMonitor.js --file --dry-run analiza una captura y avisa', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'icmp-'));
    const file = path.join(tmp, 'captura.txt');
    fs.writeFileSync(file, Array.from({ length: 22 }, (_, i) => tcpdumpText({
        header: `${1700000000 + i}.000000 IP 10.0.0.5 > 203.0.113.7: ICMP echo request, id 7, seq ${i}, length 64`,
        payload: pingPatternPayload(chunk(i))
    })).join('\n'));

    const out = execFileSync('node', [path.join(__dirname, 'scripts/icmpMonitor.js'), '--file', file, '--dry-run'], { encoding: 'utf8' });

    assert.match(out, /\[HIGH\].*PATTERN_STEPPING/);
    assert.match(out, /\[CRITICAL\].*PATTERN_STEPPING/);
    assert.match(out, /22 paquetes, 22 no estándar, 2 alertas/);
    fs.rmSync(tmp, { recursive: true, force: true });
});

test('scripts/icmpMonitor.js rechaza nombres de interfaz peligrosos', () => {
    assert.throws(
        () => execFileSync('node', [path.join(__dirname, 'scripts/icmpMonitor.js'), '--interface', 'eth0; rm -rf /', '--dry-run'], { stdio: 'pipe' }),
        /Nombre de interfaz inválido/
    );
});
