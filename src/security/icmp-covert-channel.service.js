const os = require('os');

// Detector de canales encubiertos por ICMP (exfiltración con `ping -p <patrón> <ip>`).
//
// Cómo funciona el ataque: `ping -p` rellena el payload del echo-request con un patrón de hasta
// 16 bytes repetido. El atacante envía un trozo del archivo como patrón en cada ping y la otra
// máquina, escuchando, reconstruye el archivo a partir de los payloads. Un ping normal NO se
// parece a eso: Linux/macOS/BSD rellenan con bytes incrementales (0x10, 0x11, ...) y Windows con
// el alfabeto ("abcdefghijklmnopqrstuvwabcdefghi").
//
// Qué se detecta:
//   - payload con patrón repetido (periodo <= 16) que no es el relleno estándar de ningún SO
//   - muchos patrones DISTINTOS entre el mismo par de IPs (= datos que "avanzan" ping a ping),
//     tanto en ventana corta (ráfaga) como en ventana larga (goteo lento)
//   - payloads de alta entropía (datos cifrados/comprimidos, p. ej. túneles ICMP)
//   - payloads sobredimensionados no estándar
//   - echo-reply cuyo payload no coincide con el de su request (las pilas legítimas lo reflejan)
//
// Este módulo es puro (no toca red, BD ni disco): recibe paquetes ya capturados.
// scripts/icmpMonitor.js se encarga de capturar (tcpdump) y de actuar sobre las alertas.

const LEVELS = ['none', 'low', 'medium', 'high', 'critical'];
const levelRank = (level) => LEVELS.indexOf(level);

const MAX_PATTERN_BYTES = 16; // límite de `ping -p`
const WINDOWS_PAYLOAD = Buffer.from('abcdefghijklmnopqrstuvwabcdefghi');

function shannonEntropy(buf) {
    if (buf.length === 0) return 0;
    const counts = new Array(256).fill(0);
    for (const byte of buf) counts[byte]++;
    let entropy = 0;
    for (const count of counts) {
        if (count === 0) continue;
        const p = count / buf.length;
        entropy -= p * Math.log2(p);
    }
    return entropy;
}

function isIncrementing(buf, start) {
    if (buf.length < 8) return false;
    for (let i = 0; i < buf.length; i++) {
        if (buf[i] !== ((start + i) & 0xff)) return false;
    }
    return true;
}

// Rotación lexicográficamente menor: el mismo patrón visto con distinto desfase
// (timestamp de 8 o de 16 bytes) produce la misma clave.
function canonicalRotation(unit) {
    let best = null;
    for (let i = 0; i < unit.length; i++) {
        const rotated = Buffer.concat([unit.subarray(i), unit.subarray(0, i)]).toString('hex');
        if (best === null || rotated < best) best = rotated;
    }
    return best;
}

// Menor periodo p <= 16 tal que buf se repite con ese periodo (al menos 2 repeticiones).
function findPeriod(buf) {
    for (let p = 1; p <= MAX_PATTERN_BYTES && buf.length >= p * 2; p++) {
        let repeats = true;
        for (let i = 0; i + p < buf.length; i++) {
            if (buf[i] !== buf[i + p]) { repeats = false; break; }
        }
        if (repeats) return p;
    }
    return null;
}

function analyzePayload(payload) {
    const size = payload.length;
    const result = {
        size,
        standard: null,       // 'linux' | 'windows' | 'empty' | null
        period: null,
        patternKey: null,
        entropy: 0,
        highEntropy: false
    };

    if (size === 0) return { ...result, standard: 'empty' };

    // Relleno estándar de cada SO
    if (size >= 16 && isIncrementing(payload.subarray(16), 0x10)) return { ...result, standard: 'linux' };
    if (size >= 8 && isIncrementing(payload.subarray(8), 0x08)) return { ...result, standard: 'linux' };
    if (size >= 32 && payload.subarray(0, 32).equals(WINDOWS_PAYLOAD)) return { ...result, standard: 'windows' };

    // Zona "libre": tras el timestamp que ping escribe al inicio del payload
    const tail = size >= 32 ? payload.subarray(16) : (size > 16 ? payload.subarray(8) : payload);
    result.entropy = shannonEntropy(tail);

    if (size < 16) {
        // Payload diminuto: el patrón es el payload completo
        result.patternKey = payload.toString('hex');
        return result;
    }

    const period = findPeriod(tail);
    if (period !== null) {
        result.period = period;
        result.patternKey = canonicalRotation(tail.subarray(0, period));
    } else if (tail.length >= 24 && result.entropy >= 4.0) {
        // Sin patrón repetido pero con muchos bytes distintos: datos cifrados o comprimidos
        result.highEntropy = true;
    }

    return result;
}

class IcmpCovertChannelDetector {
    constructor(options = {}) {
        this.options = {
            windowMs: 10 * 60 * 1000,           // ventana de ráfaga
            slowWindowMs: 6 * 60 * 60 * 1000,   // ventana de goteo lento
            highDistinct: 8,
            criticalDistinct: 20,
            slowHighDistinct: 40,
            slowCriticalDistinct: 100,
            highEntropyHigh: 5,
            highEntropyCritical: 15,
            oversizedBytes: 128,
            oversizedHigh: 3,
            oversizedCritical: 10,
            floodPerMinute: 60,
            alertCooldownMs: 30 * 60 * 1000,
            maxEventsPerFlow: 5000,
            maxFlows: 2000,
            allowlist: [],                      // IPs de monitoreo legítimas (se ignoran)
            localIps: null,                     // por defecto, las de las interfaces de esta máquina
            ...options
        };

        this.allowlist = new Set(this.options.allowlist);
        this.localIps = new Set(this.options.localIps || IcmpCovertChannelDetector.discoverLocalIps());
        this.flows = new Map();
        this.pendingRequests = new Map();
        this.counters = { packets: 0, standard: 0, nonStandard: 0, alerts: 0, tamperedReplies: 0 };
    }

    static discoverLocalIps() {
        const ips = [];
        for (const addrs of Object.values(os.networkInterfaces())) {
            for (const addr of addrs || []) ips.push(addr.address);
        }
        return ips;
    }

    direction(src, dst) {
        if (this.localIps.has(src) && !this.localIps.has(dst)) return 'egress';
        if (!this.localIps.has(src) && this.localIps.has(dst)) return 'ingress';
        return 'transit';
    }

    // pkt: { time (ms), src, dst, type: 'echo-request' | 'echo-reply', id, seq, payload: Buffer }
    // Devuelve una alerta cuando el nivel de un flujo sube (o tras el cooldown); si no, null.
    observe(pkt) {
        this.counters.packets++;
        if (this.allowlist.has(pkt.src) || this.allowlist.has(pkt.dst)) return null;

        if (pkt.type === 'echo-reply') return this.observeReply(pkt);

        this.pendingRequests.set(`${pkt.src}>${pkt.dst}:${pkt.id}:${pkt.seq}`, { payload: pkt.payload, time: pkt.time });
        this.prunePending(pkt.time);

        return this.record(pkt, analyzePayload(pkt.payload), []);
    }

    observeReply(pkt) {
        // El reply va en sentido contrario al request
        const key = `${pkt.dst}>${pkt.src}:${pkt.id}:${pkt.seq}`;
        const request = this.pendingRequests.get(key);
        if (!request) return null;
        this.pendingRequests.delete(key);

        if (request.payload.equals(pkt.payload)) return null;

        // Las pilas ICMP legítimas devuelven el payload tal cual: si cambia, alguien responde "a mano"
        this.counters.tamperedReplies++;
        const analysis = analyzePayload(pkt.payload);
        const extra = [{ code: 'MODIFIED_REPLY', detail: 'El echo-reply no refleja el payload del echo-request' }];
        return this.record(pkt, { ...analysis, standard: null }, extra);
    }

    prunePending(now) {
        if (this.pendingRequests.size < 1000) return;
        for (const [key, value] of this.pendingRequests) {
            if (now - value.time > 60 * 1000) this.pendingRequests.delete(key);
        }
    }

    record(pkt, analysis, extraReasons) {
        if (analysis.standard) {
            this.counters.standard++;
            return null;
        }
        this.counters.nonStandard++;

        const flowKey = `${pkt.src}>${pkt.dst}`;
        let flow = this.flows.get(flowKey);
        if (!flow) {
            this.pruneFlows(pkt.time);
            flow = { src: pkt.src, dst: pkt.dst, events: [], firstSeen: pkt.time, alertedLevel: 'none', alertedAt: 0 };
            this.flows.set(flowKey, flow);
        }

        flow.events.push({
            time: pkt.time,
            key: analysis.patternKey,
            highEntropy: analysis.highEntropy,
            oversized: analysis.size > this.options.oversizedBytes
        });
        flow.lastSeen = pkt.time;

        const cutoff = pkt.time - this.options.slowWindowMs;
        while (flow.events.length > 0 && (flow.events[0].time < cutoff || flow.events.length > this.options.maxEventsPerFlow)) {
            flow.events.shift();
        }

        let { level, reasons, stats } = this.evaluate(flow, pkt.time, analysis);
        if (extraReasons.length > 0) {
            // Un reply que no refleja su request es sospechoso por sí solo
            reasons = [...extraReasons, ...reasons];
            if (levelRank(level) < levelRank('high')) level = 'high';
        }
        return this.maybeAlert(flow, level, reasons, stats, pkt.time);
    }

    evaluate(flow, now, lastAnalysis) {
        const o = this.options;
        const shortEvents = flow.events.filter(e => e.time >= now - o.windowMs);
        const lastMinute = flow.events.filter(e => e.time >= now - 60 * 1000);
        const distinct = (events) => new Set(events.filter(e => e.key).map(e => e.key)).size;

        const stats = {
            nonStandardInWindow: shortEvents.length,
            distinctPatternsWindow: distinct(shortEvents),
            distinctPatternsSlow: distinct(flow.events),
            highEntropyInWindow: shortEvents.filter(e => e.highEntropy).length,
            oversizedInWindow: shortEvents.filter(e => e.oversized).length,
            perMinute: lastMinute.length,
            lastPatternSize: lastAnalysis.size
        };

        const reasons = [];
        let level = 'low';
        const raise = (candidate, code, detail) => {
            reasons.push({ code, detail });
            if (levelRank(candidate) > levelRank(level)) level = candidate;
        };

        if (stats.distinctPatternsWindow >= o.criticalDistinct) {
            raise('critical', 'PATTERN_STEPPING', `${stats.distinctPatternsWindow} patrones distintos en ${Math.round(o.windowMs / 60000)} min: datos avanzando ping a ping`);
        } else if (stats.distinctPatternsWindow >= o.highDistinct) {
            raise('high', 'PATTERN_STEPPING', `${stats.distinctPatternsWindow} patrones distintos en ${Math.round(o.windowMs / 60000)} min`);
        }

        if (stats.distinctPatternsSlow >= o.slowCriticalDistinct) {
            raise('critical', 'SLOW_PATTERN_STEPPING', `${stats.distinctPatternsSlow} patrones distintos en ${Math.round(o.slowWindowMs / 3600000)} h (exfiltración lenta)`);
        } else if (stats.distinctPatternsSlow >= o.slowHighDistinct) {
            raise('high', 'SLOW_PATTERN_STEPPING', `${stats.distinctPatternsSlow} patrones distintos en ${Math.round(o.slowWindowMs / 3600000)} h (exfiltración lenta)`);
        }

        if (stats.highEntropyInWindow >= o.highEntropyCritical) {
            raise('critical', 'HIGH_ENTROPY_PAYLOAD', `${stats.highEntropyInWindow} payloads con aspecto de datos cifrados`);
        } else if (stats.highEntropyInWindow >= o.highEntropyHigh) {
            raise('high', 'HIGH_ENTROPY_PAYLOAD', `${stats.highEntropyInWindow} payloads con aspecto de datos cifrados`);
        }

        if (stats.oversizedInWindow >= o.oversizedCritical) {
            raise('critical', 'OVERSIZED_PAYLOAD', `${stats.oversizedInWindow} payloads no estándar de más de ${o.oversizedBytes} bytes`);
        } else if (stats.oversizedInWindow >= o.oversizedHigh) {
            raise('high', 'OVERSIZED_PAYLOAD', `${stats.oversizedInWindow} payloads no estándar de más de ${o.oversizedBytes} bytes`);
        }

        if (stats.perMinute >= o.floodPerMinute) {
            raise('medium', 'NON_STANDARD_FLOOD', `${stats.perMinute} pings no estándar en el último minuto`);
        }

        return { level, reasons, stats };
    }

    maybeAlert(flow, level, reasons, stats, now) {
        if (levelRank(level) < levelRank('medium')) return null;

        const risen = levelRank(level) > levelRank(flow.alertedLevel);
        const cooledDown = now - flow.alertedAt >= this.options.alertCooldownMs;
        if (!risen && !cooledDown) return null;

        flow.alertedLevel = level;
        flow.alertedAt = now;
        this.counters.alerts++;

        return {
            type: 'ICMP_COVERT_CHANNEL',
            level,
            direction: this.direction(flow.src, flow.dst),
            src: flow.src,
            dst: flow.dst,
            reasons,
            stats,
            firstSeen: new Date(flow.firstSeen).toISOString(),
            lastSeen: new Date(flow.lastSeen).toISOString(),
            // Muestra de patrones como evidencia forense (no se guarda el flujo completo)
            samplePatterns: [...new Set(flow.events.map(e => e.key).filter(Boolean))].slice(-5)
        };
    }

    pruneFlows(now) {
        if (this.flows.size < this.options.maxFlows) return;
        for (const [key, flow] of this.flows) {
            if (now - flow.lastSeen > this.options.slowWindowMs) this.flows.delete(key);
        }
        // Si siguen siendo demasiados, descartar el más antiguo
        if (this.flows.size >= this.options.maxFlows) {
            this.flows.delete(this.flows.keys().next().value);
        }
    }

    getStats() {
        return { ...this.counters, trackedFlows: this.flows.size };
    }
}

module.exports = {
    IcmpCovertChannelDetector,
    analyzePayload,
    shannonEntropy,
    levelRank
};
