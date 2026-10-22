const { AsyncLocalStorage } = require('async_hooks');
const crypto = require('crypto');

// Trazas: contexto W3C (traceparent) + spans por petición y por consulta SQL, con exportación OTLP/HTTP opcional.
//
//  - Cada petición recibe un traceId (el de la cabecera `traceparent` si es válida, o uno nuevo). Sale en las respuestas
//    como `X-Request-Id` y `traceparent`, y se añade a los eventos de seguridad: dado un evento sospechoso se puede
//    reconstruir TODO lo que hizo esa petición.
//  - Los spans (petición, consultas SQL) solo se guardan si la traza está MUESTREADA y hay exportador configurado:
//    OTEL_EXPORTER_OTLP_TRACES_ENDPOINT (o OTEL_EXPORTER_OTLP_ENDPOINT + /v1/traces).
//  - Sin datos personales: los spans llevan método, RUTA (la plantilla, no la URL real), código de estado y operación SQL.
//    Nunca query string, cabeceras, parámetros ni texto SQL.
//
//  OTEL_TRACES_SAMPLER_ARG (0.1)    fracción de peticiones muestreadas; una traza que ya viene muestreada se respeta
//  OTEL_EXPORTER_OTLP_HEADERS       "clave=valor,clave2=valor2" (p. ej. Authorization del colector)
//  OTEL_BSP_SCHEDULE_DELAY (5000)   cada cuántos ms se envía el lote
//  OTEL_SERVICE_NAME (secure-server)

const als = new AsyncLocalStorage();
const TRACEPARENT = /^00-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$/;
const hex = (bytes) => crypto.randomBytes(bytes).toString('hex');
const ZERO_TRACE = '0'.repeat(32);
const ZERO_SPAN = '0'.repeat(16);

const nowNs = () => BigInt(Date.now()) * 1_000_000n + (process.hrtime.bigint() % 1_000_000n);

// ------------------------------------------------------------------ exportador OTLP/HTTP (JSON)
class Exporter {
    constructor() {
        this.queue = [];
        this.timer = null;
        this.failures = 0;
    }

    endpoint() {
        const specific = process.env.OTEL_EXPORTER_OTLP_TRACES_ENDPOINT;
        if (specific) return specific;
        const base = process.env.OTEL_EXPORTER_OTLP_ENDPOINT;
        return base ? `${base.replace(/\/$/, '')}/v1/traces` : null;
    }

    enabled() {
        return Boolean(this.endpoint());
    }

    headers() {
        const out = { 'Content-Type': 'application/json' };
        for (const pair of (process.env.OTEL_EXPORTER_OTLP_HEADERS || '').split(',')) {
            const i = pair.indexOf('=');
            if (i > 0) out[pair.slice(0, i).trim()] = pair.slice(i + 1).trim();
        }
        return out;
    }

    enqueue(spans) {
        if (!this.enabled()) return;
        this.queue.push(...spans);
        if (this.queue.length > 2048) this.queue.splice(0, this.queue.length - 2048); // acotado: el más antiguo se descarta
        if (this.queue.length >= 256) return void this.flush();
        if (!this.timer) {
            this.timer = setTimeout(() => { this.timer = null; this.flush(); }, Number(process.env.OTEL_BSP_SCHEDULE_DELAY) || 5000);
            this.timer.unref();
        }
    }

    static attr(key, value) {
        if (typeof value === 'number') return { key, value: Number.isInteger(value) ? { intValue: String(value) } : { doubleValue: value } };
        if (typeof value === 'boolean') return { key, value: { boolValue: value } };
        return { key, value: { stringValue: String(value).slice(0, 200) } };
    }

    payload(spans) {
        return {
            resourceSpans: [{
                resource: { attributes: [Exporter.attr('service.name', process.env.OTEL_SERVICE_NAME || 'secure-server')] },
                scopeSpans: [{
                    scope: { name: 'secure-server' },
                    spans: spans.map(span => ({
                        traceId: span.traceId,
                        spanId: span.spanId,
                        ...(span.parentSpanId && { parentSpanId: span.parentSpanId }),
                        name: span.name,
                        kind: span.kind,
                        startTimeUnixNano: String(span.startNs),
                        endTimeUnixNano: String(span.endNs),
                        attributes: Object.entries(span.attrs).map(([k, v]) => Exporter.attr(k, v)),
                        status: { code: span.error ? 2 : 1 }
                    }))
                }]
            }]
        };
    }

    async flush() {
        if (!this.enabled() || this.queue.length === 0) return;
        const batch = this.queue.splice(0, this.queue.length);
        const url = this.endpoint();
        try {
            if (!url.startsWith('https://') && process.env.NODE_ENV === 'production' && process.env.OTEL_ALLOW_HTTP !== 'true') {
                throw new Error('el colector OTLP debe ser https:// en producción');
            }
            const res = await fetch(url, {
                method: 'POST', headers: this.headers(), body: JSON.stringify(this.payload(batch)),
                redirect: 'error', signal: AbortSignal.timeout(5000)
            });
            if (!res.ok) throw new Error(`el colector respondió ${res.status}`);
        } catch (error) {
            this.failures++;
            require('./metrics').otelExportFailures.inc();
            if (this.failures === 1 || this.failures % 50 === 0) console.error(`⚠️ No se pudieron exportar las trazas (${this.failures} fallos): ${error.message}`);
        }
    }
}
const exporter = new Exporter();

// ------------------------------------------------------------------ spans
function newSpan(store, name, kind, attrs = {}, parentSpanId = null) {
    return {
        traceId: store.traceId, spanId: hex(8), parentSpanId, name, kind, attrs, error: false,
        startNs: nowNs(), endNs: null
    };
}
function endSpan(store, span, extraAttrs = {}, error = false) {
    span.endNs = nowNs();
    Object.assign(span.attrs, extraAttrs);
    span.error = error;
    if (store.sampled) store.spans.push(span);
}

// Ejecuta fn dentro de un span hijo (si hay traza muestreada); en otro caso, solo ejecuta fn
async function withSpan(name, attrs, fn) {
    const store = als.getStore();
    if (!store || !store.sampled || !exporter.enabled()) return fn();
    const span = newSpan(store, name, 3, attrs, store.rootSpanId); // 3 = CLIENT
    try {
        const result = await fn();
        endSpan(store, span);
        return result;
    } catch (error) {
        endSpan(store, span, { 'error.code': String(error.code || 'ERROR').slice(0, 60) }, true);
        throw error;
    }
}

const currentTraceId = () => als.getStore()?.traceId || null;

// Parte de la petición que NO es la plantilla de ruta: si Express no encontró ruta, no se etiqueta con la URL real
function routeLabel(req) {
    if (req.route?.path !== undefined) {
        const label = `${req.baseUrl || ''}${req.route.path}`;
        return label.length > 1 ? label.replace(/\/+$/, '') || '/' : label || '/'; // "/api/notes/" y "/api/notes" son la misma ruta
    }
    return 'unmatched';
}

function middleware() {
    return (req, res, next) => {
        const incoming = TRACEPARENT.exec(String(req.headers.traceparent || '').trim());
        const valid = incoming && incoming[1] !== ZERO_TRACE && incoming[2] !== ZERO_SPAN;
        const traceId = valid ? incoming[1] : hex(16);
        const parentSpanId = valid ? incoming[2] : null;

        const ratio = Number(process.env.OTEL_TRACES_SAMPLER_ARG);
        const rate = Number.isFinite(ratio) ? Math.min(Math.max(ratio, 0), 1) : 0.1;
        const parentSampled = valid && (parseInt(incoming[3], 16) & 1) === 1;
        const sampled = exporter.enabled() && (parentSampled || Math.random() < rate);

        const root = newSpan({ traceId }, `${req.method}`, 2, { 'http.request.method': req.method }, parentSpanId); // 2 = SERVER
        const store = { traceId, rootSpanId: root.spanId, sampled, spans: [] };

        res.setHeader('X-Request-Id', traceId);
        res.setHeader('traceparent', `00-${traceId}-${root.spanId}-${sampled ? '01' : '00'}`);
        req.traceId = traceId;

        res.on('finish', () => {
            const route = routeLabel(req);
            root.name = `${req.method} ${route}`;
            endSpan(store, root, { 'http.route': route, 'http.response.status_code': res.statusCode }, res.statusCode >= 500);
            if (store.sampled) exporter.enqueue(store.spans);
        });

        als.run(store, next);
    };
}

module.exports = { middleware, withSpan, currentTraceId, routeLabel, exporter, TRACEPARENT };
