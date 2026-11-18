// Pruebas en vivo desde la web (FASE 3): diagnóstico, simulación de ataques y suites de pruebas.
//
// Modelo (sirve con varias réplicas: el progreso vive en la BD, no en memoria):
//   - ops_runs: una fila por ejecución. `active_kind` (índice ÚNICO) vale `kind` mientras está viva y NULL al terminar: así solo hay
//     UNA ejecución activa por tipo en todo el cluster, de forma atómica y sin cerrojos (el INSERT del segundo choca → 409).
//   - ops_run_events: el registro en vivo. El navegador sondea GET /runs/:id?afterSeq=N (no usa el stream SSE: ese tiene su propio
//     cursor de eventos de seguridad y mezclar líneas de ejecución lo complicaría sin ganar nada).
//   - La ejecución corre en segundo plano en el proceso que atendió la petición; `host` guarda `<máquina>:<pid>`.
//   - Cancelar escribe `cancelled` en la BD; el ejecutor lo comprueba entre pasos (y el runner de suites mata a su hijo), de modo
//     que vale también si la ejecución vive en otra réplica.
// Los ejecutores están en src/ops/runners/*.js y reciben un contexto (ver makeContext).

const os = require('os');
const db = require('../config/database');
const { sqlInt } = require('../config/sql');

const KINDS = ['diagnostic', 'attack_sim', 'test_suite'];
const ACTIVE = ['queued', 'running'];
const MAX_EVENTS_PER_RUN = 5000;
const MAX_PENDING_EVENTS = 1000; // inserciones en cola en memoria por ejecución: si la BD va lenta, se descartan líneas `output`
const PAGE = 500;
const MAX_RUN_MINUTES = 60; // una ejecución «viva» más vieja que esto (y de otro host) se da por muerta

const HOST = `${os.hostname()}:${process.pid}`.slice(0, 64);

class RunError extends Error {
    constructor(code, message, status = 400) {
        super(message);
        this.code = code;
        this.status = status;
    }
}

// Estado en memoria de las ejecuciones QUE ESTE PROCESO está ejecutando: contador de seq, cola de inserciones (orden garantizado) y
// contadores para el resumen.
const live = new Map();

const retentionDays = () => {
    const n = Number(process.env.OPS_RUNS_RETENTION_DAYS);
    return Number.isFinite(n) && n >= 1 ? n : 14;
};

const clip = (text, max) => String(text ?? '').slice(0, max);

// Redacta credenciales ANTES de guardar nada en ops_run_events (la salida de una suite puede imprimir URLs con contraseña, tokens...):
//   esquema://usuario:contraseña@host → esquema://usuario:***@host · password=/secret=/token=/api_key=... valor → ***
//   "password":"valor" (JSON) → "password":"***" · Bearer <token> → Bearer ***
function redact(text) {
    return String(text ?? '')
        .replace(/([a-z][a-z0-9+.-]*:\/\/[^\s:/@]+):[^\s@/]+@/gi, '$1:***@')
        .replace(/\bBearer\s+[A-Za-z0-9._~+/=-]+/gi, 'Bearer ***')
        .replace(/(\b(?:password|passwd|pwd|contrase(?:ñ|n)a|secret|token|api[_-]?key)["']?\s*[=:]\s*)("(?:[^"\x5c]|\x5c.)*"|'[^']*'|[^\s,;&}"']+)/gi,
            (_m, head, value) => `${head}${value[0] === '"' ? '"***"' : value[0] === "'" ? "'***'" : '***'}`);
}

function parseJson(text) {
    if (!text) return null;
    try { return JSON.parse(text); } catch { return null; }
}

const toIso = (value) => (value instanceof Date ? value.toISOString() : value ? new Date(value).toISOString() : null);

function publicRun(row) {
    return {
        id: Number(row.id), kind: row.kind, target: row.target, status: row.status, requestedBy: row.requested_by,
        startedAt: toIso(row.started_at), finishedAt: toIso(row.finished_at), host: row.host, summary: parseJson(row.summary_json)
    };
}

const runners = () => ({
    diagnostic: require('./runners/diagnostic'),
    attack_sim: require('./runners/attack-sim'),
    test_suite: require('./runners/test-suite')
});

// ------------------------------------------------------------------ registro de eventos

function stateOf(runId) {
    let state = live.get(runId);
    if (!state) {
        state = { seq: 0, pending: 0, chain: Promise.resolve(), counts: { pass: 0, fail: 0, warn: 0 }, done: 0, total: null, events: 0, dropped: 0, lastFlush: 0, cancelledAt: 0, cancelled: false };
        live.set(runId, state);
    }
    return state;
}

async function flushSummary(runId, force = false) {
    const state = live.get(runId);
    if (!state) return;
    const now = Date.now();
    if (!force && now - state.lastFlush < 400) return;
    state.lastFlush = now;
    const summary = { done: state.done, total: state.total, ...state.counts };
    try {
        await db.query("UPDATE ops_runs SET summary_json = ? WHERE id = ? AND status IN ('queued', 'running')", [JSON.stringify(summary), runId]);
    } catch (error) {
        console.error('⚠️ Resumen de la ejecución:', error.code || error.message);
    }
}

// Inserta un evento con seq creciente. Las inserciones se encadenan para conservar el orden. Nunca lanza: un fallo de la BD al
// anotar no debe tumbar la ejecución (se anota en consola).
function emit(runId, { level = 'info', step = '', message = '', data } = {}) {
    const state = stateOf(runId);
    if (['pass', 'fail', 'warn'].includes(level)) state.counts[level]++;
    // Tope por ejecución: se descartan las líneas de salida (no los resultados) para que una suite ruidosa no llene la BD
    // Cola en memoria acotada: con la BD lenta también se descartan las líneas de salida (nunca pass/fail/error/warn/info)
    if ((state.events >= MAX_EVENTS_PER_RUN || state.pending >= MAX_PENDING_EVENTS) && level === 'output') {
        state.dropped++;
        return state.chain;
    }
    state.events++;
    state.pending++;
    const seq = ++state.seq;
    const json = data === undefined ? null : clip(redact(JSON.stringify(data)), 4000);
    const safeMessage = clip(redact(message), 500);
    state.chain = state.chain.then(() => db.query(
        'INSERT INTO ops_run_events (run_id, seq, level, step, message, data_json) VALUES (?, ?, ?, ?, ?, ?)',
        [runId, seq, level, clip(step, 80), safeMessage, json]
    )).catch((error) => { console.error('⚠️ Evento de ejecución:', error.code || error.message); })
        .then(() => { state.pending--; });
    if (level !== 'output') state.chain = state.chain.then(() => flushSummary(runId));
    return state.chain;
}

// ------------------------------------------------------------------ ciclo de vida

async function finish(runId, status, summary) {
    const state = live.get(runId);
    if (state) {
        if (state.dropped) await emit(runId, { level: 'warn', step: 'registro', message: `Se omitieron ${state.dropped} líneas de salida (tope de ${MAX_EVENTS_PER_RUN} eventos o BD lenta: cola de ${MAX_PENDING_EVENTS})` });
        await state.chain;
    }
    const merged = { done: state?.done ?? 0, total: state?.total ?? null, ...(state?.counts || {}), ...(summary || {}) };
    // Solo si sigue viva: una ejecución cancelada conserva su estado `cancelled`
    await db.query(
        "UPDATE ops_runs SET status = ?, active_kind = NULL, finished_at = CURRENT_TIMESTAMP, summary_json = ? WHERE id = ? AND status IN ('queued', 'running')",
        [status, JSON.stringify(merged), runId]
    );
    // Si estaba cancelada, solo falta guardar el resumen y liberar el tipo: cancel() NO lo libera, lo hace el ejecutor al terminar de verdad
    await db.query("UPDATE ops_runs SET summary_json = ?, active_kind = NULL WHERE id = ? AND status = 'cancelled'", [JSON.stringify(merged), runId]);
    live.delete(runId);
    const [rows] = await db.query('SELECT * FROM ops_runs WHERE id = ?', [runId]);
    return rows[0] ? publicRun(rows[0]) : null;
}

class Cancelled extends Error {}

async function isCancelled(runId) {
    const state = live.get(runId);
    if (state?.cancelled) return true;
    // Barato: como mucho una consulta cada 400 ms por ejecución
    const now = Date.now();
    if (state && now - state.cancelledAt < 400) return false;
    if (state) state.cancelledAt = now;
    const [rows] = await db.query('SELECT status FROM ops_runs WHERE id = ?', [runId]);
    const cancelled = rows[0]?.status === 'cancelled';
    if (cancelled && state) state.cancelled = true;
    return cancelled;
}

// Contexto que ven los ejecutores
function makeContext(run, extra) {
    const runId = run.id;
    const state = stateOf(runId);
    const ctx = {
        runId, kind: run.kind, target: run.target, ...extra,
        emit: (level, step, message, data) => emit(runId, { level, step, message, data }),
        isCancelled: () => isCancelled(runId),
        setTotal: (n) => { state.total = n; },
        tick: () => { state.done++; },
        // Ejecuta un paso: anuncia el inicio y emite el resultado con su duración. `fn` devuelve { level?, message?, data? } o un
        // texto; lanzar una excepción = fallo. Antes de cada paso se comprueba la cancelación.
        async step(name, announce, fn) {
            if (await isCancelled(runId)) throw new Cancelled();
            await emit(runId, { level: 'info', step: name, message: `▶ ${announce}` });
            const started = Date.now();
            let result;
            try {
                result = await fn();
            } catch (error) {
                if (error instanceof Cancelled) throw error;
                result = { level: 'fail', message: clip(error.message || String(error), 300) };
            }
            const out = typeof result === 'string' ? { message: result } : (result || {});
            const ms = Date.now() - started;
            state.done++;
            await emit(runId, { level: out.level || 'pass', step: name, message: `${out.message || announce} (${ms} ms)`, data: { ms, ...(out.data || {}) } });
        }
    };
    return ctx;
}

async function execute(run, extra) {
    const ctx = makeContext(run, extra);
    let status = 'passed';
    let summary;
    try {
        await db.query("UPDATE ops_runs SET status = 'running' WHERE id = ? AND status = 'queued'", [run.id]);
        const result = await runners()[run.kind].run(ctx);
        summary = result?.summary;
        const state = stateOf(run.id);
        status = result?.status || (state.counts.fail > 0 ? 'failed' : 'passed');
        if (await isCancelled(run.id)) status = 'cancelled';
    } catch (error) {
        if (error instanceof Cancelled) {
            status = 'cancelled';
            await emit(run.id, { level: 'warn', step: 'cancelar', message: 'Ejecución cancelada' });
        } else {
            status = 'error';
            console.error('❌ Ejecución de pruebas:', error.code || error.message);
            await emit(run.id, { level: 'error', step: 'ejecución', message: clip(error.message || 'Error inesperado', 300) });
        }
    }
    try {
        await finish(run.id, status, summary);
    } catch (error) {
        console.error('❌ Cerrando la ejecución:', error.code || error.message);
    }
}

// Borra ejecuciones antiguas (los eventos caen por ON DELETE CASCADE). Nunca toca las vivas.
async function purgeOld() {
    const cutoff = new Date(Date.now() - retentionDays() * 24 * 3600 * 1000);
    await db.query("DELETE FROM ops_runs WHERE started_at < ? AND status NOT IN ('queued', 'running')", [cutoff]);
}

function isDuplicate(error) {
    return error?.code === 'ER_DUP_ENTRY' || error?.code === '23505';
}

// `context`: datos que solo conoce la petición (puerto local y confianza en el proxy, para la simulación de ataques). El destino
// de la simulación SALE de aquí (el propio socket de la petición), nunca de lo que envía el cliente.
async function start({ kind, target, requestedBy, context = {} }) {
    if (!KINDS.includes(kind)) throw new RunError('INVALID_KIND', 'Tipo de ejecución desconocido', 400);
    const cleanTarget = target === undefined || target === null || target === '' ? null : String(target);
    runners()[kind].validate?.(cleanTarget); // lanza RunError (400/403/409) si el destino no vale o el runner está desactivado

    await purgeOld().catch((error) => console.error('⚠️ Retención de ejecuciones:', error.code || error.message));

    let id;
    try {
        const [result] = await db.query(
            "INSERT INTO ops_runs (kind, target, status, active_kind, requested_by, host) VALUES (?, ?, 'queued', ?, ?, ?)",
            [kind, cleanTarget, kind, requestedBy ?? null, HOST]
        );
        id = Number(result.insertId);
    } catch (error) {
        if (isDuplicate(error)) throw new RunError('RUN_IN_PROGRESS', 'Ya hay una ejecución de este tipo en curso', 409);
        throw error;
    }
    const [rows] = await db.query('SELECT * FROM ops_runs WHERE id = ?', [id]);
    const run = publicRun(rows[0]);
    stateOf(id);
    // Segundo plano: la petición responde ya (202) y el navegador sondea el avance
    setImmediate(() => { execute(run, { ...context, host: HOST }).catch((error) => console.error('❌ Ejecución:', error.message)); });
    return run;
}

async function list({ limit = 30 } = {}) {
    const n = Math.min(100, Math.max(1, Number(limit) || 30));
    const [rows] = await db.query(`SELECT * FROM ops_runs ORDER BY id DESC LIMIT ${sqlInt(n, { min: 1, max: 100 })}`);
    return rows.map(publicRun);
}

async function get(id, { afterSeq = 0 } = {}) {
    const [rows] = await db.query('SELECT * FROM ops_runs WHERE id = ?', [id]);
    if (!rows[0]) throw new RunError('NOT_FOUND', 'Ejecución no encontrada', 404);
    const [events] = await db.query(
        `SELECT seq, level, step, message, data_json, created_at FROM ops_run_events WHERE run_id = ? AND seq > ? ORDER BY seq LIMIT ${sqlInt(PAGE + 1, { min: 1, max: 1000 })}`,
        [id, Math.max(0, Number(afterSeq) || 0)]
    );
    const hasMore = events.length > PAGE;
    const page = events.slice(0, PAGE).map(e => ({
        seq: Number(e.seq), level: e.level, step: e.step, message: e.message, data: parseJson(e.data_json), at: toIso(e.created_at)
    }));
    return { run: publicRun(rows[0]), events: page, lastSeq: page.length ? page[page.length - 1].seq : Math.max(0, Number(afterSeq) || 0), hasMore };
}

async function cancel(id) {
    const [rows] = await db.query('SELECT status FROM ops_runs WHERE id = ?', [id]);
    if (!rows[0]) throw new RunError('NOT_FOUND', 'Ejecución no encontrada', 404);
    if (!ACTIVE.includes(rows[0].status)) throw new RunError('NOT_ACTIVE', 'La ejecución ya terminó', 409);
    // `active_kind` se CONSERVA: el tipo sigue ocupado (409 al lanzar otra) hasta que el ejecutor termine de verdad (para las suites,
    // cuando el proceso hijo haya cerrado) y `finish` lo libere. Si el ejecutor muere, lo libera recoverStale.
    await db.query(
        "UPDATE ops_runs SET status = 'cancelled', finished_at = CURRENT_TIMESTAMP WHERE id = ? AND status IN ('queued', 'running')",
        [id]
    );
    const state = live.get(id);
    if (state) state.cancelled = true;
    await emit(id, { level: 'warn', step: 'cancelar', message: 'Cancelación solicitada' });
    const [after] = await db.query('SELECT * FROM ops_runs WHERE id = ?', [id]);
    return publicRun(after[0]);
}

const pidAlive = (pid) => {
    try { process.kill(pid, 0); return true; } catch (error) { return error.code === 'EPERM'; }
};

// Al arrancar: lo que quedó «vivo» porque el proceso murió pasa a `error`. Por host+pid (no toca lo de otros procesos del cluster
// que siguen vivos) y, para otras máquinas, por antigüedad.
async function recoverStale() {
    const [rows] = await db.query("SELECT id, host, started_at, status FROM ops_runs WHERE status IN ('queued', 'running') OR (status = 'cancelled' AND active_kind IS NOT NULL)");
    let recovered = 0;
    for (const row of rows) {
        const [machine, pidText] = String(row.host || '').split(/:(?=\d+$)/);
        const sameMachine = machine === os.hostname();
        const dead = sameMachine ? !pidAlive(Number(pidText)) || Number(pidText) === process.pid : Date.now() - new Date(row.started_at).getTime() > MAX_RUN_MINUTES * 60_000;
        if (!dead || live.has(Number(row.id))) continue;
        if (row.status === 'cancelled') { // cancelada cuyo ejecutor murió: solo falta liberar el tipo
            await db.query("UPDATE ops_runs SET active_kind = NULL WHERE id = ? AND status = 'cancelled'", [row.id]);
            continue;
        }
        const [result] = await db.query(
            "UPDATE ops_runs SET status = 'error', active_kind = NULL, finished_at = CURRENT_TIMESTAMP WHERE id = ? AND status IN ('queued', 'running')",
            [row.id]
        );
        if (result.affectedRows) {
            recovered++;
            await db.query(
                'INSERT INTO ops_run_events (run_id, seq, level, step, message) SELECT ?, COALESCE(MAX(seq), 0) + 1, \'error\', \'reinicio\', \'Interrumpida por reinicio\' FROM ops_run_events WHERE run_id = ?',
                [row.id, row.id]
            );
        }
    }
    return recovered;
}

// Apagado del servidor: mata los procesos hijos del runner de suites y marca como `error` («servidor detenido») las ejecuciones que
// ESTE proceso tenía en marcha, liberando su tipo. No toca las de otras réplicas. Nunca lanza.
async function abortLocal(reason = 'servidor detenido') {
    let killed = 0;
    try { killed = require('./runners/test-suite').killAll(); } catch { /* sin runner */ }
    const ids = [...live.keys()];
    for (const id of ids) {
        try {
            await emit(id, { level: 'error', step: 'apagado', message: `Ejecución interrumpida: ${reason}` });
            await live.get(id)?.chain;
            await db.query(
                "UPDATE ops_runs SET status = 'error', active_kind = NULL, finished_at = COALESCE(finished_at, CURRENT_TIMESTAMP) WHERE id = ? AND (status IN ('queued', 'running') OR (status = 'cancelled' AND active_kind IS NOT NULL))",
                [id]
            );
        } catch (error) {
            console.error('⚠️ Cerrando la ejecución al apagar:', error.code || error.message);
        }
    }
    return { killed, runs: ids.length };
}

function catalog() {
    const all = runners();
    return {
        kinds: KINDS.map(kind => ({ kind, ...(all[kind].describe ? all[kind].describe() : {}) })),
        retentionDays: retentionDays()
    };
}

module.exports = { start, list, get, cancel, emit, finish, recoverStale, abortLocal, catalog, redact, RunError, Cancelled, KINDS, HOST };
