// Estado de TODOS los procesos del cluster en /api/system/status.
//
// Con `npm run start:cluster` cada worker es un proceso con su propia memoria: una petición la atiende uno cualquiera, así que
// "uptime", memoria, liderazgo o conexiones de streaming de un solo worker no describen el servicio. Igual que las métricas
// (metrics.js), el worker pide al proceso principal que pregunte a todos y le devuelva la lista:
//
//   worker A ──secure-server:cluster-status──▶ principal ──secure-server:snapshot-request──▶ todos los workers
//   worker A ◀──secure-server:cluster-status:result── principal ◀──secure-server:snapshot── (cada uno, máx. 1,5 s)
//
// Sin cluster (proceso único) devuelve solo el propio proceso. Un worker que no contesta a tiempo aparece como "sin respuesta"
// en lugar de bloquear la petición. Nada de lo que se comparte es secreto: pid, hueco, tiempos, memoria y contadores.

const inCluster = () => process.env.CLUSTER_METRICS === 'true' && typeof process.send === 'function';

let provider = () => ({});
let nextRequest = 1;
const pending = new Map();

// index.js registra lo que solo él sabe (liderazgo, si está cerrándose, mantenimiento, streams abiertos)
function registerProvider(fn) { provider = fn; }

function snapshot() {
    const memory = process.memoryUsage();
    let extra = {};
    try { extra = provider() || {}; } catch { extra = {}; }
    return {
        pid: process.pid,
        slot: process.env.CLUSTER_WORKER_INDEX != null ? Number(process.env.CLUSTER_WORKER_INDEX) : null,
        uptimeSeconds: Math.round(process.uptime()),
        rssMb: Math.round(memory.rss / 1048576),
        heapUsedMb: Math.round(memory.heapUsed / 1048576),
        ...extra
    };
}

if (inCluster()) {
    process.on('message', (message) => {
        if (message?.type === 'secure-server:snapshot-request') {
            process.send({ type: 'secure-server:snapshot', id: message.id, data: snapshot() });
            return;
        }
        if (message?.type !== 'secure-server:cluster-status:result') return;
        const waiter = pending.get(message.id);
        if (!waiter) return;
        pending.delete(message.id);
        waiter(message);
    });
}

async function clusterStatus() {
    if (!inCluster()) return { mode: 'single', workers: [snapshot()], missing: 0 };
    const result = await new Promise((resolve) => {
        const id = nextRequest++;
        const timer = setTimeout(() => { pending.delete(id); resolve(null); }, 3000);
        pending.set(id, (message) => { clearTimeout(timer); resolve(message); });
        process.send({ type: 'secure-server:cluster-status', id });
    });
    // Sin respuesta del principal: al menos el propio proceso (y se dice)
    if (!result) return { mode: 'cluster', workers: [snapshot()], missing: null, error: 'el proceso principal no respondió a tiempo' };
    return { mode: 'cluster', primaryPid: result.primaryPid, workers: result.workers, missing: result.missing };
}

// ---------------------------------------------------------------- lado del proceso principal (lo llama src/cluster.js)
// Pide la foto a cada worker vivo y responde al que preguntó. `workers` es la lista de workers de node:cluster.
let nextRound = 1;
function answerFromPrimary(asker, requestId, workers, timeoutMs = 1500) {
    const alive = workers.filter(w => w.isConnected());
    const round = `r${nextRound++}`;
    const replies = new Map();
    const handlers = new Map();
    let done = false;

    const finish = () => {
        if (done) return;
        done = true;
        clearTimeout(timer);
        for (const [worker, handler] of handlers) worker.off('message', handler);
        const data = alive.map(w => replies.get(w) || { pid: w.process.pid, slot: w.slot ?? null, unresponsive: true });
        if (asker.isConnected()) {
            asker.send({
                type: 'secure-server:cluster-status:result', id: requestId, primaryPid: process.pid,
                workers: data.sort((a, b) => (a.slot ?? 99) - (b.slot ?? 99)), missing: data.filter(d => d.unresponsive).length
            });
        }
    };
    const timer = setTimeout(finish, timeoutMs);

    for (const worker of alive) {
        const handler = (message) => {
            if (message?.type !== 'secure-server:snapshot' || message.id !== round) return;
            replies.set(worker, message.data);
            if (replies.size === alive.length) finish();
        };
        handlers.set(worker, handler);
        worker.on('message', handler);
        try { worker.send({ type: 'secure-server:snapshot-request', id: round }); } catch { /* murió entre medias: saldrá como sin respuesta */ }
    }
    if (alive.length === 0) finish();
}

module.exports = { registerProvider, snapshot, clusterStatus, answerFromPrimary, inCluster };
