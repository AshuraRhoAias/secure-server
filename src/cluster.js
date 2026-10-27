#!/usr/bin/env node
// Arranque con VARIOS procesos (node:cluster): `npm run start:cluster`.
//
// Un proceso de Node usa un solo núcleo. Este proceso principal lanza WEB_CONCURRENCY workers (por defecto, uno por núcleo, máx. 16),
// cada uno con su propio servidor HTTP sobre el mismo puerto (el sistema operativo reparte las conexiones), y los vigila:
//
//   - un worker que muere se relanza con espera creciente; si fallan 5 seguidos en 60 s, el principal se detiene con error (para que el
//     orquestador lo vea en vez de relanzar sin fin un arranque roto);
//   - SIGTERM / SIGINT: cierre ordenado de todos (cada uno deja terminar sus peticiones), con plazo y después SIGKILL;
//   - SIGHUP: REINICIO EN CALIENTE (rolling): sustituye los workers de uno en uno, esperando a que el nuevo esté escuchando antes de
//     parar el viejo: se puede desplegar código o recargar claves sin cortar el servicio;
//   - /api/metrics: agrega las métricas de TODOS los workers (prom-client AggregatorRegistry), vengan de donde vengan.
//
// El principal NO carga secretos, base de datos ni código de la aplicación: es un supervisor mínimo (menos superficie).
// Reparto de conexiones a la BD: cada worker abre su pool (DB_POOL_SIZE). Total = WEB_CONCURRENCY × DB_POOL_SIZE: debe quedar por debajo
// de max_connections de la BD (con margen para otras instancias). Ver docs/SEGURIDAD.md §23.

'use strict';
const cluster = require('cluster');
const os = require('os');
const path = require('path');

const MAX_WORKERS = 16;
const CRASH_WINDOW_MS = 60_000;
const CRASH_LIMIT = 5;

const intEnv = (name, fallback) => { const n = Number(process.env[name]); return Number.isInteger(n) && n > 0 ? n : fallback; };
const workerCount = () => Math.min(intEnv('WEB_CONCURRENCY', os.availableParallelism ? os.availableParallelism() : os.cpus().length), MAX_WORKERS);

function runPrimary() {
    const { AggregatorRegistry } = require('prom-client');
    const aggregator = new AggregatorRegistry();
    const total = workerCount();
    const slots = new Map();           // hueco (0..N-1) -> worker vivo
    const crashes = [];
    let stopping = false;
    let rolling = false;

    // Reparto de conexiones. 'none' (por defecto): todos los workers aceptan del MISMO socket de escucha, que sobrevive a cualquiera de
    // ellos: al parar uno (reinicio en caliente, caída), lo que estaba en la cola del kernel lo acepta otro y no se pierde ninguna conexión.
    // 'rr' (round-robin del principal): reparto más parejo con pocas conexiones largas, pero una conexión ya enviada a un worker que
    // se cierra en ese instante se pierde (en las pruebas: ~1 de cada 200 durante un reinicio en caliente).
    cluster.schedulingPolicy = process.env.CLUSTER_SCHEDULING === 'rr' ? cluster.SCHED_RR : cluster.SCHED_NONE;
    cluster.setupPrimary({ exec: path.join(__dirname, 'index.js') });
    console.log(`🧵 Supervisor (pid ${process.pid}): ${total} worker(s)`);

    function fork(slot) {
        const worker = cluster.fork({ CLUSTER_WORKER_INDEX: String(slot), CLUSTER_METRICS: 'true' });
        worker.slot = slot;
        slots.set(slot, worker);
        worker.on('message', (message) => {
            if (message?.type !== 'secure-server:metrics') return;
            aggregator.clusterMetrics()
                .then(text => worker.isConnected() && worker.send({ type: 'secure-server:metrics:result', id: message.id, text }))
                .catch(error => worker.isConnected() && worker.send({ type: 'secure-server:metrics:result', id: message.id, error: error.message }));
        });
        return worker;
    }

    cluster.on('exit', (worker, code, signal) => {
        if (slots.get(worker.slot) === worker) slots.delete(worker.slot);
        if (stopping || worker.replaced) return;

        const now = Date.now();
        crashes.push(now);
        while (crashes.length && now - crashes[0] > CRASH_WINDOW_MS) crashes.shift();
        console.error(`⚠️ Worker ${worker.process.pid} (hueco ${worker.slot}) terminó (código ${code}${signal ? `, señal ${signal}` : ''})`);

        if (crashes.length >= CRASH_LIMIT) {
            console.error(`❌ ${CRASH_LIMIT} caídas en ${CRASH_WINDOW_MS / 1000} s: el arranque está roto; el supervisor se detiene`);
            shutdown(1);
            return;
        }
        const delay = Math.min(1000 * 2 ** (crashes.length - 1), 15_000);
        console.log(`   Relanzando el hueco ${worker.slot} en ${delay} ms`);
        setTimeout(() => { if (!stopping) fork(worker.slot); }, delay);
    });

    const waitFor = (worker, event, ms) => new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error(`el worker no emitió "${event}" a tiempo`)), ms);
        worker.once(event, () => { clearTimeout(timer); resolve(); });
    });

    // Reinicio en caliente: el nuevo escucha ANTES de que el viejo deje de atender
    async function rollingRestart() {
        if (rolling || stopping) return;
        rolling = true;
        console.log('🔄 Reinicio en caliente (SIGHUP)…');
        try {
            for (const slot of [...slots.keys()].sort((a, b) => a - b)) {
                const old = slots.get(slot);
                if (!old) continue;
                old.replaced = true;
                const fresh = fork(slot);
                await waitFor(fresh, 'listening', intEnv('STARTUP_TIMEOUT_MS', 60_000));
                const exited = waitFor(old, 'exit', intEnv('SHUTDOWN_TIMEOUT_MS', 10_000) + 5000).catch(() => old.kill('SIGKILL'));
                old.process.kill('SIGTERM');
                await exited;
                console.log(`   ✅ Hueco ${slot} renovado`);
            }
            console.log('✅ Reinicio en caliente completado');
        } catch (error) {
            console.error('❌ Reinicio en caliente interrumpido:', error.message);
        } finally {
            rolling = false;
        }
    }

    function shutdown(code = 0) {
        if (stopping) return;
        stopping = true;
        console.log('🛑 Supervisor: cerrando workers…');
        const workers = Object.values(cluster.workers || {});
        workers.forEach(worker => worker.process.kill('SIGTERM'));
        const limit = intEnv('SHUTDOWN_TIMEOUT_MS', 10_000) + 5000;
        const timer = setTimeout(() => { workers.forEach(w => w.process.kill('SIGKILL')); process.exit(code || 1); }, limit);
        timer.unref();
        const check = setInterval(() => {
            if (Object.keys(cluster.workers || {}).length === 0) { clearInterval(check); process.exit(code); }
        }, 200);
    }

    process.on('SIGTERM', () => shutdown(0));
    process.on('SIGINT', () => shutdown(0));
    process.on('SIGHUP', () => { rollingRestart(); });

    for (let slot = 0; slot < total; slot++) fork(slot);
}

if (cluster.isPrimary) runPrimary();
