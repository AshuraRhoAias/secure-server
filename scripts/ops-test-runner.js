#!/usr/bin/env node
// Trabajador de suites de pruebas: `npm run ops:test-runner`. Lo arranca el OPERADOR a propósito, en el mismo servidor.
//
// Por qué existe: el servidor (src/) nunca ejecuta procesos externos (invariante de seguridad, test/test_icmp.js). La interfaz web
// solo ENCOLA la suite (ops_runs.status = 'queued'); este proceso, independiente y fuera de src/, la reclama y la ejecuta.
//
// Qué hace:
//   - Al arrancar comprueba sus salvaguardas y se NIEGA a arrancar si fallan: OPS_TEST_RUNNER=true; nunca con NODE_ENV=production
//     salvo OPS_TEST_RUNNER_ALLOW_PRODUCTION=true; dependencias de desarrollo y carpeta test/ presentes; y la guarda de BD (dbGuard:
//     las BD de pruebas ≠ BD de la aplicación, nombres con «test», BD de la aplicación determinable).
//   - Late en la tabla ops_workers cada ~5 s (el servidor exige un latido de < 15 s para aceptar suites).
//   - Cada ~1 s busca ejecuciones `test_suite` en `queued` y reclama UNA de forma atómica
//     (UPDATE ... SET status = 'running' WHERE id = ? AND status = 'queued': solo un trabajador gana).
//   - La ejecuta: lista CERRADA validada otra vez aquí, spawn SIN shell, entorno LIMPIO (nada de DB_*, semillas ni secretos de la
//     aplicación; solo TEST_*), reporter TAP, salida en vivo con redacción de credenciales (runs.service.emit), tiempo límite
//     (OPS_TEST_RUNNER_TIMEOUT_MIN, 20 por defecto) y muerte del árbol de procesos.
//   - Entre líneas comprueba si la ejecución pasó a `cancelled` y mata al hijo.
//   - Con SIGINT/SIGTERM mata a los hijos y marca la ejecución en curso como `error` («trabajador detenido»).

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');

const ROOT = path.resolve(__dirname, '..');
const KIND = 'test_suite';

const TAP_RESULT = /^\s*(not ok|ok) \d+ - (.*)$/;
const TAP_SKIP = / # (?:SKIP|TODO)\b/;
const TAP_TOTAL = /^# (tests|pass|fail|skipped|cancelled|todo) (\d+)/;

// Salvaguardas de arranque. Devuelve null si todo está bien o { code, message }. `guardEnv`: entorno para la guarda de BD.
function checkSafeguards(env = process.env, guardEnv = env) {
    if (env.OPS_TEST_RUNNER !== 'true') {
        return { code: 'TEST_RUNNER_DISABLED', message: 'Desactivado: define OPS_TEST_RUNNER=true en el entorno del trabajador para permitir ejecutar suites' };
    }
    if (env.NODE_ENV === 'production' && env.OPS_TEST_RUNNER_ALLOW_PRODUCTION !== 'true') {
        return { code: 'TEST_RUNNER_PRODUCTION', message: 'Bloqueado en producción: hace falta además OPS_TEST_RUNNER_ALLOW_PRODUCTION=true' };
    }
    if (!fs.existsSync(path.join(ROOT, 'node_modules', 'eslint')) || !fs.existsSync(path.join(ROOT, 'test', 'helpers', 'env.js'))) {
        return { code: 'NO_DEV_DEPS', message: 'Sin dependencias de desarrollo ni carpeta test/ (instalación de producción): no se pueden ejecutar suites' };
    }
    return require('../src/ops/runners/test-suite').dbGuard(guardEnv);
}

function killTree(child) {
    if (!child.pid) return;
    try {
        if (process.platform === 'win32') {
            spawn('taskkill', ['/pid', String(child.pid), '/T', '/F'], { stdio: 'ignore', windowsHide: true, shell: false }).on('error', () => child.kill());
        } else {
            process.kill(-child.pid, 'SIGKILL'); // el hijo es líder de su grupo (detached): se mata el grupo entero
        }
    } catch {
        try { child.kill('SIGKILL'); } catch { /* ya terminó */ }
    }
}

// Arranca el trabajador. Lanza un Error con `.code` si fallan las salvaguardas. Devuelve { stop, id, activeChildren }.
//   pollMs / heartbeatMs: periodos (por defecto 1000 y 5000). id: identificador en ops_workers (por defecto `<máquina>:<pid>`).
//   guardEnv: entorno para la guarda de BD (por defecto process.env; las pruebas pasan uno propio).
function startWorker({ pollMs = 1000, heartbeatMs = 5000, id, guardEnv } = {}) {
    const problem = checkSafeguards(process.env, guardEnv || process.env);
    if (problem) throw Object.assign(new Error(problem.message), { code: problem.code });

    const db = require('../src/config/database');
    const runs = require('../src/ops/runs.service');
    const suiteRunner = require('../src/ops/runners/test-suite');
    const workerId = String(id || `${os.hostname()}:${process.pid}`).slice(0, 64);
    const children = new Set();
    let stopping = false;
    let busy = null; // promesa de la ejecución en curso
    let pollTimer = null;
    let beatTimer = null;

    async function heartbeat() {
        try {
            await db.query(
                `INSERT INTO ops_workers (host, kind, pid, last_seen) VALUES (?, ?, ?, CURRENT_TIMESTAMP(3))
                 ON DUPLICATE KEY UPDATE kind = VALUES(kind), pid = VALUES(pid), last_seen = CURRENT_TIMESTAMP(3)`,
                [workerId, KIND, process.pid]
            );
        } catch (error) {
            console.error('⚠️ Latido del trabajador:', error.code || error.message);
        }
    }

    // Reclama UNA ejecución encolada de forma atómica. Devuelve { id, kind, target } o null.
    async function claim() {
        const [rows] = await db.query("SELECT id, target FROM ops_runs WHERE kind = ? AND status = 'queued' ORDER BY id LIMIT 1", [KIND]);
        if (!rows[0]) return null;
        const [result] = await db.query("UPDATE ops_runs SET status = 'running', host = ? WHERE id = ? AND status = 'queued'", [workerId, rows[0].id]);
        if (!result.affectedRows) return null; // otro trabajador (o una cancelación) se adelantó
        return { id: Number(rows[0].id), kind: KIND, target: rows[0].target };
    }

    async function runSuite(ctx) {
        const suite = suiteRunner.suites()[ctx.target];
        const args = ['--test', '--test-reporter=tap', '--test-concurrency=1', ...suite.files];
        await ctx.emit('info', 'inicio', `Ejecutando ${suite.files.length} archivo(s): ${suite.files.join(' ')}`, { files: suite.files, db: suite.db, worker: workerId });
        if (suite.db) await ctx.emit('warn', 'bd-de-pruebas', `Esta suite vacía y recrea la BD de pruebas «${suiteRunner.testDbName()}» (no la de la aplicación)`);

        const child = spawn(process.execPath, args, {
            cwd: ROOT, env: suiteRunner.childEnv(), shell: false, windowsHide: true, detached: process.platform !== 'win32', stdio: ['ignore', 'pipe', 'pipe']
        });
        children.add(child);

        const totals = {};
        let timedOut = false;
        let killedForCancel = false;
        const handleLine = (line, isErr) => {
            if (!line.trim()) return;
            const result = TAP_RESULT.exec(line);
            if (result) {
                const [, outcome, rawName] = result;
                const skip = TAP_SKIP.exec(rawName);
                const name = skip ? rawName.slice(0, skip.index) : rawName;
                if (skip) return ctx.emit('info', 'suite', `↷ ${name} (omitida)`);
                ctx.tick();
                return ctx.emit(outcome === 'ok' ? 'pass' : 'fail', 'suite', name);
            }
            const total = TAP_TOTAL.exec(line);
            if (total) totals[total[1]] = Number(total[2]);
            return ctx.emit('output', isErr ? 'stderr' : 'stdout', line.slice(0, 500));
        };
        const pump = (stream, isErr) => {
            let pending = '';
            stream.setEncoding('utf8');
            stream.on('data', (chunk) => {
                pending += chunk;
                const lines = pending.split(/\r?\n/);
                pending = lines.pop();
                lines.forEach(l => handleLine(l, isErr));
            });
            stream.on('end', () => { if (pending) handleLine(pending, isErr); });
        };
        pump(child.stdout, false);
        pump(child.stderr, true);

        // Cancelación (se lee de la BD: la orden la da la API, otro proceso) y tiempo límite
        const watcher = setInterval(async () => {
            try {
                if (!killedForCancel && await ctx.isCancelled()) { killedForCancel = true; killTree(child); }
            } catch { /* se reintenta en el siguiente ciclo */ }
        }, 300);
        const limit = setTimeout(() => { timedOut = true; killTree(child); }, suiteRunner.timeoutMs());

        const outcome = await new Promise((resolve) => {
            child.on('error', (error) => resolve({ spawnError: error }));
            child.on('close', (code, signal) => resolve({ code, signal }));
        });
        clearInterval(watcher);
        clearTimeout(limit);
        children.delete(child);

        if (outcome.spawnError) throw new Error(`No se pudo lanzar el proceso: ${outcome.spawnError.message}`);
        const summary = { exitCode: outcome.code, signal: outcome.signal, ...totals };
        if (stopping) return { status: 'error', summary };
        if (killedForCancel) {
            await ctx.emit('warn', 'proceso', 'Proceso de pruebas terminado por la cancelación');
            return { status: 'cancelled', summary };
        }
        if (timedOut) {
            await ctx.emit('error', 'proceso', `Superó el tiempo límite (${suiteRunner.timeoutMs() / 60_000} min): proceso terminado`);
            return { status: 'error', summary };
        }
        const ok = outcome.code === 0;
        await ctx.emit(ok ? 'pass' : 'fail', 'resultado', ok ? `Suite terminada sin fallos (${totals.pass ?? '?'} correctas)` : `Suite con fallos (código de salida ${outcome.code}${totals.fail ? `, ${totals.fail} fallidas` : ''})`);
        return { status: ok ? 'passed' : 'failed', summary };
    }

    async function execute(run) {
        const ctx = runs.makeContext(run, { host: workerId });
        let status = 'passed';
        let summary;
        try {
            suiteRunner.validate(run.target); // lista cerrada validada OTRA VEZ aquí (la fila de la BD no es de fiar)
            const result = await runSuite(ctx);
            summary = result.summary;
            status = result.status;
            if (!stopping && await ctx.isCancelled()) status = 'cancelled';
        } catch (error) {
            status = 'error';
            console.error('❌ Ejecución de pruebas:', error.code || error.message);
            await ctx.emit('error', 'ejecución', String(error.message || 'Error inesperado').slice(0, 300));
        }
        if (stopping) {
            status = 'error';
            await ctx.emit('error', 'apagado', 'Ejecución interrumpida: trabajador detenido');
        }
        try {
            await runs.finish(run.id, status, summary);
        } catch (error) {
            console.error('❌ Cerrando la ejecución:', error.code || error.message);
        }
    }

    async function poll() {
        pollTimer = null;
        if (stopping) return;
        try {
            if (!busy) {
                const run = await claim();
                if (run) {
                    busy = execute(run).finally(() => { busy = null; });
                    await busy;
                }
            }
        } catch (error) {
            console.error('⚠️ Sondeo de ejecuciones:', error.code || error.message);
        }
        if (!stopping) pollTimer = setTimeout(poll, pollMs);
    }

    heartbeat().then(() => { if (!stopping) pollTimer = setTimeout(poll, 0); });
    beatTimer = setInterval(heartbeat, heartbeatMs);

    return {
        id: workerId,
        activeChildren: () => children.size,
        async stop() {
            if (stopping) return;
            stopping = true;
            clearInterval(beatTimer);
            if (pollTimer) clearTimeout(pollTimer);
            for (const child of children) killTree(child);
            if (busy) await busy.catch(() => {});
            try { await db.query('DELETE FROM ops_workers WHERE host = ?', [workerId]); } catch { /* ya sin BD */ }
        }
    };
}

async function main() {
    require('dotenv').config({ path: process.env.ENV_FILE || path.join(ROOT, '.env') });
    let worker;
    try {
        worker = startWorker();
    } catch (error) {
        console.error(`❌ El trabajador de pruebas no arranca (${error.code || 'ERROR'}): ${error.message}`);
        process.exit(1);
    }
    console.log(`✅ Trabajador de pruebas «${worker.id}» a la espera de suites (Ctrl+C para detenerlo)`);
    let closing = false;
    const shutdown = async (signal) => {
        if (closing) return;
        closing = true;
        console.log(`Recibido ${signal}: deteniendo hijos y cerrando`);
        try { await worker.stop(); } finally {
            try { await require('../src/config/database').pool.end(); } catch { /* ya cerrada */ }
            process.exit(0);
        }
    };
    for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => shutdown(signal));
}

if (require.main === module) main();

module.exports = { startWorker, checkSafeguards };
