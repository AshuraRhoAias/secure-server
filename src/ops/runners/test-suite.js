// Ejecuta suites de `node --test` desde la web y emite su salida y sus resultados EN VIVO.
//
// Salvaguardas (este ejecutor lanza procesos y las suites con BD hacen DROP DATABASE de la BD de PRUEBAS):
//   - Lista CERRADA de suites; el cliente solo elige una clave (nada de rutas ni argumentos libres).
//   - spawn SIN shell, argumentos en array, cwd = raíz del repositorio.
//   - Desactivado salvo OPS_TEST_RUNNER=true, y con NODE_ENV=production salvo además OPS_TEST_RUNNER_ALLOW_PRODUCTION=true.
//   - El hijo recibe un entorno LIMPIO (PATH y lo mínimo del sistema + variables TEST_*): nunca DB_*, semillas ni secretos de la
//     aplicación. Las pruebas usan su propia BD de pruebas (test/helpers/env.js y test_rotation.js). Guarda contra el DROP de la BD
//     real (dbGuard): se obtienen las DOS BD de pruebas (TEST_APP_DB_URL y TEST_DB_URL, con los valores por defecto de las suites) y la
//     de la aplicación (DB_FRAGMENT_1+2+3, como la construye credential-builder); se niega si no se puede determinar la de la
//     aplicación (APP_DB_UNKNOWN), si alguna de prueba coincide con ella (mismo nombre en el mismo servidor: TEST_DB_IS_APP_DB) o si
//     el nombre de una de prueba no contiene «test» (TEST_DB_NOT_TEST).
//   - gracefulShutdown llama a killAll(): mata los hijos activos y marca sus ejecuciones como canceladas («servidor detenido»).
//   - Tiempo límite (OPS_TEST_RUNNER_TIMEOUT_MIN, 20 por defecto): mata el árbol de procesos. Cancelar también lo mata.
//   - Sin node_modules de desarrollo (instalación de producción) se niega con el motivo.

const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');

const ROOT = path.resolve(__dirname, '../../..');
const children = new Set();

// clave → { label, files, db }. `db`: usa la BD de pruebas (hace DROP DATABASE de ella).
const SUITE_FILES = {
    test_api: { label: 'API sin BD (test_api)', files: ['test/test_api.js'], db: false },
    test_sanitize: { label: 'Saneado (test_sanitize)', files: ['test/test_sanitize.js'], db: true },
    test_security: { label: 'Seguridad (test_security)', files: ['test/test_security.js'], db: true },
    test_rbac: { label: 'Permisos por rol (test_rbac)', files: ['test/test_rbac.js'], db: true },
    test_sessions: { label: 'Sesiones (test_sessions)', files: ['test/test_sessions.js'], db: true },
    test_users_admin: { label: 'Usuarios desde la web (test_users_admin)', files: ['test/test_users_admin.js'], db: true },
    test_settings: { label: 'Configuración en caliente (test_settings)', files: ['test/test_settings.js'], db: true },
    test_fuzz: { label: 'Fuzzing (test_fuzz)', files: ['test/test_fuzz.js'], db: true }
};

// `all` = las mismas suites que `npm run test:all`, leídas de package.json (solo archivos test/test_*.js, sin la propia test_runs)
function allFiles() {
    try {
        const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
        const files = (pkg.scripts?.['test:all'] || '').split(/\s+/).filter(f => /^test\/test_[a-z0-9_]+\.js$/.test(f) && f !== 'test/test_runs.js');
        if (files.length) return files;
    } catch { /* se usa la lista fija */ }
    return Object.values(SUITE_FILES).flatMap(s => s.files);
}

const suites = () => ({ ...SUITE_FILES, all: { label: 'Todas (equivale a npm run test:all)', files: allFiles(), db: true } });

const timeoutMs = () => {
    const n = Number(process.env.OPS_TEST_RUNNER_TIMEOUT_MIN);
    return (Number.isFinite(n) && n > 0 ? n : 20) * 60_000;
};

// ¿Está permitido lanzar suites? { enabled, reason }
function availability() {
    if (process.env.OPS_TEST_RUNNER !== 'true') return { enabled: false, reason: 'Desactivado: define OPS_TEST_RUNNER=true en el entorno del servidor para permitir ejecutar suites' };
    if (process.env.NODE_ENV === 'production' && process.env.OPS_TEST_RUNNER_ALLOW_PRODUCTION !== 'true') {
        return { enabled: false, reason: 'Bloqueado en producción: hace falta además OPS_TEST_RUNNER_ALLOW_PRODUCTION=true' };
    }
    if (!fs.existsSync(path.join(ROOT, 'node_modules', 'eslint')) || !fs.existsSync(path.join(ROOT, 'test', 'helpers', 'env.js'))) {
        return { enabled: false, reason: 'Sin dependencias de desarrollo ni carpeta test/ (instalación de producción): no se pueden ejecutar suites', conflict: true };
    }
    return { enabled: true, reason: null };
}

// Valores por defecto IDÉNTICOS a los de test/helpers/env.js (TEST_APP_DB_URL) y test/test_rotation.js (TEST_DB_URL)
const DEFAULT_TEST_APP_DB_URL = 'mysql://sec:sec_test_pw@127.0.0.1:3306/secure_platform_test_app';
const DEFAULT_TEST_DB_URL = 'mysql://sec:sec_test_pw@127.0.0.1:3306/secure_platform_test';

// { host, port, name } de una URL de BD, o null si no se puede interpretar. localhost/127.0.0.1/::1/0.0.0.0 se normalizan a «localhost»
function dbTarget(urlText) {
    try {
        const url = new URL(urlText);
        let host = url.hostname.toLowerCase().replace(/^\[|\]$/g, '');
        if (['localhost', '127.0.0.1', '::1', '0.0.0.0', ''].includes(host)) host = 'localhost';
        const name = decodeURIComponent(url.pathname.replace(/^\//, '')).toLowerCase();
        if (!name) return null;
        return { host, port: url.port || '3306', name };
    } catch { return null; }
}

// Guarda contra el DROP DATABASE de la BD real. Devuelve null si todo está bien, o { code, message } (se traduce a 409).
function dbGuard(env = process.env) {
    const tests = [
        ['TEST_APP_DB_URL', dbTarget(env.TEST_APP_DB_URL || DEFAULT_TEST_APP_DB_URL)],
        ['TEST_DB_URL', dbTarget(env.TEST_DB_URL || DEFAULT_TEST_DB_URL)]
    ];
    const app = dbTarget(`${env.DB_FRAGMENT_1 || ''}${env.DB_FRAGMENT_2 || ''}${env.DB_FRAGMENT_3 || ''}`);
    if (!app) return { code: 'APP_DB_UNKNOWN', message: 'No se pudo determinar la BD de la aplicación (DB_FRAGMENT_1/2/3): por seguridad no se lanzan suites que borran bases de datos' };
    for (const [variable, target] of tests) {
        if (!target) return { code: 'TEST_DB_NOT_TEST', message: `${variable} no es una URL de BD válida con nombre de base de datos` };
        if (target.host === app.host && target.port === app.port && target.name === app.name) {
            return { code: 'TEST_DB_IS_APP_DB', message: `${variable} apunta a la BD de la aplicación: las suites con BD la destruirían. Usa otra` };
        }
        if (!/test/.test(target.name)) {
            return { code: 'TEST_DB_NOT_TEST', message: `El nombre de la BD de ${variable} («${target.name}») debe contener «test»: las suites la borran y recrean` };
        }
    }
    return null;
}

const testDbName = () => dbTarget(process.env.TEST_APP_DB_URL || DEFAULT_TEST_APP_DB_URL)?.name || '';

function describe() {
    const a = availability();
    return {
        title: 'Suites de pruebas',
        description: 'Ejecuta node --test sobre una lista cerrada de suites y muestra su salida en vivo. Las suites con BD usan la BD de PRUEBAS (se vacía), nunca la de la aplicación.',
        enabled: a.enabled, reason: a.reason, timeoutMin: timeoutMs() / 60_000,
        warning: `Las suites marcadas «BD» borran y recrean la base de datos de pruebas «${testDbName()}», no la de la aplicación.`,
        suites: Object.entries(suites()).map(([value, s]) => ({ value, label: s.label, db: s.db }))
    };
}

function validate(target) {
    const { RunError } = require('../runs.service');
    const a = availability();
    if (!a.enabled) throw new RunError(a.conflict ? 'NO_DEV_DEPS' : 'TEST_RUNNER_DISABLED', a.reason, a.conflict ? 409 : 403);
    const all = suites();
    const suite = Object.hasOwn(all, target || '') ? all[target] : null;
    if (!suite) throw new RunError('INVALID_TARGET', 'Suite fuera de la lista permitida', 400);
    if (suite.db) {
        const problem = dbGuard();
        if (problem) throw new RunError(problem.code, problem.message, 409);
    }
}

// Entorno limpio del hijo: solo lo mínimo del sistema y las variables TEST_* (la BD de pruebas); nada de la aplicación
function childEnv() {
    const keep = ['PATH', 'Path', 'SystemRoot', 'SYSTEMROOT', 'windir', 'ComSpec', 'TEMP', 'TMP', 'TMPDIR', 'HOME', 'USERPROFILE', 'LANG', 'LC_ALL', 'TZ'];
    const env = {};
    for (const [name, value] of Object.entries(process.env)) {
        if (keep.includes(name) || /^TEST_[A-Z0-9_]+$/.test(name)) env[name] = value;
    }
    env.NODE_ENV = 'test';
    return env;
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

// Mata todos los hijos activos (apagado del servidor). Devuelve cuántos había.
function killAll() {
    const n = children.size;
    for (const child of children) killTree(child);
    return n;
}

const TAP_RESULT =/^\s*(not ok|ok) \d+ - (.*)$/;
const TAP_SKIP = / # (?:SKIP|TODO)\b/;
const TAP_TOTAL = /^# (tests|pass|fail|skipped|cancelled|todo) (\d+)/;

async function run(ctx) {
    const suite = suites()[ctx.target];
    const args = ['--test', '--test-reporter=tap', '--test-concurrency=1', ...suite.files];
    await ctx.emit('info', 'inicio', `Ejecutando ${suite.files.length} archivo(s): ${suite.files.join(' ')}`, { files: suite.files, db: suite.db });
    if (suite.db) await ctx.emit('warn', 'bd-de-pruebas', `Esta suite vacía y recrea la BD de pruebas «${testDbName()}» (no la de la aplicación)`);

    const child = spawn(process.execPath, args, {
        cwd: ROOT, env: childEnv(), shell: false, windowsHide: true, detached: process.platform !== 'win32', stdio: ['ignore', 'pipe', 'pipe']
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

    // Cancelación (vale también si la orden se dio en otra réplica: se lee de la BD) y tiempo límite
    const watcher = setInterval(async () => {
        try {
            if (!killedForCancel && await ctx.isCancelled()) { killedForCancel = true; killTree(child); }
        } catch { /* se reintenta en el siguiente ciclo */ }
    }, 300);
    const limit = setTimeout(() => { timedOut = true; killTree(child); }, timeoutMs());

    const outcome = await new Promise((resolve) => {
        child.on('error', (error) => resolve({ spawnError: error }));
        child.on('close', (code, signal) => resolve({ code, signal }));
    });
    clearInterval(watcher);
    clearTimeout(limit);
    children.delete(child);

    if (outcome.spawnError) throw new Error(`No se pudo lanzar el proceso: ${outcome.spawnError.message}`);
    const summary = { exitCode: outcome.code, signal: outcome.signal, ...totals };
    if (killedForCancel) {
        await ctx.emit('warn', 'proceso', 'Proceso de pruebas terminado por la cancelación');
        return { status: 'cancelled', summary };
    }
    if (timedOut) {
        await ctx.emit('error', 'proceso', `Superó el tiempo límite (${timeoutMs() / 60_000} min): proceso terminado`);
        return { status: 'error', summary };
    }
    const ok = outcome.code === 0;
    await ctx.emit(ok ? 'pass' : 'fail', 'resultado', ok ? `Suite terminada sin fallos (${totals.pass ?? '?'} correctas)` : `Suite con fallos (código de salida ${outcome.code}${totals.fail ? `, ${totals.fail} fallidas` : ''})`);
    return { status: ok ? 'passed' : 'failed', summary };
}

module.exports = { run, validate, describe, availability, childEnv, dbGuard, dbTarget, killAll, SUITE_FILES, activeChildren: () => children.size };
