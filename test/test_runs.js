// Pruebas en vivo (FASE 3): diagnóstico, simulación de ataques y suites de npm lanzados desde la API, con su registro en la BD.
// MariaDB real. IMPORTANTE: aquí NO se lanzan suites que usen la BD (borrarían la BD de la propia prueba): solo test_api (sin BD).
//
//   node --test test/test_runs.js

const test = require('node:test');
const assert = require('node:assert');

require('./helpers/env');
const helpers = require('./helpers/app');
const { api, registerAndLogin, testIp } = helpers;

let app, db, runsService, enabled = false;

test.before(async () => {
    enabled = await helpers.prepareDatabase();
    if (!enabled) return;
    db = require('../src/config/database');
    runsService = require('../src/ops/runs.service');
    app = await helpers.startApp();
});
test.after(async () => {
    if (!enabled) return;
    await app.close();
    await db.pool.end();
});

const itDb = (name, fn) => test(name, async (t) => { if (!enabled) return t.skip('sin BD'); await fn(t); });

async function userWithRole(role) {
    const ip = testIp();
    const user = await registerAndLogin(app.base, { ip });
    if (role !== 'user') await db.query('UPDATE users SET role = ? WHERE id = ?', [role, user.userId]);
    return { ...user, ip, role };
}
const call = (user, method, route, json) => api(app.base, method, route, { token: user.token, ip: user.ip, json });
const start = (user, kind, target) => call(user, 'POST', '/api/system/runs', { kind, ...(target !== undefined ? { target } : {}) });

// Sondea hasta que la ejecución termina y devuelve todos sus eventos (como hace la web)
async function waitDone(user, id, { timeoutMs = 60_000 } = {}) {
    const events = [];
    let afterSeq = 0;
    const deadline = Date.now() + timeoutMs;
    for (;;) {
        const r = await call(user, 'GET', `/api/system/runs/${id}?afterSeq=${afterSeq}`);
        assert.strictEqual(r.status, 200, r.text);
        events.push(...r.body.events);
        afterSeq = r.body.lastSeq;
        if (!['queued', 'running'].includes(r.body.run.status) && !r.body.hasMore && r.body.events.length === 0) return { run: r.body.run, events };
        if (Date.now() > deadline) throw new Error(`la ejecución ${id} no terminó (${r.body.run.status})`);
        await new Promise(resolve => setTimeout(resolve, 150));
    }
}

// Las ejecuciones usan una BD compartida y solo se admite una activa por tipo: se espera a que no quede ninguna viva
async function idle() {
    for (let i = 0; i < 200; i++) {
        // también las canceladas que aún no liberaron su tipo (active_kind): lo libera `finish` cuando el ejecutor termina de verdad
        const [rows] = await db.query("SELECT COUNT(*) AS n FROM ops_runs WHERE status IN ('queued', 'running') OR active_kind IS NOT NULL");
        if (Number(rows[0].n) === 0) return;
        await new Promise(resolve => setTimeout(resolve, 150));
    }
}

// ============================================================================ permisos y validación

itDb('permisos: solo admin ve y lanza; otros roles 403; sin sesión 401', async () => {
    for (const role of ['user', 'auditor', 'operator']) {
        const u = await userWithRole(role);
        assert.strictEqual((await call(u, 'GET', '/api/system/runs')).status, 403, role);
        assert.strictEqual((await call(u, 'GET', '/api/system/runs/catalog')).status, 403, role);
        assert.strictEqual((await start(u, 'diagnostic')).status, 403, role);
        assert.strictEqual((await call(u, 'POST', '/api/system/runs/1/cancel')).status, 403, role);
    }
    assert.strictEqual((await api(app.base, 'GET', '/api/system/runs', { ip: testIp() })).status, 401);
});

itDb('validación: tipo desconocido 400, destino no válido 400, ejecución inexistente 404', async () => {
    const admin = await userWithRole('admin');
    assert.strictEqual((await start(admin, 'rm_rf')).status, 400);
    assert.strictEqual((await call(admin, 'POST', '/api/system/runs', {})).status, 400);
    const bad = await start(admin, 'diagnostic', 'otra-cosa');
    assert.strictEqual(bad.status, 400);
    assert.strictEqual(bad.body.code, 'INVALID_TARGET');
    assert.strictEqual((await call(admin, 'GET', '/api/system/runs/999999')).status, 404);
    assert.strictEqual((await call(admin, 'POST', '/api/system/runs/999999/cancel')).status, 404);
    assert.strictEqual((await call(admin, 'GET', '/api/system/runs/abc')).status, 400);
});

itDb('catálogo: tres tipos y el estado del runner de suites', async () => {
    const admin = await userWithRole('admin');
    const r = await call(admin, 'GET', '/api/system/runs/catalog');
    assert.strictEqual(r.status, 200);
    assert.deepStrictEqual(r.body.kinds.map(k => k.kind), ['diagnostic', 'attack_sim', 'test_suite']);
});

// ============================================================================ diagnóstico

itDb('diagnóstico: termina passed, eventos con seq creciente y sondeo incremental por afterSeq', async () => {
    const admin = await userWithRole('admin');
    const started = await start(admin, 'diagnostic');
    assert.strictEqual(started.status, 202, started.text);
    assert.strictEqual(started.body.run.kind, 'diagnostic');

    const { run, events } = await waitDone(admin, started.body.run.id);
    const failures = events.filter(e => e.level === 'fail' || e.level === 'error');
    assert.strictEqual(run.status, 'passed', `fallos: ${JSON.stringify(failures)}`);
    assert.ok(run.finishedAt);
    assert.ok(events.length >= 20);
    // seq estrictamente creciente y sin huecos
    events.forEach((e, i) => assert.strictEqual(e.seq, i + 1));
    const steps = new Set(events.map(e => e.step));
    for (const s of ['base-de-datos', 'cifrado', 'integridad', 'almacenamiento', 'canales', 'reloj', 'recursos', 'rotacion', 'lider']) assert.ok(steps.has(s), `falta el paso ${s}`);
    assert.ok(events.some(e => e.level === 'pass' && /\(\d+ ms\)$/.test(e.message)), 'cada resultado lleva su duración');
    assert.ok(run.summary.pass >= 10);

    // Sondeo incremental: desde la mitad solo llegan los posteriores
    const half = Math.floor(events.length / 2);
    const tail = await call(admin, 'GET', `/api/system/runs/${run.id}?afterSeq=${half}`);
    assert.strictEqual(tail.body.events.length, events.length - half);
    assert.strictEqual(tail.body.events[0].seq, half + 1);
    const none = await call(admin, 'GET', `/api/system/runs/${run.id}?afterSeq=${events.length}`);
    assert.strictEqual(none.body.events.length, 0);

    // Aparece en el historial y deja eventos de seguridad
    const list = await call(admin, 'GET', '/api/system/runs?limit=5');
    assert.ok(list.body.runs.some(r => r.id === run.id));
    const [ev] = await db.query("SELECT COUNT(*) AS n FROM security_events WHERE event_type = 'OPS_RUN_STARTED'");
    assert.ok(Number(ev[0].n) >= 1);
});

itDb('una sola ejecución activa por tipo: la segunda recibe 409 RUN_IN_PROGRESS; cancelar libera el tipo', async () => {
    await idle();
    const admin = await userWithRole('admin');
    const first = await start(admin, 'diagnostic');
    assert.strictEqual(first.status, 202);
    const second = await start(admin, 'diagnostic');
    assert.strictEqual(second.status, 409);
    assert.strictEqual(second.body.code, 'RUN_IN_PROGRESS');
    const cancelled = await call(admin, 'POST', `/api/system/runs/${first.body.run.id}/cancel`);
    assert.ok([200, 409].includes(cancelled.status), cancelled.text); // 409 si ya había terminado
    const { run } = await waitDone(admin, first.body.run.id);
    assert.ok(['cancelled', 'passed'].includes(run.status), run.status);
    const again = await call(admin, 'POST', `/api/system/runs/${first.body.run.id}/cancel`);
    assert.strictEqual(again.status, 409);
    await idle();
});

itDb('recoverStale: una ejecución viva de un proceso muerto pasa a error y libera el tipo', async () => {
    await idle();
    await db.query("INSERT INTO ops_runs (kind, status, active_kind, host) VALUES ('diagnostic', 'running', 'diagnostic', ?)", [`${require('os').hostname()}:2147483646`]);
    const recovered = await runsService.recoverStale();
    assert.ok(recovered >= 1);
    const [rows] = await db.query("SELECT status, active_kind FROM ops_runs WHERE host LIKE '%:2147483646'");
    assert.strictEqual(rows[0].status, 'error');
    assert.strictEqual(rows[0].active_kind, null);
});

// ============================================================================ simulación de ataques

itDb('simulación de ataques: detecta SQLi, JWT falso y fuerza bruta, y limpia IP bloqueadas y usuarios temporales', async () => {
    await idle();
    const admin = await userWithRole('admin');
    const [[before]] = [await db.query('SELECT COUNT(*) AS n FROM users')].map(r => r[0]);
    const started = await start(admin, 'attack_sim');
    assert.strictEqual(started.status, 202, started.text);
    const { run, events } = await waitDone(admin, started.body.run.id, { timeoutMs: 120_000 });
    const bad = events.filter(e => e.level === 'fail' || e.level === 'error');
    assert.strictEqual(run.status, 'passed', `fallos: ${JSON.stringify(bad)}`);

    const attacks = run.summary.attacks;
    for (const name of ['Inyección SQL (login)', 'JWT falsificado', 'Fuerza bruta', 'Subida de ejecutable', 'Payload enorme']) {
        const a = attacks.find(x => x.name === name);
        assert.ok(a && a.blocked, `no se bloqueó: ${name} (${JSON.stringify(attacks)})`);
    }
    assert.ok(run.summary.recorded >= 2, 'al menos la SQLi y la fuerza bruta dejan eventos de seguridad');
    for (const step of ['sqli-login', 'jwt-falso', 'fuerza-bruta', 'limpieza']) assert.ok(events.some(e => e.step === step && e.level !== 'info'), `falta ${step}`);
    const clean = events.find(e => e.step === 'limpieza' && e.level !== 'info');
    assert.strictEqual(clean.level, 'pass', clean.message);

    // Sin rastro: ninguna IP de prueba bloqueada y ningún usuario temporal
    // (solo las IP de ESTA simulación: otras pruebas usan también 203.0.113.x con testIp())
    const simIps = [`203.0.113.${100 + ((run.id * 2) % 100)}`, `203.0.113.${101 + ((run.id * 2) % 100)}`];
    const [blocked] = await db.query('SELECT ip_address FROM blocked_ips WHERE ip_address IN (?, ?)', simIps);
    assert.strictEqual(blocked.length, 0, JSON.stringify(blocked));
    // ... y ningún estado por IP: intentos de login ni contadores de límite de las IP de documentación
    const [attempts] = await db.query("SELECT COUNT(*) AS n FROM login_attempts WHERE ip_address IN (?, ?) OR ip_subject IN (?, ?)", [...simIps, ...simIps]);
    assert.strictEqual(Number(attempts[0].n), 0, 'login_attempts de las IP de prueba');
    const [counters] = await db.query("SELECT COUNT(*) AS n FROM rate_limit_counters WHERE subject LIKE ? OR subject LIKE ?", simIps.map(ip => `%${ip}`));
    assert.strictEqual(Number(counters[0].n), 0, 'rate_limit_counters de las IP de prueba');
    const [after] = await db.query('SELECT COUNT(*) AS n FROM users');
    assert.strictEqual(Number(after[0].n), Number(before.n));
    // El registro no contiene contraseñas ni tokens
    const all = JSON.stringify(events);
    assert.ok(!/eyJ[A-Za-z0-9_-]{10,}\./.test(all), 'no debe haber JWT en el registro');
    assert.ok(!/Sim-[A-Za-z0-9]{14}-1/.test(all), 'no debe haber contraseñas en el registro');
    await idle();
});

itDb('simulación de ataques: sin confianza en el proxy NO ejecuta ningún ataque y no deja estado por IP (ni loopback)', async () => {
    const sim = require('../src/ops/runners/attack-sim');
    const results = [];
    const emitted = [];
    const ctx = {
        runId: 7, trustsForwardedFor: false, port: 1, // el puerto no se usa: no debe salir ninguna petición
        emit: async (level, step, message) => { emitted.push({ level, step, message }); },
        isCancelled: async () => false, setTotal() {}, tick() {},
        step: async (name, announce, fn) => { results.push({ name, ...(await fn()) }); }
    };
    const out = await sim.run(ctx);
    assert.ok(results.length >= 10, 'recorre los pasos');
    for (const r of results) assert.strictEqual(r.level, 'warn', `${r.name} debe omitirse con warn: ${JSON.stringify(r)}`);
    assert.ok(results.every(r => /TRUST_PROXY|Omitido/.test(r.message)));
    assert.strictEqual(out.summary.total, 0, 'ningún ataque ejecutado');
    assert.ok(emitted.some(e => e.step === 'configuracion' && e.level === 'warn'));
    const [b] = await db.query("SELECT COUNT(*) AS n FROM blocked_ips WHERE ip_address = '127.0.0.1'");
    assert.strictEqual(Number(b[0].n), 0, 'el loopback no queda bloqueado');
});

itDb('simulación de ataques: no admite destino (400)', async () => {
    await idle();
    const admin = await userWithRole('admin');
    const r = await start(admin, 'attack_sim', 'http-evil');
    assert.strictEqual(r.status, 400);
    assert.strictEqual(r.body.code, 'INVALID_TARGET');
});

// ============================================================================ suites de npm (solo test_api: NO usa la BD)
// El servidor solo ENCOLA; las corre el trabajador de scripts/ops-test-runner.js, que aquí se arranca EN EL PROCESO DE LA PRUEBA.

const suiteRunner = () => require('../src/ops/runners/test-suite');
const workerModule = () => require('../scripts/ops-test-runner');
const appEnv = (name = 'secure_platform', host = 'localhost:3306') => ({ DB_FRAGMENT_1: 'mysql://u:p@', DB_FRAGMENT_2: host, DB_FRAGMENT_3: `/${name}` });
const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

// Arranca N trabajadores (con la guarda de BD alimentada por un entorno propio: en la prueba la BD de la app ES la de pruebas)
async function withWorkers(count, fn) {
    const previous = process.env.OPS_TEST_RUNNER;
    process.env.OPS_TEST_RUNNER = 'true';
    await db.query('DELETE FROM ops_workers');
    const workers = [];
    try {
        for (let i = 0; i < count; i++) workers.push(workerModule().startWorker({ pollMs: 100, heartbeatMs: 500, id: `prueba-${i}:${process.pid}`, guardEnv: appEnv() }));
        for (let i = 0; i < 100; i++) { // espera al primer latido
            const [rows] = await db.query('SELECT COUNT(*) AS n FROM ops_workers');
            if (Number(rows[0].n) >= count) break;
            await sleep(50);
        }
        await fn(workers);
    } finally {
        await Promise.all(workers.map(w => w.stop()));
        await db.query('DELETE FROM ops_workers');
        if (previous === undefined) delete process.env.OPS_TEST_RUNNER; else process.env.OPS_TEST_RUNNER = previous;
    }
}
const anyChildren = (workers) => workers.reduce((n, w) => n + w.activeChildren(), 0);

itDb('suites: sin trabajador vivo => 409 TEST_RUNNER_OFFLINE, no queda fila y el catálogo lo cuenta', async () => {
    await idle();
    await db.query('DELETE FROM ops_workers');
    const admin = await userWithRole('admin');
    const r = await start(admin, 'test_suite', 'test_api');
    assert.strictEqual(r.status, 409, r.text);
    assert.strictEqual(r.body.code, 'TEST_RUNNER_OFFLINE');
    assert.match(r.body.message, /npm run ops:test-runner/);
    const [n] = await db.query("SELECT COUNT(*) AS n FROM ops_runs WHERE kind = 'test_suite'");
    assert.strictEqual(Number(n[0].n), 0, 'no se crea ninguna ejecución sin trabajador');
    const cat = await call(admin, 'GET', '/api/system/runs/catalog');
    assert.strictEqual(cat.body.testRunner.online, false);
    assert.match(cat.body.testRunner.reason, /ops:test-runner/);
    const suites = cat.body.kinds.find(k => k.kind === 'test_suite');
    assert.strictEqual(suites.enabled, false);
    // un latido viejo (> 15 s) tampoco cuenta
    await db.query("INSERT INTO ops_workers (host, kind, pid, last_seen) VALUES ('viejo:1', 'test_suite', 1, DATE_SUB(CURRENT_TIMESTAMP(3), INTERVAL 60 SECOND))");
    try {
        assert.strictEqual((await start(admin, 'test_suite', 'test_api')).status, 409);
    } finally { await db.query('DELETE FROM ops_workers'); }
});

itDb('suites: con latido reciente el catálogo informa del trabajador (online, host, lastSeen)', async () => {
    await withWorkers(1, async (workers) => {
        const admin = await userWithRole('admin');
        const cat = await call(admin, 'GET', '/api/system/runs/catalog');
        assert.strictEqual(cat.body.testRunner.online, true);
        assert.strictEqual(cat.body.testRunner.host, workers[0].id);
        assert.ok(cat.body.testRunner.lastSeen);
        assert.strictEqual(cat.body.testRunner.reason, null);
        assert.strictEqual(cat.body.kinds.find(k => k.kind === 'test_suite').enabled, true);
    });
});

test('trabajador: las salvaguardas impiden arrancarlo (desactivado, producción, BD de pruebas = BD de la app)', () => {
    const { checkSafeguards, startWorker } = workerModule();
    assert.strictEqual(checkSafeguards({}).code, 'TEST_RUNNER_DISABLED');
    assert.strictEqual(checkSafeguards({ OPS_TEST_RUNNER: 'true', NODE_ENV: 'production' }).code, 'TEST_RUNNER_PRODUCTION');
    // con el permiso explícito deja de bloquear por producción
    assert.notStrictEqual(checkSafeguards({ OPS_TEST_RUNNER: 'true', NODE_ENV: 'production', OPS_TEST_RUNNER_ALLOW_PRODUCTION: 'true' }, appEnv())?.code, 'TEST_RUNNER_PRODUCTION');
    // dbGuard: BD de la app indeterminable, igual a la de pruebas, o nombre sin «test»
    const ok = { OPS_TEST_RUNNER: 'true' };
    assert.strictEqual(checkSafeguards(ok, {}).code, 'APP_DB_UNKNOWN');
    assert.strictEqual(checkSafeguards(ok, appEnv('secure_platform_test_app', '127.0.0.1:3306')).code, 'TEST_DB_IS_APP_DB');
    assert.strictEqual(checkSafeguards(ok, { ...appEnv(), TEST_DB_URL: 'mysql://a:b@localhost/otra' }).code, 'TEST_DB_NOT_TEST');
    assert.strictEqual(checkSafeguards(ok, appEnv()), null);

    // y startWorker se niega de verdad (lanza con el código), sin dejar timers ni latido
    const saved = { runner: process.env.OPS_TEST_RUNNER, env: process.env.NODE_ENV };
    try {
        delete process.env.OPS_TEST_RUNNER;
        assert.throws(() => startWorker({ guardEnv: appEnv() }), (e) => e.code === 'TEST_RUNNER_DISABLED');
        process.env.OPS_TEST_RUNNER = 'true';
        assert.throws(() => startWorker({ guardEnv: appEnv('secure_platform_test', 'localhost') }), (e) => e.code === 'TEST_DB_IS_APP_DB');
        process.env.NODE_ENV = 'production';
        assert.throws(() => startWorker({ guardEnv: appEnv() }), (e) => e.code === 'TEST_RUNNER_PRODUCTION');
    } finally {
        if (saved.runner === undefined) delete process.env.OPS_TEST_RUNNER; else process.env.OPS_TEST_RUNNER = saved.runner;
        process.env.NODE_ENV = saved.env;
    }
});

itDb('suites: el entorno del hijo es limpio (sin DB_*, semillas ni secretos de la aplicación)', () => {
    process.env.TEST_APP_DB_URL_PROBE = 'visible';
    process.env.MI_SECRETO = 'x';
    try {
        const env = suiteRunner().childEnv();
        for (const name of Object.keys(env)) assert.ok(!/^DB_|SEED|SECRET|JWT|PASSWORD|TOKEN/i.test(name), `variable filtrada: ${name}`);
        assert.strictEqual(env.TEST_APP_DB_URL_PROBE, 'visible');
        assert.strictEqual(env.MI_SECRETO, undefined);
        assert.strictEqual(env.DB_FRAGMENT_1, undefined);
        assert.strictEqual(env.BASE_SEED, undefined);
        assert.ok(env.PATH || env.Path);
    } finally {
        delete process.env.TEST_APP_DB_URL_PROBE;
        delete process.env.MI_SECRETO;
    }
});

itDb('suites: una suite fuera de la lista (o con ruta/argumentos) da 400; sin destino también', async () => {
    const admin = await userWithRole('admin');
    for (const target of ['test_inexistente', 'test_api-js', 'etc', 'all2']) {
        const r = await start(admin, 'test_suite', target);
        assert.strictEqual(r.status, 400, `${target}: ${r.text}`);
    }
    // caracteres de ruta o de shell ni siquiera pasan la validación de la ruta
    for (const target of ['../test_api', 'test_api;ls', 'test_api && id', '$(id)']) {
        assert.strictEqual((await start(admin, 'test_suite', target)).status, 400, target);
    }
    assert.strictEqual((await start(admin, 'test_suite')).status, 400);
});

itDb('suites: se encola (202 queued), el trabajador la reclama, la ejecuta y emite líneas y resultados en vivo', async () => {
    await idle();
    await withWorkers(1, async (workers) => {
        const admin = await userWithRole('admin');
        const started = await start(admin, 'test_suite', 'test_api');
        assert.strictEqual(started.status, 202, started.text);
        assert.strictEqual(started.body.run.status, 'queued');

        // dos a la vez: 409
        const second = await start(admin, 'test_suite', 'test_api');
        assert.strictEqual(second.status, 409);
        assert.strictEqual(second.body.code, 'RUN_IN_PROGRESS');

        const { run, events } = await waitDone(admin, started.body.run.id, { timeoutMs: 180_000 });
        const bad = events.filter(e => e.level === 'fail' || e.level === 'error');
        assert.strictEqual(run.status, 'passed', `fallos: ${JSON.stringify(bad.slice(0, 3))}`);
        assert.strictEqual(run.host, workers[0].id, 'la ejecuta el trabajador, no el servidor');
        assert.strictEqual(run.summary.exitCode, 0);
        assert.ok(run.summary.pass >= 5, JSON.stringify(run.summary));
        assert.ok(events.filter(e => e.level === 'pass' && e.step === 'suite').length >= 5, 'resultados por subprueba');
        assert.ok(events.some(e => e.level === 'output'), 'líneas de salida');
        events.forEach((e, i) => assert.strictEqual(e.seq, i + 1));
        assert.strictEqual(anyChildren(workers), 0);
        await idle();
    });
});

itDb('suites: cancelar una en curso mata el hijo y el tipo NO se libera hasta que el hijo cierra (409 mientras tanto)', async () => {
    await idle();
    await withWorkers(1, async (workers) => {
        const admin = await userWithRole('admin');
        const started = await start(admin, 'test_suite', 'test_api');
        assert.strictEqual(started.status, 202, started.text);
        for (let i = 0; i < 200 && anyChildren(workers) === 0; i++) await sleep(50); // el trabajador la reclamó y lanzó el hijo
        assert.strictEqual(anyChildren(workers), 1, 'debe haber un hijo en marcha');
        const cancelled = await call(admin, 'POST', `/api/system/runs/${started.body.run.id}/cancel`);
        assert.strictEqual(cancelled.status, 200, cancelled.text);
        assert.strictEqual(cancelled.body.run.status, 'cancelled');
        // el hijo aún no ha cerrado (el vigilante lo mata en <= 300 ms y luego cierra): lanzar otra suite al instante => 409
        const again = await start(admin, 'test_suite', 'test_api');
        assert.strictEqual(again.status, 409, again.text);
        assert.strictEqual(again.body.code, 'RUN_IN_PROGRESS');
        const [held] = await db.query('SELECT active_kind FROM ops_runs WHERE id = ?', [started.body.run.id]);
        assert.strictEqual(held[0].active_kind, 'test_suite');
        // y el hijo desaparece; entonces `finish` libera el tipo
        for (let i = 0; i < 100 && anyChildren(workers) > 0; i++) await sleep(100);
        assert.strictEqual(anyChildren(workers), 0, 'el proceso hijo debe haber terminado');
        await idle();
        const [freed] = await db.query('SELECT status, active_kind FROM ops_runs WHERE id = ?', [started.body.run.id]);
        assert.strictEqual(freed[0].status, 'cancelled');
        assert.strictEqual(freed[0].active_kind, null);
    });
});

itDb('suites: cancelar una encolada (sin reclamar) la marca cancelled y libera el tipo directamente', async () => {
    await idle();
    // latido falso: hay «trabajador» pero ninguno reclama
    await db.query("INSERT INTO ops_workers (host, kind, pid) VALUES ('falso:1', 'test_suite', 1) ON DUPLICATE KEY UPDATE last_seen = CURRENT_TIMESTAMP(3)");
    try {
        const admin = await userWithRole('admin');
        const started = await start(admin, 'test_suite', 'test_api');
        assert.strictEqual(started.status, 202, started.text);
        assert.strictEqual(started.body.run.status, 'queued');
        const cancelled = await call(admin, 'POST', `/api/system/runs/${started.body.run.id}/cancel`);
        assert.strictEqual(cancelled.status, 200, cancelled.text);
        assert.strictEqual(cancelled.body.run.status, 'cancelled');
        const [row] = await db.query('SELECT status, active_kind FROM ops_runs WHERE id = ?', [started.body.run.id]);
        assert.strictEqual(row[0].active_kind, null, 'el tipo queda libre al instante');
        assert.strictEqual((await call(admin, 'POST', `/api/system/runs/${started.body.run.id}/cancel`)).status, 409);
    } finally {
        await db.query('DELETE FROM ops_workers');
        await idle();
    }
});

itDb('suites: dos trabajadores no reclaman la misma ejecución', async () => {
    await idle();
    await withWorkers(2, async (workers) => {
        const admin = await userWithRole('admin');
        const started = await start(admin, 'test_suite', 'test_api');
        assert.strictEqual(started.status, 202, started.text);
        const { run, events } = await waitDone(admin, started.body.run.id, { timeoutMs: 180_000 });
        assert.strictEqual(run.status, 'passed');
        assert.ok(workers.map(w => w.id).includes(run.host));
        assert.strictEqual(events.filter(e => e.step === 'inicio').length, 1, 'solo un trabajador la ejecutó');
        assert.strictEqual(events.filter(e => e.step === 'resultado').length, 1);
        await idle();
    });
});

itDb('suites: al detener el trabajador mata el hijo y marca la ejecución como error «trabajador detenido»', async () => {
    await idle();
    let runId;
    const admin = await userWithRole('admin');
    await withWorkers(1, async (workers) => {
        const started = await start(admin, 'test_suite', 'test_api');
        assert.strictEqual(started.status, 202, started.text);
        runId = started.body.run.id;
        for (let i = 0; i < 200 && anyChildren(workers) === 0; i++) await sleep(50);
        assert.strictEqual(anyChildren(workers), 1);
        await workers[0].stop();
        assert.strictEqual(anyChildren(workers), 0);
    });
    const r = await call(admin, 'GET', `/api/system/runs/${runId}`);
    assert.strictEqual(r.body.run.status, 'error');
    assert.ok(r.body.events.some(e => e.step === 'apagado' && /trabajador detenido/.test(e.message)));
    await idle();
    const [row] = await db.query('SELECT active_kind FROM ops_runs WHERE id = ?', [runId]);
    assert.strictEqual(row[0].active_kind, null);
});

// ============================================================================ guarda de BD, redacción y cola (unitarias, sin lanzar suites)

test('dbGuard: valores por defecto de las suites con una app distinta => permitido', () => {
    assert.strictEqual(suiteRunner().dbGuard({ ...appEnv() }), null);
});
test('dbGuard: no se puede determinar la BD de la aplicación => APP_DB_UNKNOWN', () => {
    assert.strictEqual(suiteRunner().dbGuard({}).code, 'APP_DB_UNKNOWN');
    assert.strictEqual(suiteRunner().dbGuard({ DB_FRAGMENT_1: 'mysql://u:p@', DB_FRAGMENT_2: 'h' }).code, 'APP_DB_UNKNOWN');
});
test('dbGuard: TEST_APP_DB_URL o TEST_DB_URL iguales a la de la app (localhost = 127.0.0.1) => TEST_DB_IS_APP_DB', () => {
    const g = suiteRunner().dbGuard;
    assert.strictEqual(g({ ...appEnv('secure_platform_test_app', '127.0.0.1:3306') }).code, 'TEST_DB_IS_APP_DB'); // por defecto de TEST_APP_DB_URL
    assert.strictEqual(g({ ...appEnv('secure_platform_test', 'localhost') }).code, 'TEST_DB_IS_APP_DB');          // por defecto de TEST_DB_URL
    assert.strictEqual(g({ ...appEnv('mi_bd_test'), TEST_APP_DB_URL: 'mysql://a:b@127.0.0.1:3306/mi_bd_test' }).code, 'TEST_DB_IS_APP_DB');
    assert.strictEqual(g({ ...appEnv('mi_bd_test'), TEST_DB_URL: 'mysql://a:b@[::1]/MI_BD_TEST' }).code, 'TEST_DB_IS_APP_DB');
    // mismo nombre en OTRO servidor: no es la misma BD
    assert.strictEqual(g({ ...appEnv('secure_platform_test_app', 'db.interna:3306') }), null);
});
test('dbGuard: nombres de prueba sin «test» => TEST_DB_NOT_TEST', () => {
    const g = suiteRunner().dbGuard;
    assert.strictEqual(g({ ...appEnv(), TEST_APP_DB_URL: 'mysql://a:b@localhost/secure_platform_prod' }).code, 'TEST_DB_NOT_TEST');
    assert.strictEqual(g({ ...appEnv(), TEST_DB_URL: 'mysql://a:b@localhost/otra' }).code, 'TEST_DB_NOT_TEST');
    assert.strictEqual(g({ ...appEnv(), TEST_DB_URL: 'no es una url' }).code, 'TEST_DB_NOT_TEST');
});
test('validate de suites con BD aplica la guarda (409 con el código)', () => {
    const keys = ['DB_FRAGMENT_1', 'DB_FRAGMENT_2', 'DB_FRAGMENT_3', 'TEST_DB_URL'];
    const saved = Object.fromEntries(keys.map(k => [k, process.env[k]]));
    try {
        Object.assign(process.env, appEnv('secure_platform_test', 'localhost'));
        assert.throws(() => suiteRunner().validate('test_security'), (e) => e.status === 409 && e.code === 'TEST_DB_IS_APP_DB');
        suiteRunner().validate('test_api'); // sin BD: no aplica
    } finally {
        for (const k of keys) { if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k]; }
    }
});

test('redact: URLs con contraseña, password=/secret=/token=, JSON y Bearer', () => {
    const { redact } = require('../src/ops/runs.service');
    assert.strictEqual(redact('conectando a mysql://sec:S3cr3t!@127.0.0.1:3306/db'), 'conectando a mysql://sec:***@127.0.0.1:3306/db');
    assert.strictEqual(redact('postgres://u:p%40ss@h/db y https://x:y@z'), 'postgres://u:***@h/db y https://x:***@z');
    assert.strictEqual(redact('password=hunter2 secret=abc token=xyz resto'), 'password=*** secret=*** token=*** resto');
    assert.strictEqual(redact('TOKEN: abc123'), 'TOKEN: ***');
    assert.strictEqual(redact('Authorization: Bearer eyJhbGciOi.abc-def_1'), 'Authorization: Bearer ***');
    assert.strictEqual(redact('{"password":"a b","n":1,"token":"t"}'), '{"password":"***","n":1,"token":"***"}');
    assert.strictEqual(redact("api_key='k k'"), "api_key='***'");
    assert.strictEqual(redact('sin credenciales: 12 pruebas'), 'sin credenciales: 12 pruebas');
    assert.strictEqual(redact(undefined), '');
});

itDb('emit: redacta antes de guardar y descarta líneas output (nunca resultados) si la cola en memoria se desborda', async () => {
    const [res] = await db.query("INSERT INTO ops_runs (kind, status, host) VALUES ('diagnostic', 'passed', 'prueba:1')");
    const id = Number(res.insertId);
    try {
        await runsService.emit(id, { level: 'output', step: 'stdout', message: 'url mysql://sec:Clave123@h/db password=zzz' });
        const [row] = await db.query('SELECT message FROM ops_run_events WHERE run_id = ? ORDER BY seq LIMIT 1', [id]);
        assert.strictEqual(row[0].message, 'url mysql://sec:***@h/db password=***');
        // Desbordamiento: 3000 líneas de salida seguidas sin esperar + un resultado intercalado
        const pending = [];
        for (let i = 0; i < 3000; i++) pending.push(runsService.emit(id, { level: 'output', step: 'stdout', message: `l${i}` }));
        pending.push(runsService.emit(id, { level: 'fail', step: 'suite', message: 'resultado que no se puede perder' }));
        await Promise.all(pending);
        const [out] = await db.query("SELECT COUNT(*) AS n FROM ops_run_events WHERE run_id = ? AND level = 'output'", [id]);
        assert.ok(Number(out[0].n) <= 1001, `la cola debe acotarse (${out[0].n})`);
        const [fail] = await db.query("SELECT COUNT(*) AS n FROM ops_run_events WHERE run_id = ? AND level = 'fail'", [id]);
        assert.strictEqual(Number(fail[0].n), 1);
    } finally {
        await db.query('DELETE FROM ops_runs WHERE id = ?', [id]);
    }
});
