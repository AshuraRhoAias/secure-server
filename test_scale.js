// Escalabilidad: limitador con una sola sentencia, caché de bloqueos de IP, elección de líder, cluster (reparto entre procesos,
// relanzamiento, reinicio en caliente, métricas agregadas, cierre ordenado) y sondas de preparación. MariaDB real, procesos reales.
//
//   npm run test:scale

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const net = require('net');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');

const { filesDir } = require('./test_helpers/env');
const helpers = require('./test_helpers/app');

let dbAvailable = false;
let db;
const spawned = [];

test.before(async () => {
    dbAvailable = await helpers.prepareDatabase();
    if (dbAvailable) db = require('./src/config/database');
});

test.after(async () => {
    spawned.forEach(child => { try { child.kill('SIGKILL'); } catch { /* ya terminó */ } });
    if (db?.pool) await db.pool.end();
    fs.rmSync(filesDir, { recursive: true, force: true });
});

const itDb = (name, fn) => test(name, async (t) => { if (!dbAvailable) return t.skip('sin base de datos'); await fn(t); });
const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));
const until = async (fn, { timeout = 15000, every = 100, message = 'condición' } = {}) => {
    const end = Date.now() + timeout;
    for (;;) {
        const value = await fn();
        if (value) return value;
        if (Date.now() > end) throw new Error(`tiempo agotado esperando: ${message}`);
        await sleep(every);
    }
};

// ============================================================================ limitador de peticiones

itDb('limitador: una sentencia por golpe, contador exacto bajo concurrencia y ventana anterior ponderada', async () => {
    const limiter = require('./src/security/rate-limiter.service');
    const subject = `t-${Date.now()}`;

    // 50 golpes simultáneos desde "varios procesos": ninguno se pierde ni se cuenta dos veces
    const results = await Promise.all(Array.from({ length: 50 }, () => limiter.hit('test', subject, 3600)));
    assert.deepStrictEqual(results.map(r => r.current).sort((a, b) => a - b), Array.from({ length: 50 }, (_, i) => i + 1));
    assert.strictEqual((await limiter.hit('test', subject, 3600)).current, 51);

    // La ventana anterior pesa lo que falta de la actual: se simula insertando 100 golpes en la ventana previa
    const windowSeconds = 3600;
    const now = Math.floor(Date.now() / 1000);
    const start = now - (now % windowSeconds);
    const other = `prev-${Date.now()}`;
    await db.query('INSERT INTO rate_limit_counters (scope, subject, window_start, hits) VALUES (?, ?, ?, 100)', ['test', other, start - windowSeconds]);
    const first = await limiter.hit('test', other, windowSeconds);
    const expected = Math.ceil(1 + 100 * (1 - (now - start) / windowSeconds));
    assert.ok(Math.abs(first.count - expected) <= 1, `count ${first.count}, esperado ≈ ${expected}`);

    // Ventanas de 60 s distintas no se mezclan y la cuenta nueva empieza en 1
    assert.strictEqual((await limiter.hit('test', `fresh-${Date.now()}`, 60)).current, 1);
});

itDb('limitador: cuenta con UNA consulta cuando la ventana anterior ya está en memoria', async () => {
    const limiter = require('./src/security/rate-limiter.service');
    const subject = `q-${Date.now()}`;
    await limiter.hit('test', subject, 60); // la primera vez lee la ventana anterior y la recuerda
    const original = db.query;
    let queries = 0;
    db.query = function (...args) { queries++; return original.apply(this, args); };
    try {
        for (let i = 0; i < 20; i++) await limiter.hit('test', subject, 60);
    } finally { db.query = original; }
    assert.strictEqual(queries, 20, 'una sentencia por comprobación');
});

// ============================================================================ caché de bloqueos

itDb('caché de bloqueo: responde sin consultar durante PROTECTION_CACHE_MS y esta instancia lo invalida al bloquear/desbloquear', async () => {
    const anomaly = require('./src/security/anomaly-detection.service');
    const ip = '203.0.113.201';
    const saved = process.env.PROTECTION_CACHE_MS;
    process.env.PROTECTION_CACHE_MS = '60000';
    try {
        assert.strictEqual(await anomaly.isIPBlocked(ip), false);
        // Otra instancia bloquea la IP (escritura directa en la BD): esta tarda como mucho el TTL en notarlo
        await db.query("INSERT INTO blocked_ips (ip_address, reason, blocked_until, block_count) VALUES (?, 'otra-instancia', DATE_ADD(NOW(), INTERVAL 1 HOUR), 1)", [ip]);
        assert.strictEqual(await anomaly.isIPBlocked(ip), false, 'dentro del TTL se responde desde la caché');

        // Bloquear/desbloquear DESDE esta instancia surte efecto al instante
        assert.strictEqual(await anomaly.unblockIP(ip), true);
        assert.strictEqual(await anomaly.isIPBlocked(ip), false);
        assert.strictEqual(await anomaly.blockIP(ip, 'prueba'), true);
        assert.strictEqual(await anomaly.isIPBlocked(ip), true);
        assert.strictEqual(await anomaly.unblockIP(ip), true);
        assert.strictEqual(await anomaly.isIPBlocked(ip), false);

        // Con TTL 0 cada comprobación va a la BD
        process.env.PROTECTION_CACHE_MS = '0';
        await db.query("INSERT INTO blocked_ips (ip_address, reason, blocked_until, block_count) VALUES (?, 'directo', DATE_ADD(NOW(), INTERVAL 1 HOUR), 1)", [ip]);
        assert.strictEqual(await anomaly.isIPBlocked(ip), true);
        await anomaly.unblockIP(ip);
    } finally {
        if (saved === undefined) delete process.env.PROTECTION_CACHE_MS; else process.env.PROTECTION_CACHE_MS = saved;
    }
});

itDb('caché de bloqueo: caduca y tras el TTL se ve el cambio hecho por otra instancia', async () => {
    const anomaly = require('./src/security/anomaly-detection.service');
    const ip = '203.0.113.202';
    process.env.PROTECTION_CACHE_MS = '150';
    try {
        assert.strictEqual(await anomaly.isIPBlocked(ip), false);
        await db.query("INSERT INTO blocked_ips (ip_address, reason, blocked_until, block_count) VALUES (?, 'otra', DATE_ADD(NOW(), INTERVAL 1 HOUR), 1)", [ip]);
        await sleep(250);
        assert.strictEqual(await anomaly.isIPBlocked(ip), true);
        await db.query('DELETE FROM blocked_ips WHERE ip_address = ?', [ip]);
    } finally { process.env.PROTECTION_CACHE_MS = '0'; }
});

// ============================================================================ panel

itDb('panel: peticiones simultáneas idénticas comparten UN cálculo; después vuelve a calcular con datos frescos', async () => {
    const dashboard = require('./src/security/dashboard.service');
    const original = db.query;
    let queries = 0;
    db.query = function (...args) { queries++; return original.apply(this, args); };
    try {
        await dashboard.snapshot({ hours: 24 });
        const single = queries;
        queries = 0;
        const results = await Promise.all(Array.from({ length: 10 }, () => dashboard.snapshot({ hours: 24 })));
        assert.ok(queries <= single + 2, `10 simultáneas hicieron ${queries} consultas; una sola, ${single}`);
        assert.ok(results.every(r => r === results[0]), 'todas reciben el mismo resultado');
        queries = 0;
        await dashboard.snapshot({ hours: 24 });
        assert.ok(queries >= single - 1, 'sin caché con caducidad: la siguiente petición calcula de nuevo');
        // otra ventana es otro cálculo
        queries = 0;
        await Promise.all([dashboard.snapshot({ hours: 1 }), dashboard.snapshot({ hours: 24 })]);
        assert.ok(queries >= single * 1.5, 'ventanas distintas no se mezclan');
    } finally { db.query = original; }
});

// ============================================================================ elección de líder

itDb('líder: solo UNA instancia lo es, el relevo ocurre al parar o al perder la conexión, y las tareas se paran con él', async () => {
    const { LeaderElection } = require('./src/tasks/leader');
    process.env.LEADER_RETRY_SECONDS = '0.2';
    process.env.LEADER_PING_SECONDS = '0.2';
    const log = [];
    const make = (name) => {
        const election = new LeaderElection();
        const tasks = [{ name: 'tarea', start: () => log.push(`${name}:start`), stop: () => log.push(`${name}:stop`) }];
        return { election, tasks };
    };
    const a = make('A'), b = make('B'), c = make('C');
    await a.election.start(a.tasks);
    await b.election.start(b.tasks);
    await c.election.start(c.tasks);
    try {
        assert.strictEqual([a, b, c].filter(x => x.election.isLeader()).length, 1, 'exactamente un líder');
        assert.strictEqual(log.filter(l => l.endsWith(':start')).length, 1, 'las tareas solo se inician en el líder');
        const first = [a, b, c].find(x => x.election.isLeader());

        // El líder se para ordenadamente: otro toma el relevo
        await first.election.stop();
        const rest = [a, b, c].filter(x => x !== first);
        await until(() => rest.some(x => x.election.isLeader()), { message: 'relevo tras parar el líder' });
        assert.strictEqual(rest.filter(x => x.election.isLeader()).length, 1);
        assert.ok(log.includes(`${['A', 'B', 'C'][[a, b, c].indexOf(first)]}:stop`));

        // El líder pierde su conexión (caída de red, reinicio de la BD…): se retira SOLO y otro lo sustituye
        const second = rest.find(x => x.election.isLeader());
        const [[{ id }]] = await db.query('SELECT CONNECTION_ID() AS id');
        void id;
        const leaderConnectionId = (await second.election.conn.query('SELECT CONNECTION_ID() AS id'))[0][0].id;
        await db.query(`KILL ${Number(leaderConnectionId)}`);
        await until(() => !second.election.isLeader(), { message: 'el líder se retira al perder la conexión' });
        const third = rest.find(x => x !== second);
        await until(() => third.election.isLeader(), { message: 'relevo tras perder la conexión' });
    } finally {
        await Promise.all([a, b, c].map(x => x.election.stop()));
        delete process.env.LEADER_RETRY_SECONDS;
        delete process.env.LEADER_PING_SECONDS;
    }
});

// ============================================================================ cluster (procesos reales)

// index.js exige que el archivo de entorno exista; todo lo demás llega por variables de entorno
// (en un directorio propio creado con mkdtemp, permisos 0700: nada predecible en /tmp)
const envDir = fs.mkdtempSync(path.join(os.tmpdir(), 'scale-test-'));
const envFile = path.join(envDir, 'test.env');
fs.writeFileSync(envFile, '# vacío a propósito: la configuración llega por variables de entorno\n', { mode: 0o600 });
test.after(() => fs.rmSync(envDir, { recursive: true, force: true }));

const freePort = () => new Promise((resolve) => { const s = net.createServer(); s.listen(0, '127.0.0.1', () => { const { port } = s.address(); s.close(() => resolve(port)); }); });

function startCluster(extraEnv = {}) {
    return freePort().then(async (port) => {
        const logs = [];
        const child = spawn(process.execPath, [path.join(__dirname, 'src/cluster.js')], {
            env: {
                ...process.env, ENV_FILE: envFile, PORT: String(port), WEB_CONCURRENCY: '2', ALERTS_DISABLED: 'true',
                LEADER_RETRY_SECONDS: '0.3', LEADER_PING_SECONDS: '0.3', PROTECTION_CACHE_MS: '0', SHUTDOWN_TIMEOUT_MS: '3000',
                METRICS_TOKEN: 'metricas-de-prueba-0123456789abcdef0123456789', ...extraEnv
            },
            stdio: ['ignore', 'pipe', 'pipe']
        });
        spawned.push(child);
        child.stdout.on('data', d => logs.push(String(d)));
        child.stderr.on('data', d => logs.push(String(d)));
        const exited = new Promise(resolve => child.on('exit', (code, signal) => resolve({ code, signal })));
        return { child, port, base: `http://127.0.0.1:${port}`, logs, exited };
    });
}

// Una petición por conexión nueva (sin keep-alive) para que el reparto del cluster sea visible
const ready = async (base) => {
    const res = await fetch(`${base}/health/ready`, { headers: { Connection: 'close' }, signal: AbortSignal.timeout(5000) });
    return { status: res.status, body: await res.json().catch(() => null) };
};
const pidsSeen = async (base, n = 60) => {
    const seen = new Map();
    for (let i = 0; i < n; i++) {
        try { const r = await ready(base); if (r.body?.pid) seen.set(r.body.pid, r.body); } catch { /* arrancando */ }
    }
    return seen;
};

itDb('cluster: reparte entre procesos, un solo líder, métricas agregadas sin multiplicar y cierre ordenado', async () => {
    const cluster = await startCluster();
    try {
        await until(async () => (await pidsSeen(cluster.base, 20)).size >= 2, { timeout: 60000, every: 300, message: 'dos workers atendiendo' });
        const seen = await pidsSeen(cluster.base, 80);
        assert.strictEqual(seen.size, 2, `procesos distintos: ${[...seen.keys()]}`);

        await until(async () => [...(await pidsSeen(cluster.base, 40)).values()].filter(b => b.leader).length === 1, { message: 'exactamente un líder' });

        // /api/metrics (token de scraper) agrega TODOS los workers: un gauge que sale de la BD no se multiplica por 2
        await db.query("INSERT INTO blocked_ips (ip_address, reason, blocked_until, block_count) VALUES ('203.0.113.77', 'metricas', DATE_ADD(NOW(), INTERVAL 1 HOUR), 1)");
        const metrics = await fetch(`${cluster.base}/api/metrics`, { headers: { Authorization: 'Bearer metricas-de-prueba-0123456789abcdef0123456789' } });
        assert.strictEqual(metrics.status, 200);
        const text = await metrics.text();
        assert.match(text, /secure_server_http_requests_total/);
        const blocked = /^secure_server_blocked_ips_active (\d+)/m.exec(text);
        assert.ok(blocked && Number(blocked[1]) === 1, `ips bloqueadas agregadas: ${blocked?.[0]}`);
        // y los contadores de procesos distintos sí se suman: las peticiones de /health/ready de los dos workers aparecen
        const count = [...text.matchAll(/^secure_server_http_requests_total\{[^}]*route="\/health\/ready"[^}]*\} (\d+)/gm)].reduce((sum, m) => sum + Number(m[1]), 0);
        assert.ok(count >= 100, `peticiones contadas entre procesos: ${count}`);

        // Cierre ordenado: SIGTERM al supervisor → sale con 0, sin procesos huérfanos y el cerrojo de líder liberado
        const started = Date.now();
        cluster.child.kill('SIGTERM');
        const { code } = await cluster.exited;
        assert.strictEqual(code, 0, cluster.logs.join('').slice(-800));
        assert.ok(Date.now() - started < 10000, 'cierre rápido');
        await until(async () => (await db.query("SELECT IS_FREE_LOCK('secure-server:leader') AS free"))[0][0].free === 1, { message: 'el cerrojo de líder se liberó' });
        for (const pid of seen.keys()) assert.throws(() => process.kill(pid, 0), 'el worker ya no existe');
    } finally {
        await db.query("DELETE FROM blocked_ips WHERE ip_address = '203.0.113.77'");
        cluster.child.kill('SIGKILL');
    }
});

itDb('cluster: un worker que muere se relanza y el líder pasa a otro si era él', async () => {
    const cluster = await startCluster();
    try {
        await until(async () => (await pidsSeen(cluster.base, 20)).size >= 2, { timeout: 60000, every: 300, message: 'dos workers' });
        const before = await until(async () => { const s = await pidsSeen(cluster.base, 40); return [...s.values()].some(b => b.leader) && s; }, { message: 'líder' });
        const leaderPid = [...before.values()].find(b => b.leader).pid;

        process.kill(leaderPid, 'SIGKILL'); // el líder muere de golpe (sin cierre ordenado)
        const after = await until(async () => {
            const s = await pidsSeen(cluster.base, 40);
            return s.size >= 2 && !s.has(leaderPid) && [...s.values()].filter(b => b.leader).length === 1 && s;
        }, { timeout: 40000, every: 300, message: 'worker relanzado y nuevo líder' });
        assert.ok(!after.has(leaderPid));
        assert.match(cluster.logs.join(''), /Relanzando el hueco/);
    } finally { cluster.child.kill('SIGKILL'); }
});

itDb('cluster: reinicio en caliente (SIGHUP) cambia TODOS los procesos sin rechazar peticiones', async () => {
    const cluster = await startCluster();
    try {
        await until(async () => (await pidsSeen(cluster.base, 20)).size >= 2, { timeout: 60000, every: 300, message: 'dos workers' });
        const original = new Set((await pidsSeen(cluster.base, 60)).keys());

        let running = true, failures = 0, total = 0;
        // Cuatro clientes en paralelo, cada uno con una conexión nueva por petición
        const hammer = Promise.all(Array.from({ length: 4 }, async () => {
            while (running) {
                // /health (no /health/ready: durante el cierre de un worker la sonda de preparación responde 503 A PROPÓSITO, para que un balanceador lo retire)
                try { const r = await fetch(`${cluster.base}/health`, { headers: { Connection: 'close' }, signal: AbortSignal.timeout(5000) }); total++; if (r.status !== 200) failures++; await r.text(); } catch { total++; failures++; }
            }
        }));

        cluster.child.kill('SIGHUP');
        await until(() => /Reinicio en caliente completado/.test(cluster.logs.join('')), { timeout: 90000, every: 300, message: 'reinicio completado' });
        running = false;
        await hammer;

        const now = new Set((await pidsSeen(cluster.base, 60)).keys());
        assert.ok([...now].every(pid => !original.has(pid)), 'todos los procesos son nuevos');
        assert.ok(now.size === 2, 'siguen siendo dos');
        assert.ok(total > 200, `peticiones durante el reinicio: ${total}`);
        assert.strictEqual(failures, 0, `${failures} de ${total} peticiones fallaron durante el reinicio en caliente`);
    } finally { cluster.child.kill('SIGKILL'); }
});

itDb('cluster: si el arranque está roto, el supervisor se detiene con error en vez de relanzar sin fin', async () => {
    const cluster = await startCluster({ BASE_SEED: '', ENCRYPTION_SEED: '', JWT_SEED: '', DB_FRAGMENT_1: '' });
    const { code } = await Promise.race([cluster.exited, sleep(90000).then(() => ({ code: 'timeout' }))]);
    assert.notStrictEqual(code, 'timeout', cluster.logs.join('').slice(-600));
    assert.notStrictEqual(code, 0);
    assert.match(cluster.logs.join(''), /el arranque está roto/);
});

itDb('sondas de preparación: /health/ready no pasa por el límite ni el bloqueo de IP (un balanceador no puede quedarse fuera)', async () => {
    const protection = require('./src/middleware/protection.middleware');
    const res = { setHeader() {}, set() { return this; }, removeHeader() {}, once() {}, status() { throw new Error('no debería responder'); } };
    for (const path of ['/health', '/health/ready']) {
        let passed = false;
        await protection.autoProtect()({ path, ip: '198.51.100.9', headers: {}, method: 'GET' }, res, () => { passed = true; });
        assert.ok(passed, path);
    }
    // Con la IP bloqueada de verdad, una ruta normal SÍ se corta y las sondas siguen pasando
    const anomaly = require('./src/security/anomaly-detection.service');
    await anomaly.blockIP('198.51.100.9', 'prueba-sondas');
    try {
        let status = null;
        const blocked = { ...res, status(code) { status = code; return { json() {} }; } };
        await protection.autoProtect()({ path: '/api/notes', ip: '198.51.100.9', headers: {}, method: 'GET', query: {}, params: {}, originalUrl: '/api/notes' }, blocked, () => {});
        assert.strictEqual(status, 403);
        let probe = false;
        await protection.autoProtect()({ path: '/health/ready', ip: '198.51.100.9', headers: {}, method: 'GET' }, res, () => { probe = true; });
        assert.ok(probe);
    } finally { await anomaly.unblockIP('198.51.100.9'); }
});
