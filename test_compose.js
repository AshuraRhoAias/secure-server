// Escalabilidad HORIZONTAL de verdad: varias réplicas del API (contenedores distintos) detrás de nginx, con MariaDB y SeaweedFS (S3)
// compartidos. Lo levanta deploy/docker-compose.yml; esta prueba solo habla con el balanceador (y con la BD por `docker compose exec`).
//
//   docker compose -f deploy/docker-compose.yml --env-file deploy/compose.env up -d --build
//   COMPOSE_ENV_FILE=deploy/compose.env npm run test:compose
//
// Comprueba lo que se rompe al pasar de una máquina a varias: reparto entre réplicas, UN solo líder entre TODAS, archivos que
// sube una réplica y sirve otra (S3 compartido), límites de peticiones compartidos (estado en la BD) y el stream en vivo a través
// del balanceador. Imprime además un rendimiento orientativo (no es una prueba de carga: misma máquina para todo).

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const BASE = process.env.COMPOSE_BASE || 'http://127.0.0.1:8080';
const ENV_FILE = process.env.COMPOSE_ENV_FILE || path.join(__dirname, 'deploy/compose.env');
const COMPOSE = ['compose', '-f', path.join(__dirname, 'deploy/docker-compose.yml'), '--env-file', ENV_FILE];
const REPLICAS = Number(process.env.API_REPLICAS) || 2;
const PASSWORD = 'Contraseña-de-prueba-compose-1';
const enabled = fs.existsSync(ENV_FILE);   // solo si se montó el compose (deploy/compose.env existe)

const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));
const envValue = (name) => fs.readFileSync(ENV_FILE, 'utf8').split('\n').find(l => l.startsWith(`${name}=`))?.slice(name.length + 1).trim();

function sql(statement, params = []) {
    // Valores numéricos de la propia prueba: no hay entrada externa
    const text = params.reduce((s, p) => s.replace('?', String(Number(p))), statement);
    const r = spawnSync('docker', [...COMPOSE, 'exec', '-T', 'mariadb', 'mariadb', '-usecure', `-p${envValue('DB_PASSWORD')}`, 'secure_platform', '-N', '-e', text], { encoding: 'utf8' });
    if (r.status !== 0) throw new Error(`SQL: ${r.stderr}`);
    return r.stdout.trim();
}

async function call(method, route, { token, json, form, headers = {}, fresh = true } = {}) {
    const res = await fetch(BASE + route, {
        method,
        headers: { ...(fresh && { Connection: 'close' }), ...(token && { Authorization: `Bearer ${token}` }), ...(json && { 'Content-Type': 'application/json' }), ...headers },
        body: json ? JSON.stringify(json) : form
    });
    const buffer = Buffer.from(await res.arrayBuffer());
    let body = null;
    try { body = JSON.parse(buffer.toString('utf8')); } catch { /* binario */ }
    return { status: res.status, headers: res.headers, body, buffer };
}

async function newUser({ admin = false } = {}) {
    const username = `cmp_${crypto.randomBytes(5).toString('hex')}`;
    const reg = await call('POST', '/api/auth/register', { json: { username, email: `${username}@ejemplo.com`, password: PASSWORD } });
    assert.strictEqual(reg.status, 201, JSON.stringify(reg.body));
    const userId = reg.body.userId ?? reg.body.user?.id;
    if (admin) sql('UPDATE users SET role = \'admin\' WHERE id = ?', [userId]);
    const login = await call('POST', '/api/auth/login', { json: { username, password: PASSWORD } });
    assert.strictEqual(login.status, 200, JSON.stringify(login.body));
    return { username, userId, token: login.body.token };
}

test.before(async () => {
    if (!enabled) return;
    const end = Date.now() + 180_000;
    for (;;) {
        try { if ((await call('GET', '/health/ready')).status === 200) break; } catch { /* arrancando */ }
        if (Date.now() > end) throw new Error('el balanceador no responde');
        await sleep(1000);
    }
});

const itCompose = (name, fn) => test(name, async (t) => { if (!enabled) return t.skip('sin docker compose (falta deploy/compose.env)'); await fn(t); });

itCompose(`reparto: responden las ${REPLICAS} réplicas y hay UN solo líder entre todas`, async () => {
    const seen = new Map();
    for (let i = 0; i < 80; i++) {
        const r = await call('GET', '/health/ready');
        if (r.status === 200) seen.set(`${r.body.instance}/${r.body.pid}`, r.body);
    }
    const instances = new Set([...seen.values()].map(b => b.instance));
    assert.strictEqual(instances.size, REPLICAS, `réplicas vistas: ${[...instances]}`);
    // El liderazgo (cerrojo GET_LOCK en la BD compartida) puede moverse; se espera a que quede estable
    let leaders = [];
    for (let attempt = 0; attempt < 20; attempt++) {
        leaders = [...seen.values()].filter(b => b.leader);
        if (leaders.length === 1) break;
        await sleep(500);
        for (let i = 0; i < 40; i++) { const r = await call('GET', '/health/ready'); if (r.status === 200) seen.set(`${r.body.instance}/${r.body.pid}`, r.body); }
    }
    assert.strictEqual(leaders.length, 1, `líderes: ${leaders.map(l => `${l.instance}/${l.pid}`)}`);
});

itCompose('archivos: lo que sube una réplica lo sirve cualquiera (S3 compartido), entero y por rangos', async () => {
    const user = await newUser();
    const data = Buffer.from(Array.from({ length: 8000 }, (_, i) => `fila ${i} ${crypto.randomBytes(4).toString('hex')}\n`).join(''));
    const form = new FormData();
    form.append('file', new Blob([data]), 'compose.txt');
    const up = await call('POST', '/api/files', { token: user.token, form });
    assert.strictEqual(up.status, 201, JSON.stringify(up.body));
    for (let i = 0; i < 12; i++) {
        const full = await call('GET', `/api/files/${up.body.file.id}/download`, { token: user.token });
        assert.strictEqual(full.status, 200);
        assert.ok(full.buffer.equals(data), `descarga ${i}`);
        const part = await call('GET', `/api/files/${up.body.file.id}/download`, { token: user.token, headers: { Range: 'bytes=100000-100099' } });
        assert.strictEqual(part.status, 206);
        assert.ok(part.buffer.equals(data.subarray(100000, 100100)));
    }
});

itCompose('en vivo: el stream SSE atraviesa el balanceador y entrega un evento nuevo', async () => {
    const admin = await newUser({ admin: true });
    const controller = new AbortController();
    const res = await fetch(`${BASE}/api/system/stream`, { headers: { Authorization: `Bearer ${admin.token}` }, signal: controller.signal });
    assert.strictEqual(res.status, 200);
    // Lectura continua: con una carrera reader.read() contra un temporizador, la lectura que pierde la carrera se queda
    // pendiente y el trozo que entrega después se pierde (podía ser justo el del evento)
    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let text = '';
    const pump = (async () => {
        try {
            for (;;) {
                const { value, done } = await reader.read();
                if (done) break;
                text += decoder.decode(value, { stream: true });
            }
        } catch { /* abortado */ }
    })();
    const read = async (pattern, ms = 15000) => {
        const end = Date.now() + ms;
        while (!pattern.test(text) && Date.now() < end) await sleep(100);
        return pattern.test(text);
    };
    try {
        assert.ok(await read(/event: hello/), 'hello');
        sql("INSERT INTO security_events (event_type, rule, severity, ip_address) VALUES ('COMPOSE_LIVE', 'COMPOSE', 'high', '203.0.113.50')");
        assert.ok(await read(/COMPOSE_LIVE/), 'el evento llega por el balanceador sin búfer');
    } finally { controller.abort(); await pump; }
});

itCompose('rendimiento orientativo a través del balanceador (no es una prueba de carga)', async () => {
    const user = await newUser();
    const seconds = 8, concurrency = 32;
    let ok = 0, errors = 0;
    const end = Date.now() + seconds * 1000;
    await Promise.all(Array.from({ length: concurrency }, async () => {
        while (Date.now() < end) {
            const r = await fetch(`${BASE}/api/files/quota`, { headers: { Authorization: `Bearer ${user.token}` } }).catch(() => null);
            if (r?.status === 200) ok++; else errors++;
            await r?.arrayBuffer().catch(() => {});
        }
    }));
    console.log(`ℹ️ /api/files/quota vía nginx con ${REPLICAS} réplicas: ${Math.round(ok / seconds)} req/s, ${errors} errores (${concurrency} conexiones, ${seconds} s)`);
    assert.ok(ok > 0);
    assert.strictEqual(errors, 0, 'sin errores');
});

// Al final a propósito: agota el cupo de login/registro de esta IP durante un minuto
itCompose('límites compartidos: el contador de login es el mismo en todas las réplicas (estado en la BD, no en memoria)', async () => {
    const statuses = [];
    for (let i = 0; i < 14; i++) statuses.push((await call('POST', '/api/auth/login', { json: { username: `nadie_${i}`, password: 'incorrecta' } })).status);
    assert.ok(statuses.includes(429), `alguna petición limitada: ${statuses}`);
    assert.ok(statuses.indexOf(429) <= 11, `el límite (10/min por IP) se alcanza aunque las peticiones vayan a réplicas distintas: ${statuses}`);
});
