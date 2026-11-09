#!/usr/bin/env node
/*
 * scale-bench.js — mide el servidor REAL (src/index.js o src/cluster.js) con una BD real y reporta req/s y latencias
 * de rutas representativas: ligera (/health), autenticada ligera (perfil) y pesada (notas: descifra campos).
 *
 *   node benchmarks/scale-bench.js --env /ruta/env [--cluster N] [--duration 10] [--concurrency 64] [--label "texto"]
 *
 * El archivo de entorno apunta a una BD de PRUEBAS (se crean usuarios y notas). Una corrida por celda: son órdenes de
 * magnitud, no cifras de catálogo (el generador de carga comparte CPU con el servidor).
 */
'use strict';
const { spawn } = require('child_process');
const path = require('path');
const http = require('http');

const arg = (name, fallback) => { const i = process.argv.indexOf(`--${name}`); return i >= 0 ? process.argv[i + 1] : fallback; };
const ENV_FILE = arg('env');
const CLUSTER = Number(arg('cluster', 0));
const DURATION = Number(arg('duration', 10));
const CONC = Number(arg('concurrency', 64));
const LABEL = arg('label', CLUSTER ? `cluster x${CLUSTER}` : 'proceso único');
if (!ENV_FILE) { console.error('Falta --env'); process.exit(2); }
const PORT = Number(require('dotenv').parse(require('fs').readFileSync(ENV_FILE)).PORT || 3000);
const ROOT = path.join(__dirname, '..');
const base = `http://127.0.0.1:${PORT}`;

const request = (method, url, { token, json } = {}) => new Promise((resolve, reject) => {
    const body = json ? JSON.stringify(json) : null;
    const req = http.request(base + url, { method, headers: { ...(body && { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) }), ...(token && { Authorization: `Bearer ${token}` }), 'X-Forwarded-For': '198.51.100.7' } }, (res) => {
        let text = ''; res.on('data', c => { text += c; });
        res.on('end', () => { let parsed = null; try { parsed = JSON.parse(text); } catch { /* texto */ } resolve({ status: res.statusCode, body: parsed, text }); });
    });
    req.on('error', reject); if (body) req.write(body); req.end();
});

function load(url, token) {
    return new Promise((resolve) => {
        const args = [path.join(__dirname, 'loadtest.js'), '--url', base + url, '--duration', String(DURATION), '--concurrency', String(CONC), '--json', 'true'];
        if (token) args.push('--header', `Authorization: Bearer ${token}`);
        const child = spawn(process.execPath, args, { stdio: ['ignore', 'pipe', 'pipe'] });
        let out = ''; child.stdout.on('data', d => { out += d; });
        child.on('close', () => {
            const start = out.indexOf('{'); let r = null;
            try { r = JSON.parse(out.slice(start)); } catch { /* sin json */ }
            resolve(r);
        });
    });
}

(async () => {
    const script = CLUSTER ? 'src/cluster.js' : 'src/index.js';
    const server = spawn(process.execPath, [path.join(ROOT, script)], { env: { ...process.env, ENV_FILE, ...(CLUSTER && { WEB_CONCURRENCY: String(CLUSTER) }) }, stdio: ['ignore', 'ignore', 'inherit'] });
    try {
        for (let i = 0; i < 60; i++) { try { if ((await request('GET', '/health')).status === 200) break; } catch { /* arrancando */ } await new Promise(r => setTimeout(r, 500)); }
        const user = `bench_${Date.now().toString(36)}`;
        const password = `Bench-${require('crypto').randomBytes(9).toString('hex')}-Pw1!`;
        await request('POST', '/api/auth/register', { json: { username: user, email: `${user}@example.com`, password } });
        const login = await request('POST', '/api/auth/login', { json: { username: user, password } });
        const token = login.body?.token; if (!token) throw new Error(`login falló: ${login.text.slice(0, 200)}`);
        for (let i = 0; i < 40; i++) await request('POST', '/api/notes', { token, json: { title: `Nota ${i}`, content: 'x'.repeat(200) } });

        const rows = [];
        for (const [name, url, auth] of [['/health', '/health', false], ['/api/files/quota', '/api/files/quota', true], ['/api/notes?limit=20', '/api/notes?limit=20', true]]) {
            const r = await load(url, auth ? token : null);
            const lat = r?.latency_ms || {};
            rows.push({ name, rps: Math.round(r?.rps ?? 0), p50: lat.p50, p99: lat.p99, ok: r?.status_codes ? JSON.stringify(r.status_codes) : '', errors: r?.errors });
        }
        console.log(`\n### ${LABEL} — ${DURATION}s por ruta, ${CONC} conexiones`);
        console.log('| Ruta | req/s | p50 ms | p99 ms | códigos | errores |\n|---|---:|---:|---:|---|---:|');
        for (const r of rows) console.log(`| ${r.name} | ${r.rps} | ${r.p50 ?? '-'} | ${r.p99 ?? '-'} | ${r.ok} | ${r.errors ?? 0} |`);
    } finally { server.kill('SIGTERM'); }
})().catch((e) => { console.error(e); process.exit(1); });
