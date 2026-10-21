#!/usr/bin/env node
/*
 * loadtest.js — Generador de carga HTTP concurrente, sin dependencias.
 *
 * Mide throughput real (req/s), latencias p50/p90/p95/p99, distribución de
 * códigos de estado y errores. Mantiene N peticiones en vuelo con keep-alive.
 *
 * Uso:
 *   node loadtest.js --url http://127.0.0.1:3000/health --requests 100000 --concurrency 200
 *   node loadtest.js --url .../api/notes --requests 1000000 --concurrency 300 --header "Authorization: Bearer <t>"
 *   node loadtest.js --url ... --duration 30            (por tiempo en lugar de por nº)
 *   node loadtest.js ... --method POST --body '{"x":1}' --json
 *
 * Variables útiles: --sample-pid <pid> para muestrear CPU/RAM de ese proceso.
 */
'use strict';
const http = require('http');
const https = require('https');
const { performance } = require('perf_hooks');
const fs = require('fs');

function arg(name, def) {
  const i = process.argv.indexOf('--' + name);
  if (i === -1) return def;
  const v = process.argv[i + 1];
  return (v === undefined || v.startsWith('--')) ? true : v;
}

const URL_ = String(arg('url', 'http://127.0.0.1:3000/health'));
const CONC = parseInt(arg('concurrency', '100'), 10);
const REQS = arg('requests', null) ? parseInt(arg('requests'), 10) : null;
const DURATION = arg('duration', null) ? parseFloat(arg('duration')) : null;
const METHOD = String(arg('method', 'GET')).toUpperCase();
const BODY = arg('body', null);
const ISJSON = !!arg('json', false);
const SAMPLE_PID = arg('sample-pid', null);
const OUT = arg('out', null);
const headers = {};
let h = arg('header', null);
if (h && typeof h === 'string') { const idx = h.indexOf(':'); headers[h.slice(0, idx).trim()] = h.slice(idx + 1).trim(); }
if (ISJSON) headers['Content-Type'] = 'application/json';

const u = new URL(URL_);
const client = u.protocol === 'https:' ? https : http;
const agent = new client.Agent({ keepAlive: true, maxSockets: CONC, maxFreeSockets: CONC });

const lat = [];              // latencias (ms)
const codes = {};            // conteo por código
let errors = 0, sent = 0, done = 0, inflight = 0;
let stop = false;
const started = performance.now();
let deadline = DURATION ? started + DURATION * 1000 : null;

// ---- Muestreo de CPU/RAM de un PID (lee /proc) ----
const samples = [];
let sampler = null;
function readProc(pid) {
  try {
    const stat = fs.readFileSync(`/proc/${pid}/stat`, 'utf8').trim();
    const rparen = stat.lastIndexOf(')');
    const rest = stat.slice(rparen + 2).split(' ');
    const utime = parseInt(rest[11], 10), stime = parseInt(rest[12], 10); // jiffies
    const statusTxt = fs.readFileSync(`/proc/${pid}/status`, 'utf8');
    const m = statusTxt.match(/VmRSS:\s+(\d+)\s+kB/);
    const rssMB = m ? parseInt(m[1], 10) / 1024 : 0;
    return { cpuJiffies: utime + stime, rssMB };
  } catch (_) { return null; }
}
function startSampling(pid) {
  const HZ = 100; // USER_HZ típico
  const ncpu = require('os').cpus().length;
  let prev = readProc(pid); let prevT = performance.now();
  sampler = setInterval(() => {
    const cur = readProc(pid); const now = performance.now();
    if (prev && cur) {
      const dt = (now - prevT) / 1000;
      const cpuPct = ((cur.cpuJiffies - prev.cpuJiffies) / HZ) / dt * 100; // % de 1 núcleo
      samples.push({ t: now - started, cpuPctOneCore: cpuPct, cpuPctAllCores: cpuPct / ncpu, rssMB: cur.rssMB });
    }
    prev = cur; prevT = now;
  }, 500);
}

function pct(sorted, p) {
  if (!sorted.length) return 0;
  const i = Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length));
  return sorted[i];
}

function fireOne() {
  if (stop) return;
  if (REQS !== null && sent >= REQS) return;
  if (deadline && performance.now() >= deadline) { stop = true; return; }
  sent++; inflight++;
  const t0 = performance.now();
  const opts = { method: METHOD, hostname: u.hostname, port: u.port || (u.protocol === 'https:' ? 443 : 80), path: u.pathname + u.search, headers, agent };
  const req = client.request(opts, (res) => {
    res.on('data', () => {});
    res.on('end', () => {
      lat.push(performance.now() - t0);
      codes[res.statusCode] = (codes[res.statusCode] || 0) + 1;
      finishOne();
    });
  });
  req.on('error', () => { errors++; finishOne(); });
  if (BODY && typeof BODY === 'string') req.write(BODY);
  req.end();
}

function finishOne() {
  done++; inflight--;
  // Mantener la concurrencia llena
  if (!stop && (REQS === null || sent < REQS) && (!deadline || performance.now() < deadline)) fireOne();
  else if (inflight === 0) report();
}

function report() {
  if (sampler) clearInterval(sampler);
  const elapsed = (performance.now() - started) / 1000;
  const sorted = lat.slice().sort((a, b) => a - b);
  const sum = sorted.reduce((a, b) => a + b, 0);
  const ok2xx = Object.entries(codes).filter(([c]) => +c >= 200 && +c < 300).reduce((a, [, n]) => a + n, 0);
  const result = {
    url: URL_, method: METHOD, concurrency: CONC,
    requests_completed: done, requests_sent: sent, errors,
    elapsed_s: +elapsed.toFixed(2),
    rps: +(done / elapsed).toFixed(1),
    latency_ms: {
      min: +(sorted[0] || 0).toFixed(2), mean: +((sum / (sorted.length || 1))).toFixed(2),
      p50: +pct(sorted, 50).toFixed(2), p90: +pct(sorted, 90).toFixed(2),
      p95: +pct(sorted, 95).toFixed(2), p99: +pct(sorted, 99).toFixed(2),
      max: +(sorted[sorted.length - 1] || 0).toFixed(2)
    },
    status_codes: codes,
    success_rate_pct: +(100 * ok2xx / (done || 1)).toFixed(2)
  };
  if (samples.length) {
    const rss = samples.map(s => s.rssMB), cpu1 = samples.map(s => s.cpuPctOneCore), cpuAll = samples.map(s => s.cpuPctAllCores);
    result.resource = {
      samples: samples.length,
      rss_mb_max: +Math.max(...rss).toFixed(1), rss_mb_avg: +(rss.reduce((a, b) => a + b, 0) / rss.length).toFixed(1),
      cpu_pct_one_core_max: +Math.max(...cpu1).toFixed(1), cpu_pct_one_core_avg: +(cpu1.reduce((a, b) => a + b, 0) / cpu1.length).toFixed(1),
      cpu_pct_all_cores_avg: +(cpuAll.reduce((a, b) => a + b, 0) / cpuAll.length).toFixed(1)
    };
  }
  const json = JSON.stringify(result, null, 2);
  process.stdout.write(json + '\n');
  if (OUT && typeof OUT === 'string') { try { fs.writeFileSync(OUT, json); } catch (_) {} }
  process.exit(0);
}

process.on('SIGINT', () => { stop = true; });
if (SAMPLE_PID && typeof SAMPLE_PID === 'string') startSampling(SAMPLE_PID.trim());
console.error(`[loadtest] ${METHOD} ${URL_}  conc=${CONC}  ${REQS !== null ? REQS + ' req' : DURATION + 's'}`);
for (let i = 0; i < CONC; i++) fireOne();
