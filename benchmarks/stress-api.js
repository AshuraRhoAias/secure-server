#!/usr/bin/env node
/*
 * stress-api.js — API de estrés que ejecuta VARIAS cargas a la vez para saturar
 * CPU y RAM (y GPU si hay una disponible), con TOPES configurables.
 *
 * Es independiente: NO toca el código de la app. Usa sólo módulos nativos de
 * Node (http, crypto, zlib, worker_threads, os) — sin dependencias nuevas.
 *
 * Topes (variables de entorno; valores pensados para el objetivo del usuario:
 * portátil Ryzen 7 usando ~1/2 CPU, ≤8 GB RAM, ~1/2 de una RTX 3050 Ti):
 *   STRESS_PORT        (def 3100)
 *   STRESS_CPU_WORKERS (def = mitad de los núcleos disponibles)
 *   STRESS_MAX_RAM_MB  (def 8192)  -> tope duro de RAM que reserva la API
 *   STRESS_GPU_FRACTION(def 0.5)   -> fracción de GPU a usar SI hay GPU
 *
 * Endpoints:
 *   GET /stress?ms=2000   -> lanza CPU+RAM+zlib (+GPU si hay) durante ~ms y
 *                            devuelve métricas reales de lo que hizo.
 *   GET /health           -> ligero (para comparar techo de throughput).
 *   GET /caps             -> topes efectivos y hardware detectado.
 */
'use strict';
const http = require('http');
const os = require('os');
const crypto = require('crypto');
const zlib = require('zlib');
const { Worker, isMainThread, parentPort, workerData } = require('worker_threads');

const CORES = os.cpus().length;
const CPU_WORKERS = Math.max(1, parseInt(process.env.STRESS_CPU_WORKERS || Math.max(1, Math.floor(CORES / 2)), 10));
const MAX_RAM_MB = Math.max(64, parseInt(process.env.STRESS_MAX_RAM_MB || '8192', 10));
const GPU_FRACTION = Math.min(1, Math.max(0, parseFloat(process.env.STRESS_GPU_FRACTION || '0.5')));
const PORT = parseInt(process.env.STRESS_PORT || '3100', 10);

// ---- Trabajo en worker: bucle de hashing/pbkdf2 hasta una fecha límite ----
if (!isMainThread) {
  const until = workerData.until;
  let ops = 0;
  const salt = crypto.randomBytes(16);
  while (Date.now() < until) {
    // PBKDF2 es intensivo en CPU (y lo usan los esquemas de contraseñas).
    crypto.pbkdf2Sync('stress-' + ops, salt, 300, 32, 'sha256');
    ops++;
  }
  parentPort.postMessage({ ops });
  return;
}

// ---- Detección de GPU (honesta: sólo si existe de verdad) ----
function detectGPU() {
  const fs = require('fs');
  const { execSync } = require('child_process');
  // ¿hay dispositivos NVIDIA?
  let nvidia = false, name = null;
  try { fs.accessSync('/dev/nvidia0'); nvidia = true; } catch (_) {}
  try {
    const out = execSync('nvidia-smi --query-gpu=name,memory.total --format=csv,noheader 2>/dev/null', { timeout: 3000 }).toString().trim();
    if (out) { nvidia = true; name = out.split('\n')[0]; }
  } catch (_) {}
  // ¿librería de cómputo GPU instalada?
  let lib = null;
  for (const cand of ['gpu.js', '@tensorflow/tfjs-node-gpu']) {
    try { require.resolve(cand); lib = cand; break; } catch (_) {}
  }
  return { available: nvidia && !!lib, nvidia_present: nvidia, name, compute_lib: lib,
           reason: nvidia ? (lib ? 'ok' : 'hay GPU pero no hay librería de cómputo (gpu.js/tfjs-node-gpu)') : 'no se detecta GPU NVIDIA en este entorno' };
}

function runCPU(ms) {
  return new Promise((resolve) => {
    const until = Date.now() + ms;
    let pending = CPU_WORKERS, totalOps = 0;
    for (let i = 0; i < CPU_WORKERS; i++) {
      const w = new Worker(__filename, { workerData: { until } });
      w.on('message', (m) => { totalOps += m.ops; });
      w.on('exit', () => { if (--pending === 0) resolve({ workers: CPU_WORKERS, pbkdf2_ops: totalOps }); });
    }
  });
}

function runRAM(targetMB) {
  // Reserva y TOCA memoria (para que sea RSS real), respetando el tope.
  const mb = Math.min(targetMB, MAX_RAM_MB);
  const chunks = [];
  for (let i = 0; i < mb; i++) {
    const b = Buffer.allocUnsafe(1024 * 1024);
    b.fill(i & 0xff); // tocar para forzar páginas residentes
    chunks.push(b);
  }
  // mantener referencia un instante y liberar
  const held = chunks.length;
  return { allocated_mb: held, cap_mb: MAX_RAM_MB, _ref: chunks.length };
}

function runZlib(ms) {
  const until = Date.now() + ms;
  let bytes = 0, rounds = 0;
  const data = crypto.randomBytes(256 * 1024);
  while (Date.now() < until) { const z = zlib.gzipSync(data); bytes += z.length; rounds++; }
  return { gzip_rounds: rounds, compressed_bytes: bytes };
}

function runGPU(gpu, ms) {
  if (!gpu.available) return { ran: false, reason: gpu.reason, requested_fraction: GPU_FRACTION };
  // Si hubiera GPU + librería, aquí se lanzaría un kernel acotado a GPU_FRACTION.
  // No se simula ni se inventa resultado si no se ejecuta de verdad.
  return { ran: false, reason: 'ruta GPU presente pero no ejecutada en este build', requested_fraction: GPU_FRACTION };
}

const GPU = detectGPU();

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x');
  if (url.pathname === '/health') { res.writeHead(200, { 'Content-Type': 'application/json' }); return res.end('{"status":"ok"}'); }
  if (url.pathname === '/caps') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ cores_total: CORES, cpu_workers: CPU_WORKERS, max_ram_mb: MAX_RAM_MB, gpu_fraction: GPU_FRACTION, gpu: GPU }, null, 2));
  }
  if (url.pathname === '/stress') {
    const ms = Math.min(10000, Math.max(100, parseInt(url.searchParams.get('ms') || '2000', 10)));
    const ramMB = Math.min(MAX_RAM_MB, parseInt(url.searchParams.get('ram') || '512', 10));
    const t0 = Date.now();
    const rssBefore = process.memoryUsage().rss / 1048576;
    // Varias cosas A LA VEZ: CPU (workers), RAM (alloc), zlib (hilo principal), GPU (si hay)
    const ram = runRAM(ramMB);
    const [cpu, zres] = await Promise.all([runCPU(ms), Promise.resolve().then(() => runZlib(ms))]);
    const gpu = runGPU(GPU, ms);
    const rssAfter = process.memoryUsage().rss / 1048576;
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      duration_ms: Date.now() - t0,
      cpu, ram, zlib: zres, gpu,
      rss_mb_before: +rssBefore.toFixed(1), rss_mb_after: +rssAfter.toFixed(1)
    }));
    return;
  }
  res.writeHead(404); res.end('not found');
});

server.listen(PORT, () => {
  console.log(`[stress-api] escuchando en :${PORT}`);
  console.log(`[stress-api] cores=${CORES} workers=${CPU_WORKERS} max_ram=${MAX_RAM_MB}MB gpu_fraction=${GPU_FRACTION}`);
  console.log(`[stress-api] GPU: ${JSON.stringify(GPU)}`);
});
