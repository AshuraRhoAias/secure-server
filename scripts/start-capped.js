#!/usr/bin/env node
/*
 * start-capped.js — Arranca el servidor usando SÓLO la mitad del equipo.
 *
 * Detecta la capacidad (núcleos y RAM) con src/config/capacity.js y relanza
 * `node` con `--max-old-space-size` fijado a la mitad de la RAM, además de
 * exportar UV_THREADPOOL_SIZE. El resto de topes (pool de BD, trabajadores) ya
 * los aplica el propio servidor al arrancar a partir del mismo presupuesto.
 *
 * Uso:  node scripts/start-capped.js     (o: npm run start:half)
 * Ajustable con CAPACITY_FRACTION (por defecto 0.5).
 */
'use strict';
const path = require('path');
const { spawn } = require('child_process');
const capacity = require(path.join('..', 'src', 'config', 'capacity'));

capacity.summaryLines().forEach(line => console.log(line));

const entry = path.join(__dirname, '..', 'src', 'index.js');
const nodeArgs = [`--max-old-space-size=${capacity.recommendedMaxOldSpaceMB}`, entry];

const child = spawn(process.execPath, nodeArgs, {
    stdio: 'inherit',
    env: { ...process.env, UV_THREADPOOL_SIZE: String(capacity.threadPool) }
});

// Reenviar señales para un cierre limpio del servidor hijo.
['SIGINT', 'SIGTERM'].forEach(sig => process.on(sig, () => child.kill(sig)));
child.on('exit', code => process.exit(code === null ? 1 : code));
