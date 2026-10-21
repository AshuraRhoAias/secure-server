#!/usr/bin/env node
/*
 * seed-notes.js — Siembra N notas CIFRADAS (con el cifrado triple real de la
 * app) para un usuario, para poder medir lecturas bajo carga con datos reales.
 *
 * Uso:  node benchmarks/seed-notes.js --user-id 1 --count 100000 [--batch 1000]
 *
 * Usa el .env del proyecto (BD) y src/crypto/tripleEncryptor. Inserta en lotes.
 */
'use strict';
require('dotenv').config();
const path = require('path');

function arg(name, def) { const i = process.argv.indexOf('--' + name); return i === -1 ? def : process.argv[i + 1]; }
const USER_ID = parseInt(arg('user-id', '1'), 10);
const COUNT = parseInt(arg('count', '100000'), 10);
const BATCH = parseInt(arg('batch', '1000'), 10);

// Silenciar los logs verbosos del cifrador durante la siembra.
const origLog = console.log; console.log = () => {};
const db = require(path.join('..', 'src', 'config', 'database'));
const tripleEncryptor = require(path.join('..', 'src', 'crypto', 'tripleEncryptor'));
console.log = origLog;

function bar(done, total) {
  const w = 30, r = done / total, f = Math.round(r * w);
  process.stdout.write(`\r  [${'█'.repeat(f)}${'░'.repeat(w - f)}] ${String(Math.round(r * 100)).padStart(3)}%  ${done}/${total}`);
}

(async () => {
  const t0 = Date.now();
  console.log = () => {};
  origLog(`Sembrando ${COUNT} notas cifradas para user_id=${USER_ID} (lotes de ${BATCH})…`);
  let inserted = 0;
  try {
    for (let start = 0; start < COUNT; start += BATCH) {
      const n = Math.min(BATCH, COUNT - start);
      const placeholders = [];
      const params = [];
      for (let i = 0; i < n; i++) {
        const idx = start + i;
        const title = tripleEncryptor.encrypt(`Nota de carga #${idx}`);
        const content = tripleEncryptor.encrypt(`Contenido sintético ${idx} — ${'x'.repeat(64)} ${Date.now()}`);
        placeholders.push('(?, ?, ?, ?)');
        params.push(USER_ID, title, content, 'v3.1.0');
      }
      await db.query(
        `INSERT INTO user_notes (user_id, title_encrypted, content_encrypted, encryption_version) VALUES ${placeholders.join(', ')}`,
        params
      );
      inserted += n;
      console.log = origLog; bar(inserted, COUNT); console.log = () => {};
    }
    console.log = origLog;
    const secs = ((Date.now() - t0) / 1000).toFixed(1);
    origLog(`\n✔ Sembradas ${inserted} notas en ${secs}s (${Math.round(inserted / secs)} filas/s)`);
    process.exit(0);
  } catch (e) {
    console.log = origLog;
    origLog('\n✖ Error sembrando:', e.message);
    process.exit(1);
  }
})();
