// Arnés de las pruebas de extremo a extremo: levanta el API REAL (src/index.js) contra MariaDB y la aplicación web REAL (next start),
// y las maneja con un navegador real (Chromium vía Playwright).
'use strict';
const fs = require('fs');
const net = require('net');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');
const { createRequire } = require('module');

const WEB = path.join(__dirname, '..');
const ROOT = path.join(WEB, '..');
const rootRequire = createRequire(path.join(ROOT, 'package.json'));

// Carga el entorno de pruebas del API (BD de pruebas, semillas…) ANTES que cualquier módulo del proyecto
const { dbUrl, DB_NAME, filesDir } = require(path.join(ROOT, 'test_helpers/env'));
const helpers = require(path.join(ROOT, 'test_helpers/app'));
const totp = require(path.join(ROOT, 'src/security/totp'));

const freePort = () => new Promise((resolve) => { const s = net.createServer(); s.listen(0, '127.0.0.1', () => { const { port } = s.address(); s.close(() => resolve(port)); }); });
const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

async function waitFor(url, { timeout = 90_000, ok = (r) => r.status === 200 } = {}) {
  const end = Date.now() + timeout;
  for (;;) {
    try { if (ok(await fetch(url, { signal: AbortSignal.timeout(2000) }))) return; } catch { /* arrancando */ }
    if (Date.now() > end) throw new Error(`tiempo agotado esperando ${url}`);
    await sleep(300);
  }
}

function launch(name, command, args, { env, cwd }) {
  const logs = [];
  const child = spawn(command, args, { env, cwd, stdio: ['ignore', 'pipe', 'pipe'] });
  child.stdout.on('data', d => logs.push(String(d)));
  child.stderr.on('data', d => logs.push(String(d)));
  return { name, child, logs, stop: () => new Promise((resolve) => { if (child.exitCode !== null) return resolve(); child.once('exit', resolve); child.kill('SIGTERM'); setTimeout(() => child.kill('SIGKILL'), 8000).unref(); }) };
}

async function startApi(extraEnv = {}) {
  const port = await freePort();
  const envFile = path.join(os.tmpdir(), `ops-e2e-${process.pid}.env`);
  fs.writeFileSync(envFile, '# vacío a propósito\n');
  const proc = launch('api', process.execPath, [path.join(ROOT, 'src/index.js')], {
    cwd: ROOT,
    env: { ...process.env, ENV_FILE: envFile, PORT: String(port), TRUST_PROXY: '1', ALERTS_DISABLED: 'true', PROTECTION_CACHE_MS: '0', ...extraEnv }
  });
  await waitFor(`http://127.0.0.1:${port}/health`);
  return { ...proc, port, base: `http://127.0.0.1:${port}`, envFile };
}

async function startWeb(apiBase, extraEnv = {}) {
  const port = await freePort();
  if (!fs.existsSync(path.join(WEB, '.next', 'BUILD_ID'))) throw new Error('Falta `npm run build` en web/ antes de las pruebas de extremo a extremo');
  const proc = launch('web', process.execPath, [path.join(WEB, 'node_modules/next/dist/bin/next'), 'start', '-p', String(port), '-H', '127.0.0.1'], {
    cwd: WEB,
    env: {
      ...process.env, NODE_ENV: 'production', NEXT_TELEMETRY_DISABLED: '1',
      OPS_API_URL: apiBase, OPS_API_ALLOW_HTTP: 'true', WEB_COOKIE_SECURE: 'false', WEB_TRUST_PROXY_HOPS: '0',
      WEB_SESSION_SECRET: 'e2e-secreto-de-pruebas-0123456789abcdef0123456789', ...extraEnv
    }
  });
  await waitFor(`http://127.0.0.1:${port}/login`);
  return { ...proc, port, base: `http://127.0.0.1:${port}` };
}

async function db() {
  const mysql = rootRequire('mysql2/promise');
  return mysql.createPool({ host: dbUrl.hostname, port: Number(dbUrl.port) || 3306, user: dbUrl.username, password: dbUrl.password, database: DB_NAME, connectionLimit: 3 });
}

function playwright() {
  try { return require('playwright'); } catch { return createRequire(path.join(WEB, 'package.json'))('playwright'); }
}

module.exports = { WEB, ROOT, helpers, totp, startApi, startWeb, db, playwright, sleep, filesDir, waitFor };
