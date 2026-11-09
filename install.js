#!/usr/bin/env node
/*
 * install.js — Instalador multiplataforma de secure-server (Linux y Windows).
 *
 * Al ejecutarlo pregunta en qué sistema se quiere instalar (Linux o Windows),
 * e instala todo lo necesario mostrando una barra de progreso.
 *
 * No añade dependencias: usa sólo módulos nativos de Node (>=18).
 *
 * Uso:
 *   node install.js                 # modo interactivo (pregunta el SO)
 *   node install.js --os linux      # sin preguntar
 *   node install.js --os windows
 *   node install.js --yes           # acepta pasos opcionales (toolset de seguridad)
 *   node install.js --no-tools      # omite el toolset de seguridad de PruebasLinux
 *   node install.js --help
 */
'use strict';

const { spawn } = require('child_process');
const readline = require('readline');
const fs = require('fs');
const path = require('path');
const os = require('os');

const ROOT = __dirname;
const isTTY = process.stdout.isTTY;

// ---- Colores (desactivados sin TTY o con NO_COLOR) ----
const C = (isTTY && !process.env.NO_COLOR)
  ? { r: '\x1b[0m', b: '\x1b[1m', dim: '\x1b[2m', red: '\x1b[31m', grn: '\x1b[32m', yel: '\x1b[33m', cya: '\x1b[36m' }
  : { r: '', b: '', dim: '', red: '', grn: '', yel: '', cya: '' };

function log(msg) { process.stdout.write(msg + '\n'); }
function info(m) { log(`${C.cya}ℹ${C.r}  ${m}`); }
function ok(m) { log(`${C.grn}✔${C.r}  ${m}`); }
function warn(m) { log(`${C.yel}⚠${C.r}  ${m}`); }
function errline(m) { log(`${C.red}✖${C.r}  ${m}`); }

// ---- Argumentos ----
function parseArgs(argv) {
  const a = { os: null, yes: false, tools: true, help: false };
  for (let i = 2; i < argv.length; i++) {
    const t = argv[i];
    if (t === '--os') { a.os = (argv[++i] || '').toLowerCase(); }
    else if (t === '--yes' || t === '-y') { a.yes = true; }
    else if (t === '--no-tools') { a.tools = false; }
    else if (t === '--help' || t === '-h') { a.help = true; }
    else { warn(`Argumento ignorado: ${t}`); }
  }
  return a;
}

function usage() {
  log(`Instalador de secure-server

  node install.js                 Modo interactivo (pregunta Linux/Windows)
  node install.js --os linux      Instala para Linux sin preguntar
  node install.js --os windows    Instala para Windows sin preguntar
  node install.js --yes           Acepta pasos opcionales (toolset de seguridad)
  node install.js --no-tools      Omite el toolset de PruebasLinux
  node install.js --help          Esta ayuda`);
}

// ---- Prompt (readline) ----
function ask(question) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    rl.question(question, (ans) => { rl.close(); resolve(ans.trim()); });
  });
}

async function chooseOS(preset) {
  const valid = { linux: 'linux', windows: 'windows', win: 'windows', '1': 'linux', '2': 'windows' };
  if (preset) {
    if (valid[preset]) return valid[preset];
    errline(`SO no válido: "${preset}". Usa "linux" o "windows".`);
    process.exit(2);
  }
  const detected = process.platform === 'win32' ? 'windows' : (process.platform === 'linux' ? 'linux' : process.platform);
  if (!isTTY) {
    warn(`Sin terminal interactiva; uso el SO detectado: ${detected}.`);
    return detected === 'windows' ? 'windows' : 'linux';
  }
  log('');
  log(`${C.b}¿En qué sistema quieres instalar secure-server?${C.r}`);
  log(`  ${C.b}1)${C.r} Linux   ${C.dim}(apt + pip para el toolset)${C.r}`);
  log(`  ${C.b}2)${C.r} Windows ${C.dim}(npm; toolset vía winget/choco, opcional)${C.r}`);
  log(`${C.dim}  (SO detectado: ${detected})${C.r}`);
  while (true) {
    const ans = (await ask('Elige 1 (Linux) o 2 (Windows): ')).toLowerCase();
    if (valid[ans]) return valid[ans];
    errline('Entrada no válida. Escribe 1, 2, linux o windows.');
  }
}

// ---- Barra de progreso ----
class Progress {
  constructor(total) { this.total = total; this.done = 0; this.label = ''; this.spin = 0; this.timer = null; }
  _render() {
    const width = 30;
    const ratio = this.total ? this.done / this.total : 0;
    const filled = Math.round(ratio * width);
    const bar = '█'.repeat(filled) + '░'.repeat(width - filled);
    const pct = String(Math.round(ratio * 100)).padStart(3);
    const frames = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
    const sp = frames[this.spin % frames.length];
    const line = `  ${C.cya}${sp}${C.r} [${C.grn}${bar}${C.r}] ${pct}%  ${this.label}`;
    if (isTTY) {
      readline.clearLine(process.stdout, 0);
      readline.cursorTo(process.stdout, 0);
      process.stdout.write(line);
    }
  }
  start(label) {
    this.label = label;
    if (isTTY) { this.timer = setInterval(() => { this.spin++; this._render(); }, 120); this._render(); }
    else { log(`  … ${label}`); }
  }
  step(label) {
    this.done = Math.min(this.total, this.done + 1);
    if (label) this.label = label;
    this._render();
  }
  finishLine(okMsg) {
    if (this.timer) { clearInterval(this.timer); this.timer = null; }
    if (isTTY) { readline.clearLine(process.stdout, 0); readline.cursorTo(process.stdout, 0); }
    if (okMsg) ok(okMsg);
  }
}

// ---- Ejecutar un comando mostrando progreso (streaming a un log) ----
function run(cmd, args, opts = {}) {
  return new Promise((resolve) => {
    const child = spawn(cmd, args, { cwd: ROOT, shell: process.platform === 'win32', ...opts });
    let out = '';
    if (child.stdout) child.stdout.on('data', (d) => { out += d; });
    if (child.stderr) child.stderr.on('data', (d) => { out += d; });
    child.on('error', (e) => resolve({ code: 127, out: String(e.message) }));
    child.on('close', (code) => resolve({ code, out }));
  });
}

function have(cmd) {
  const r = require('child_process').spawnSync(process.platform === 'win32' ? 'where' : 'which', [cmd], { encoding: 'utf8' });
  return r.status === 0;
}

// ---- Pasos de instalación ----
async function main() {
  const args = parseArgs(process.argv);
  if (args.help) { usage(); return 0; }

  log(`${C.b}${C.cya}`);
  log('  ╔══════════════════════════════════════════════╗');
  log('  ║     Instalador de secure-server              ║');
  log('  ╚══════════════════════════════════════════════╝');
  log(C.r);

  const target = await chooseOS(args.os);
  ok(`Instalación para: ${C.b}${target}${C.r}`);

  // Validación de Node
  const major = parseInt(process.versions.node.split('.')[0], 10);
  if (major < 18) { errline(`Se requiere Node >= 18 (tienes ${process.versions.node}).`); return 1; }

  // Construir la lista de pasos
  const steps = [];

  steps.push({
    name: 'Comprobar requisitos',
    run: async () => {
      const notes = [`Node ${process.versions.node}`, `npm ${have('npm') ? 'presente' : 'AUSENTE'}`];
      if (!have('npm')) throw new Error('npm no está disponible en el PATH.');
      return notes.join(' · ');
    }
  });

  steps.push({
    name: 'Instalar dependencias de Node (npm)',
    run: async () => {
      const useCi = fs.existsSync(path.join(ROOT, 'package-lock.json'));
      // En producción NO se instalan las dependencias de desarrollo (nodemon, eslint, c8…): menos código, menos superficie
      const production = process.env.NODE_ENV === 'production' || process.argv.includes('--production');
      const r = await run(process.platform === 'win32' ? 'npm.cmd' : 'npm', [useCi ? 'ci' : 'install', ...(production ? ['--omit=dev'] : []), '--no-audit', '--no-fund']);
      if (r.code !== 0) throw new Error('npm falló:\n' + r.out.split('\n').slice(-8).join('\n'));
      return `${useCi ? 'npm ci' : 'npm install'} completado${production ? ' (sin dependencias de desarrollo)' : ''}`;
    }
  });

  steps.push({
    name: 'Preparar archivo .env',
    run: async () => {
      const env = path.join(ROOT, '.env');
      const example = path.join(ROOT, '.env.example');
      if (fs.existsSync(env)) return '.env ya existe (no se sobrescribe)';
      if (fs.existsSync(example)) {
        fs.copyFileSync(example, env);
        if (target === 'linux') { try { fs.chmodSync(env, 0o600); } catch (_) {} }
        return '.env creado desde .env.example' + (target === 'linux' ? ' (permisos 600)' : '');
      }
      return 'No hay .env.example; crea el .env manualmente (ver README)';
    }
  });

  steps.push({
    name: 'Ajustar permisos',
    run: async () => {
      if (target !== 'linux') return 'omitido en Windows';
      const env = path.join(ROOT, '.env');
      if (fs.existsSync(env)) { try { fs.chmodSync(env, 0o600); return 'chmod 600 .env'; } catch (_) { return 'no se pudo ajustar (continúa)'; } }
      return 'sin .env que ajustar';
    }
  });

  // Toolset de seguridad para PruebasLinux (opcional)
  let wantTools = args.tools;
  if (wantTools && !args.yes && isTTY) {
    const ans = (await ask('¿Instalar también el toolset de seguridad de PruebasLinux (nmap, sslscan, …)? [s/N]: ')).toLowerCase();
    wantTools = (ans === 's' || ans === 'y' || ans === 'si');
  } else if (wantTools && !args.yes && !isTTY) {
    wantTools = false; // sin TTY no asumimos instalaciones del sistema
  }

  if (wantTools) {
    steps.push({
      name: 'Instalar toolset de seguridad (PruebasLinux)',
      run: async () => {
        if (target === 'linux') {
          if (!have('apt-get')) return 'apt-get no disponible; instala el toolset manualmente (ver PruebasLinux/ReadmeLogMejoras.md)';
          const sudo = (typeof process.getuid === 'function' && process.getuid() === 0) ? [] : ['sudo'];
          const pkgs = ['nmap', 'sslscan', 'nikto', 'whatweb', 'tcpdump', 'shellcheck', 'sqlite3', 'dnsutils', 'iputils-ping', 'traceroute', 'mtr-tiny', 'whois', 'net-tools'];
          const r1 = await run(sudo[0] || 'apt-get', sudo.length ? ['apt-get', 'update'] : ['update'], { env: { ...process.env, DEBIAN_FRONTEND: 'noninteractive' } });
          const r2 = await run(sudo[0] || 'apt-get', [...sudo.slice(1), 'apt-get', 'install', '-y', '--no-install-recommends', ...pkgs].filter(Boolean), { env: { ...process.env, DEBIAN_FRONTEND: 'noninteractive' } });
          const pip = have('pip3') ? await run('pip3', ['install', '--break-system-packages', '--quiet', 'pip-audit', 'detect-secrets', 'yamllint', 'bandit']) : { code: 1 };
          const okApt = r2.code === 0;
          return `apt: ${okApt ? 'ok' : 'revisar'} · pip: ${pip.code === 0 ? 'ok' : 'omitido/revisar'}`;
        }
        // Windows
        if (have('winget')) return 'En Windows: ejecuta `winget install Nmap.Nmap` y las demás (ver PruebasLinux/ReadmeLogMejoras.md)';
        if (have('choco')) return 'En Windows: `choco install nmap sqlite` (ver PruebasLinux/ReadmeLogMejoras.md)';
        return 'Instala el toolset con winget/choco o WSL (ver PruebasLinux/ReadmeLogMejoras.md)';
      }
    });
  }

  steps.push({
    name: 'Verificación final',
    run: async () => {
      const okNm = fs.existsSync(path.join(ROOT, 'node_modules'));
      if (!okNm) throw new Error('node_modules no existe tras la instalación.');
      return 'dependencias presentes';
    }
  });

  // Ejecutar pasos con barra de progreso
  log('');
  const bar = new Progress(steps.length);
  const results = [];
  for (const s of steps) {
    bar.start(s.name);
    try {
      const detail = await s.run();
      bar.step(s.name);
      bar.finishLine(`${s.name}${detail ? ` — ${detail}` : ''}`);
      results.push({ name: s.name, ok: true });
    } catch (e) {
      bar.step(s.name);
      bar.finishLine('');
      errline(`${s.name} — ${e.message}`);
      results.push({ name: s.name, ok: false });
      // Un fallo en un paso crítico detiene; los opcionales ya se capturan dentro.
      if (/dependencias de Node|requisitos/i.test(s.name)) {
        errline('Instalación interrumpida por un error crítico.');
        return 1;
      }
    }
  }

  log('');
  const failed = results.filter((r) => !r.ok);
  if (failed.length === 0) {
    ok(`${C.b}Instalación completada.${C.r}`);
  } else {
    warn(`Instalación terminada con ${failed.length} paso(s) con avisos.`);
  }
  log('');
  info('Siguientes pasos:');
  log('  1. Revisa y completa el archivo .env (credenciales, semillas).');
  if (target === 'linux') log('  2. Crea la BD:  mysql -u <user> -p <db> < database/schema.sql');
  else log('  2. Crea la BD en MySQL e importa database/schema.sql');
  log('  3. Arranca:  npm start');
  log('  4. Pruebas de seguridad:  cd PruebasLinux && ./pruebas.sh   (en Windows: usa WSL/Git Bash)');
  return failed.length === 0 ? 0 : 0; // los avisos no son error de salida
}

main().then((code) => process.exit(code || 0)).catch((e) => { errline('Error inesperado: ' + e.message); process.exit(1); });
