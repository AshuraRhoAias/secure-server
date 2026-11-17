#!/usr/bin/env node
'use strict';

// Genera una CA propia y un certificado de servidor para MariaDB (TLS hacia la base de datos en producción).
// Usa el CLI `openssl` con execFileSync y argumentos en array (nunca una cadena de shell).
//
//   npm run db:tls -- [--out <dir>] [--host <nombre|ip>]... [--force] [--help]
//
// Las claves privadas NUNCA se guardan dentro del repositorio: la comprobación de ruta ocurre antes de buscar openssl.

const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

const REPO = path.resolve(__dirname, '..');

const AYUDA = `Uso: node scripts/dbTlsCerts.js [--out <dir>] [--host <nombre|ip>]... [--force]

  --out <dir>    carpeta de salida (por defecto %ProgramData%\\secure-server\\db-tls en Windows,
                 ~/.config/secure-server/db-tls en Linux/macOS). No puede estar dentro del repositorio.
  --host <h>     nombre DNS o IP extra para el subjectAltName (repetible; ya incluye localhost, 127.0.0.1 y ::1).
  --force        sobrescribe los archivos si ya existen.
  --help         muestra esta ayuda.

Genera: ca.pem, ca-key.pem, server-cert.pem, server-key.pem (CA de 10 años, servidor de 825 días).`;

function carpetaPorDefecto() {
  if (process.platform === 'win32') {
    const base = process.env.ProgramData || 'C:\\ProgramData';
    return path.join(base, 'secure-server', 'db-tls');
  }
  return path.join(os.homedir(), '.config', 'secure-server', 'db-tls');
}

function parseArgs(argv) {
  const r = { out: null, hosts: [], force: false, help: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--help' || a === '-h') r.help = true;
    else if (a === '--force') r.force = true;
    else if (a === '--out' || a === '--host') {
      const v = argv[++i];
      if (!v || v.startsWith('--')) throw new Error(`Falta el valor de ${a}`);
      if (a === '--out') r.out = v;
      else r.hosts.push(v);
    } else throw new Error(`Argumento desconocido: ${a}`);
  }
  return r;
}

function dentroDelRepo(dir) {
  const rel = path.relative(REPO, path.resolve(dir));
  return rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel));
}

// Solo nombres DNS o IPs razonables: se van a incrustar en el subjectAltName.
function sanHost(h) {
  if (!/^[A-Za-z0-9.:_-]{1,253}$/.test(h)) throw new Error(`Host no válido: ${h}`);
  return /^[0-9.]+$/.test(h) || h.includes(':') ? `IP:${h}` : `DNS:${h}`;
}

function openssl(args, opts = {}) {
  return execFileSync('openssl', args, { stdio: ['ignore', 'pipe', 'pipe'], encoding: 'utf8', ...opts });
}

function comprobarOpenssl() {
  try {
    openssl(['version']);
  } catch {
    const pista = process.platform === 'win32'
      ? ' En Windows instala Git for Windows y ejecuta esto desde Git Bash (incluye openssl), o añade openssl al PATH.'
      : ' Instálalo con el gestor de paquetes (p. ej. apt install openssl).';
    throw new Error(`No se encontró el comando «openssl».${pista}`);
  }
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    console.log(AYUDA);
    return;
  }
  const out = path.resolve(args.out || carpetaPorDefecto());

  // Antes de nada (y antes de buscar openssl): nunca claves privadas dentro del repositorio.
  if (dentroDelRepo(out)) {
    throw new Error(`Me niego a escribir claves privadas dentro del repositorio (${out}). Usa otra carpeta con --out.`);
  }
  const sans = ['DNS:localhost', 'IP:127.0.0.1', 'IP:::1', ...args.hosts.map(sanHost)];

  comprobarOpenssl();

  const f = {
    ca: path.join(out, 'ca.pem'),
    caKey: path.join(out, 'ca-key.pem'),
    cert: path.join(out, 'server-cert.pem'),
    key: path.join(out, 'server-key.pem'),
  };
  const existentes = Object.values(f).filter((p) => fs.existsSync(p));
  if (existentes.length && !args.force) {
    throw new Error(`Ya existen archivos (${existentes.map((p) => path.basename(p)).join(', ')}). Usa --force para sobrescribir.`);
  }
  fs.mkdirSync(out, { recursive: true });

  const csr = path.join(out, 'server.csr.tmp');
  const ext = path.join(out, 'server.ext.tmp');
  try {
    // CA propia (EC P-256, 10 años)
    openssl(['ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out', f.caKey]);
    openssl(['req', '-new', '-x509', '-key', f.caKey, '-sha256', '-days', '3650', '-subj', '/CN=secure-server DB CA',
      '-addext', 'basicConstraints=critical,CA:TRUE,pathlen:0', '-addext', 'keyUsage=critical,keyCertSign,cRLSign',
      '-out', f.ca]);

    // Certificado de servidor (EC P-256, 825 días)
    openssl(['ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out', f.key]);
    openssl(['req', '-new', '-key', f.key, '-subj', '/CN=localhost', '-out', csr]);
    fs.writeFileSync(ext, [
      'basicConstraints=critical,CA:FALSE',
      'keyUsage=critical,digitalSignature,keyAgreement',
      'extendedKeyUsage=serverAuth',
      `subjectAltName=${sans.join(',')}`,
      'subjectKeyIdentifier=hash',
      'authorityKeyIdentifier=keyid',
      '',
    ].join('\n'));
    openssl(['x509', '-req', '-in', csr, '-CA', f.ca, '-CAkey', f.caKey, '-CAcreateserial', '-sha256', '-days', '825',
      '-extfile', ext, '-out', f.cert]);
  } finally {
    for (const p of [csr, ext, path.join(out, 'ca.srl')]) fs.rmSync(p, { force: true });
  }

  if (process.platform !== 'win32') {
    fs.chmodSync(f.caKey, 0o600);
    fs.chmodSync(f.key, 0o600);
  }

  const veredicto = openssl(['verify', '-CAfile', f.ca, f.cert]).trim();
  if (!/OK\s*$/.test(veredicto)) throw new Error(`La verificación del certificado falló: ${veredicto}`);
  console.log(`Verificación: ${veredicto}`);

  console.log(`\nCertificados generados en ${out}\n  SAN: ${sans.join(', ')}`);
  console.log('\nSiguientes pasos:');
  if (process.platform === 'win32') {
    console.log(`  1. Como administrador: powershell -ExecutionPolicy Bypass -File instalador\\mariadb-tls.ps1 -CertDir "${out}"`);
  } else {
    console.log(`  1. Configura MariaDB (ssl_ca, ssl_cert, ssl_key en [mysqld]) con los archivos de ${out} y reinicia el servicio.`);
  }
  console.log('  2. En .env:');
  console.log('       DB_SSL=verify');
  console.log(`       DB_SSL_CA=${f.ca.replace(/\\/g, '/')}`);
  console.log('  3. npm start   (npm run dev y las pruebas siguen sin TLS)');
}

try {
  main();
} catch (e) {
  console.error(`Error: ${e.message}`);
  process.exit(1);
}
