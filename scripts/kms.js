#!/usr/bin/env node
// Gestión de secretos envueltos por un KMS/HSM (ver src/crypto/kms.js y docs/SEGURIDAD.md §KMS).
//
//   npm run kms -- status                       proveedor configurado, prueba de ida y vuelta, variables envueltas
//   npm run kms -- wrap NOMBRE                  lee el valor por stdin y escribe NOMBRE=kms:...  (el valor no pasa por argv)
//   npm run kms -- migrate-env [--file .env]    envuelve en el sitio las semillas y secretos del .env
//        [--vars A,B,C] [--no-backup] [--rewrap]    (--rewrap: pasa de un KMS a otro)
//   npm run kms -- unwrap-env [--file .env]     escribe por stdout el .env en CLARO (salida de emergencia)

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const dotenv = require('dotenv');
const kms = require('../src/crypto/kms');

const DEFAULT_VARS = ['BASE_SEED', 'ENCRYPTION_SEED', 'JWT_SEED', 'EMAIL_SEED', 'DB_FRAGMENT_1', 'PRIMARY_EMAIL_PASSWORD', 'BACKUP_EMAIL_PASSWORD', 'TELEGRAM_BOT_TOKEN'];

const args = process.argv.slice(2);
const command = args[0];
const flag = (name) => args.includes(name);
const option = (name, fallback) => { const i = args.indexOf(name); return i >= 0 && args[i + 1] ? args[i + 1] : fallback; };
const envFile = path.resolve(option('--file', process.env.ENV_FILE || path.join(__dirname, '../.env')));

function replaceInEnvText(text, updates) {
    const pending = new Set(Object.keys(updates));
    const out = text.split('\n').map((line) => {
        const m = /^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=/.exec(line);
        if (m && pending.has(m[1])) { pending.delete(m[1]); return `${m[1]}=${updates[m[1]]}`; }
        return line;
    });
    return out.join('\n');
}

function writeAtomic(file, text) {
    const tmp = `${file}.${process.pid}.tmp`;
    fs.writeFileSync(tmp, text, { mode: 0o600 });
    fs.renameSync(tmp, file);
}

function status() {
    console.log(`Proveedor para envolver: ${process.env.KMS_PROVIDER || '(no definido: KMS_PROVIDER)'}`);
    if (process.env.KMS_PROVIDER) {
        const probe = crypto.randomBytes(16).toString('hex');
        const wrapped = kms.wrapValue('KMS_STATUS_PROBE', probe);
        kms.clearCache();
        const ok = kms.resolveValue('KMS_STATUS_PROBE', wrapped) === probe;
        console.log(ok ? '✅ Prueba de cifrado/descifrado correcta' : '❌ La prueba de ida y vuelta falló');
        if (!ok) process.exitCode = 1;
    }
    if (fs.existsSync(envFile)) {
        const vars = dotenv.parse(fs.readFileSync(envFile));
        const wrapped = Object.keys(vars).filter(k => kms.isWrapped(vars[k]));
        const plain = DEFAULT_VARS.filter(k => vars[k] && !kms.isWrapped(vars[k]));
        console.log(`Variables envueltas en ${envFile}: ${wrapped.join(', ') || '(ninguna)'}`);
        if (plain.length) console.log(`⚠️ Secretos todavía en claro: ${plain.join(', ')}  →  npm run kms -- migrate-env`);
    }
}

function wrap() {
    const name = args[1];
    if (!name || !/^[A-Z_][A-Z0-9_]*$/i.test(name)) throw new Error('Uso: echo -n "valor" | npm run kms -- wrap NOMBRE');
    const value = fs.readFileSync(0, 'utf8').replace(/\r?\n$/, '');
    if (!value) throw new Error('No se recibió ningún valor por stdin');
    console.log(`${name}=${kms.wrapValue(name, value)}`);
}

function migrateEnv() {
    if (!process.env.KMS_PROVIDER) throw new Error('Define KMS_PROVIDER (file | vault | aws) y su configuración antes de migrar');
    const text = fs.readFileSync(envFile, 'utf8');
    const vars = dotenv.parse(text);
    const names = (option('--vars', '') ? option('--vars').split(',') : DEFAULT_VARS).map(s => s.trim());

    // --rewrap: también se vuelven a envolver los que ya lo estaban (con el proveedor ANTERIOR, que debe seguir accesible)
    const targets = names.filter(n => vars[n] && (flag('--rewrap') || !kms.isWrapped(vars[n])));
    if (targets.length === 0) { console.log('Nada que migrar: no hay secretos en claro en ese archivo.'); return; }

    const plain = kms.resolveMany(targets.map(n => [n, vars[n]]));
    const wrapped = kms.wrapMany(targets.map((n, i) => [n, plain[i]]));

    // Se comprueba la ida y vuelta SIN caché antes de tocar el archivo
    kms.clearCache();
    const back = kms.resolveMany(targets.map((n, i) => [n, wrapped[i]]));
    if (back.some((v, i) => v !== plain[i])) throw new Error('La verificación de ida y vuelta falló: el archivo NO se ha modificado');

    if (!flag('--no-backup')) {
        const backup = `${envFile}.pre-kms`;
        fs.writeFileSync(backup, text, { mode: 0o600 });
        console.log(`⚠️ Copia con los valores EN CLARO: ${backup}. Guárdala fuera del servidor o bórrala de forma segura cuando compruebes que todo arranca.`);
    }
    writeAtomic(envFile, replaceInEnvText(text, Object.fromEntries(targets.map((n, i) => [n, wrapped[i]]))));
    console.log(`✅ ${targets.length} variables envueltas con ${process.env.KMS_PROVIDER}: ${targets.join(', ')}`);
}

function unwrapEnv() {
    const text = fs.readFileSync(envFile, 'utf8');
    const vars = dotenv.parse(text);
    const targets = Object.keys(vars).filter(k => kms.isWrapped(vars[k]));
    const plain = kms.resolveMany(targets.map(n => [n, vars[n]]));
    process.stdout.write(replaceInEnvText(text, Object.fromEntries(targets.map((n, i) => [n, plain[i]]))));
}

const commands = { status, wrap, 'migrate-env': migrateEnv, 'unwrap-env': unwrapEnv };
try {
    if (commands[command]) {
        commands[command]();
    } else {
        console.log('Uso: npm run kms -- status | wrap NOMBRE | migrate-env [--file .env] [--vars A,B] [--no-backup] [--rewrap] | unwrap-env [--file .env]');
        process.exitCode = command ? 2 : 0;
    }
} catch (error) {
    console.error(`❌ ${error.message}`);
    process.exitCode = 1;
}
