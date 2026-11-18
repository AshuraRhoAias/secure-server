// Suites de `node --test` lanzadas desde la web: aquí SOLO está la lista cerrada, su validación y el catálogo.
//
// El servidor (src/) NO ejecuta procesos externos (invariante de seguridad: test/test_icmp.js). La ejecución la hace un trabajador
// independiente FUERA de src/ (`npm run ops:test-runner`, scripts/ops-test-runner.js) que el operador arranca a propósito:
//   - POST /api/system/runs (kind test_suite) valida la suite contra la lista cerrada y la deja en `queued`.
//   - El trabajador reclama la ejecución, la valida OTRA VEZ con este mismo módulo y la corre (spawn sin shell, entorno limpio...).
//   - Sin trabajador vivo (latido de < 15 s en ops_workers) el servidor responde 409 TEST_RUNNER_OFFLINE y no encola nada.
// Este módulo no lanza procesos; el trabajador sí (y nada de src/ importa scripts/).

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '../../..');

// clave → { label, files, db }. `db`: usa la BD de pruebas (hace DROP DATABASE de ella).
const SUITE_FILES = {
    test_api: { label: 'API sin BD (test_api)', files: ['test/test_api.js'], db: false },
    test_sanitize: { label: 'Saneado (test_sanitize)', files: ['test/test_sanitize.js'], db: true },
    test_security: { label: 'Seguridad (test_security)', files: ['test/test_security.js'], db: true },
    test_rbac: { label: 'Permisos por rol (test_rbac)', files: ['test/test_rbac.js'], db: true },
    test_sessions: { label: 'Sesiones (test_sessions)', files: ['test/test_sessions.js'], db: true },
    test_users_admin: { label: 'Usuarios desde la web (test_users_admin)', files: ['test/test_users_admin.js'], db: true },
    test_settings: { label: 'Configuración en caliente (test_settings)', files: ['test/test_settings.js'], db: true },
    test_fuzz: { label: 'Fuzzing (test_fuzz)', files: ['test/test_fuzz.js'], db: true }
};

// `all` = las mismas suites que `npm run test:all`, leídas de package.json (solo archivos test/test_*.js, sin la propia test_runs)
function allFiles() {
    try {
        const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
        const files = (pkg.scripts?.['test:all'] || '').split(/\s+/).filter(f => /^test\/test_[a-z0-9_]+\.js$/.test(f) && f !== 'test/test_runs.js');
        if (files.length) return files;
    } catch { /* se usa la lista fija */ }
    return Object.values(SUITE_FILES).flatMap(s => s.files);
}

const suites = () => ({ ...SUITE_FILES, all: { label: 'Todas (equivale a npm run test:all)', files: allFiles(), db: true } });

const timeoutMs = () => {
    const n = Number(process.env.OPS_TEST_RUNNER_TIMEOUT_MIN);
    return (Number.isFinite(n) && n > 0 ? n : 20) * 60_000;
};

// Valores por defecto IDÉNTICOS a los de test/helpers/env.js (TEST_APP_DB_URL) y test/test_rotation.js (TEST_DB_URL)
const DEFAULT_TEST_APP_DB_URL = 'mysql://sec:sec_test_pw@127.0.0.1:3306/secure_platform_test_app';
const DEFAULT_TEST_DB_URL = 'mysql://sec:sec_test_pw@127.0.0.1:3306/secure_platform_test';

// { host, port, name } de una URL de BD, o null si no se puede interpretar. localhost/127.0.0.1/::1/0.0.0.0 se normalizan a «localhost»
function dbTarget(urlText) {
    try {
        const url = new URL(urlText);
        let host = url.hostname.toLowerCase().replace(/^\[|\]$/g, '');
        if (['localhost', '127.0.0.1', '::1', '0.0.0.0', ''].includes(host)) host = 'localhost';
        const name = decodeURIComponent(url.pathname.replace(/^\//, '')).toLowerCase();
        if (!name) return null;
        return { host, port: url.port || '3306', name };
    } catch { return null; }
}

// Guarda contra el DROP DATABASE de la BD real. Devuelve null si todo está bien, o { code, message }: se obtienen las DOS BD de
// pruebas (TEST_APP_DB_URL y TEST_DB_URL) y la de la aplicación (DB_FRAGMENT_1+2+3); se niega si no se puede determinar la de la
// aplicación (APP_DB_UNKNOWN), si alguna de prueba coincide con ella (TEST_DB_IS_APP_DB) o si su nombre no contiene «test»
// (TEST_DB_NOT_TEST).
function dbGuard(env = process.env) {
    const tests = [
        ['TEST_APP_DB_URL', dbTarget(env.TEST_APP_DB_URL || DEFAULT_TEST_APP_DB_URL)],
        ['TEST_DB_URL', dbTarget(env.TEST_DB_URL || DEFAULT_TEST_DB_URL)]
    ];
    const app = dbTarget(`${env.DB_FRAGMENT_1 || ''}${env.DB_FRAGMENT_2 || ''}${env.DB_FRAGMENT_3 || ''}`);
    if (!app) return { code: 'APP_DB_UNKNOWN', message: 'No se pudo determinar la BD de la aplicación (DB_FRAGMENT_1/2/3): por seguridad no se lanzan suites que borran bases de datos' };
    for (const [variable, target] of tests) {
        if (!target) return { code: 'TEST_DB_NOT_TEST', message: `${variable} no es una URL de BD válida con nombre de base de datos` };
        if (target.host === app.host && target.port === app.port && target.name === app.name) {
            return { code: 'TEST_DB_IS_APP_DB', message: `${variable} apunta a la BD de la aplicación: las suites con BD la destruirían. Usa otra` };
        }
        if (!/test/.test(target.name)) {
            return { code: 'TEST_DB_NOT_TEST', message: `El nombre de la BD de ${variable} («${target.name}») debe contener «test»: las suites la borran y recrean` };
        }
    }
    return null;
}

const testDbName = () => dbTarget(process.env.TEST_APP_DB_URL || DEFAULT_TEST_APP_DB_URL)?.name || '';

// Entorno limpio del hijo: solo lo mínimo del sistema y las variables TEST_* (la BD de pruebas); nada de la aplicación
function childEnv(source = process.env) {
    const keep = ['PATH', 'Path', 'SystemRoot', 'SYSTEMROOT', 'windir', 'ComSpec', 'TEMP', 'TMP', 'TMPDIR', 'HOME', 'USERPROFILE', 'LANG', 'LC_ALL', 'TZ'];
    const env = {};
    for (const [name, value] of Object.entries(source)) {
        if (keep.includes(name) || /^TEST_[A-Z0-9_]+$/.test(name)) env[name] = value;
    }
    env.NODE_ENV = 'test';
    return env;
}

function describe() {
    return {
        title: 'Suites de pruebas',
        description: 'Ejecuta node --test sobre una lista cerrada de suites y muestra su salida en vivo. Las suites con BD usan la BD de PRUEBAS (se vacía), nunca la de la aplicación. Las corre un trabajador aparte (npm run ops:test-runner), no el servidor.',
        enabled: true, reason: null, timeoutMin: timeoutMs() / 60_000,
        warning: `Las suites marcadas «BD» borran y recrean la base de datos de pruebas «${testDbName()}», no la de la aplicación.`,
        suites: Object.entries(suites()).map(([value, s]) => ({ value, label: s.label, db: s.db }))
    };
}

// Lista cerrada (y guarda de BD en las suites que la usan). Lo llama la API al encolar y el trabajador al reclamar.
function validate(target) {
    const { RunError } = require('../runs.service');
    const all = suites();
    const suite = Object.hasOwn(all, target || '') ? all[target] : null;
    if (!suite) throw new RunError('INVALID_TARGET', 'Suite fuera de la lista permitida', 400);
    if (suite.db) {
        const problem = dbGuard();
        if (problem) throw new RunError(problem.code, problem.message, 409);
    }
}

module.exports = { validate, describe, suites, timeoutMs, childEnv, dbGuard, dbTarget, testDbName, SUITE_FILES, ROOT };
