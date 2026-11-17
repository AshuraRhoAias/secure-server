// `npm run dev`: SOLO para desarrollo. Reinicia el servidor al cambiar sus archivos con el modo vigilancia de Node
// (`node --watch`, de serie desde Node 22), sin nodemon: nodemon arrastraba chokidar → picomatch, con una vulnerabilidad alta
// (GHSA-fc5q-39xc-vjpf) sin versión corregida publicada.
//   - Se niega si NODE_ENV=production: en producción se usa "npm start" (node src/index.js) bajo un gestor de procesos.
//   - Fija NODE_ENV=development y DB_SSL=off (desarrollo local sin TLS hacia la base de datos; `npm start` usa el .env).
const { spawn } = require('child_process');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const ENTRY = 'src/index.js';

// Entorno del proceso de desarrollo. dotenv no pisa variables ya definidas, así que estas mandan sobre el .env.
function devEnv(base = process.env) {
    return { ...base, NODE_ENV: 'development', DB_SSL: 'off' };
}

function main() {
    if (process.env.NODE_ENV === 'production') {
        console.error('❌ "npm run dev" no se usa en producción. Arranca con "npm start" (node src/index.js) bajo un gestor de procesos.');
        process.exit(1);
    }

    const child = spawn(process.execPath, ['--watch', ENTRY], { cwd: ROOT, env: devEnv(), stdio: 'inherit' });
    // Ctrl+C llega a los dos procesos (mismo grupo de la consola); se reenvían las señales por si llegan solo al padre
    for (const signal of ['SIGINT', 'SIGTERM']) {
        process.on(signal, () => { if (!child.killed) child.kill(signal); });
    }
    child.on('exit', (code, signal) => process.exit(code ?? (signal ? 1 : 0)));
}

if (require.main === module) main();

module.exports = { devEnv, ENTRY };
