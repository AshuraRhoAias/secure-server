// Proceso HIJO para las pruebas de caídas y pausas de la rotación (test_rotation.js). Ejecuta una rotación REAL contra la
// base de datos de pruebas y, en el punto de control pedido, se corta en seco o se queda parado:
//
//   ROT_KILL_AT=<fase>           SIGKILL a sí mismo al llegar a esa fase (REENCRYPTED, DB_COMMITTED, FINALIZE…)
//   ROT_KILL_AT_STEP=<paso>      SIGKILL tras ese paso de finalizeFiles (keyring, env)
//   ROT_PAUSE_AT=<fase>          al llegar, escribe ROT_MARKER (JSON con los ids de sus conexiones) y espera a que aparezca
//                                ROT_GO; entonces sigue (simula un proceso parado al que la BD le corta las conexiones)
//
// El resultado va a ROT_RESULT (JSON): stdout lo usan los registros de los módulos.
// Usa las mismas variables que el resto de pruebas (DB_FRAGMENT_*, semillas) y ROTATION_DATA_DIR / BACKUP_DIR / ENV_FILE.
// Nunca llama a prepareDatabase(): trabaja sobre lo que dejó preparado el proceso padre.
const fs = require('fs');

const die = () => process.kill(process.pid, 'SIGKILL'); // corte en seco: ni finally, ni catch, ni flush
const quiet = { log() {} };

async function main() {
    const db = require('../../src/config/database');
    const encryptor = require('../../src/crypto/tripleEncryptor');
    const { RotationService } = require('../../src/maintenance/rotation.service');
    const { getPaths } = require('../../src/maintenance/paths');
    const paths = getPaths(process.env);
    const service = new RotationService({ db, encryptor, paths, logger: quiet, sleepFn: async () => {} });

    const onPhase = async (name, { conn, lockConn }) => {
        if (name === process.env.ROT_KILL_AT) die();
        if (name === process.env.ROT_PAUSE_AT) {
            const [[a]] = await conn.query('SELECT CONNECTION_ID() AS id');
            const [[b]] = await lockConn.query('SELECT CONNECTION_ID() AS id');
            fs.writeFileSync(process.env.ROT_MARKER, JSON.stringify({ conn: Number(a.id), lockConn: Number(b.id) }));
            while (!fs.existsSync(process.env.ROT_GO)) await new Promise(r => setTimeout(r, 50));
        }
    };
    const onFinalizeStep = (step) => { if (step === process.env.ROT_KILL_AT_STEP) die(); };

    try {
        const result = await service.run({ env: { ...process.env }, drainSeconds: 0, hooks: { onPhase, onFinalizeStep } });
        fs.writeFileSync(process.env.ROT_RESULT, JSON.stringify({ ok: true, rotationId: result.rotationId }));
    } catch (error) {
        fs.writeFileSync(process.env.ROT_RESULT, JSON.stringify({ ok: false, phase: error.rotationPhase, message: error.message }));
    } finally {
        await db.pool.end().catch(() => {});
    }
}

main().then(() => process.exit(0));
