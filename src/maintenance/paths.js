const path = require('path');

const ROOT = path.join(__dirname, '../..');

// Todo configurable por variables de entorno (útil en tests y en despliegues con volúmenes)
function getPaths(env = process.env) {
    const dataDir = env.ROTATION_DATA_DIR || path.join(ROOT, 'data/rotation');
    return {
        root: ROOT,
        dataDir,
        backupDir: env.BACKUP_DIR || path.join(ROOT, 'backups'),
        envFile: env.ENV_FILE || path.join(ROOT, '.env'),
        lockFile: path.join(dataDir, 'maintenance.lock'),
        journalFile: path.join(dataDir, 'journal.json'),
        keyringFile: env.BACKUP_DIR ? path.join(env.BACKUP_DIR, 'keyring.json') : path.join(ROOT, 'backups/keyring.json')
    };
}

module.exports = { getPaths };
