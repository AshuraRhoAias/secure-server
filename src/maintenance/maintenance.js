const fs = require('fs');
const os = require('os');
const path = require('path');
const { getPaths } = require('./paths');
const { writeFileAtomic, readJsonIfExists, isPidAlive } = require('./fsutil');

// Bloqueo de mantenimiento. Mientras exista el archivo de lock, TODOS los procesos del servidor
// responden 503 a cualquier petición y no ejecutan tareas en segundo plano que escriban datos.
//
// Es un archivo (no memoria) porque la migración puede ejecutarse en un proceso distinto del
// servidor. Y falla CERRADO: si el proceso de migración muere, el lock sigue ahí y el servidor
// sigue cerrado hasta que alguien ejecute `npm run rotate-keys -- recover`. No caduca solo,
// porque reabrir el servidor a medias de una migración corrompería datos.

class Maintenance {
    constructor(paths = getPaths()) {
        this.paths = paths;
    }

    read() {
        return readJsonIfExists(this.paths.lockFile);
    }

    isLocked() {
        return fs.existsSync(this.paths.lockFile);
    }

    // Crea el lock de forma exclusiva (O_EXCL): si ya existe, lanza con los datos de quien lo tiene.
    acquire({ operation, reason }) {
        fs.mkdirSync(path.dirname(this.paths.lockFile), { recursive: true, mode: 0o700 });

        const info = {
            operation,
            reason,
            pid: process.pid,
            host: os.hostname(),
            startedAt: new Date().toISOString(),
            phase: 'LOCKED'
        };

        try {
            const fd = fs.openSync(this.paths.lockFile, 'wx', 0o600);
            fs.writeSync(fd, JSON.stringify(info, null, 2));
            fs.fsyncSync(fd);
            fs.closeSync(fd);
        } catch (error) {
            if (error.code !== 'EEXIST') throw error;
            const holder = this.read() || {};
            const alive = holder.host === os.hostname() ? (isPidAlive(holder.pid) ? 'activo' : 'MUERTO (huérfano)') : 'en otro host';
            const err = new Error(
                `Ya hay un bloqueo de mantenimiento (${holder.operation || '?'} desde ${holder.startedAt || '?'}, pid ${holder.pid}, proceso ${alive}). ` +
                'Si fue una migración interrumpida ejecuta: npm run rotate-keys -- recover'
            );
            err.code = 'MAINTENANCE_LOCKED';
            throw err;
        }
        return info;
    }

    setPhase(phase) {
        const info = this.read();
        if (info) writeFileAtomic(this.paths.lockFile, JSON.stringify({ ...info, phase }, null, 2));
    }

    release() {
        try {
            fs.unlinkSync(this.paths.lockFile);
        } catch (error) {
            if (error.code !== 'ENOENT') throw error;
        }
    }
}

module.exports = { Maintenance };
