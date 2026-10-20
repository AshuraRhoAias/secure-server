const fs = require('fs');
const path = require('path');

// Escritura atómica y durable: se escribe en un temporal, se fuerza a disco y se renombra.
// Un fallo a mitad deja el archivo anterior intacto, nunca uno a medias.
function writeFileAtomic(file, data, mode = 0o600) {
    fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
    const tmp = `${file}.tmp-${process.pid}`;
    const fd = fs.openSync(tmp, 'w', mode);
    try {
        fs.writeSync(fd, data);
        fs.fsyncSync(fd);
    } finally {
        fs.closeSync(fd);
    }
    fs.renameSync(tmp, file);
}

function readJsonIfExists(file) {
    try {
        return JSON.parse(fs.readFileSync(file, 'utf8'));
    } catch (error) {
        if (error.code === 'ENOENT') return null;
        throw error;
    }
}

function isPidAlive(pid) {
    try {
        process.kill(pid, 0);
        return true;
    } catch (error) {
        return error.code === 'EPERM';
    }
}

module.exports = { writeFileAtomic, readJsonIfExists, isPidAlive };
