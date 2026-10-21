const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// Almacenamiento en disco de los archivos CIFRADOS.
//
//   <FILES_DIR>/tmp/<uuid>.part          subida en curso (se borra sola si queda huérfana)
//   <FILES_DIR>/files/<aa>/<uuid>.enc    archivo ya confirmado (aa = 2 primeros caracteres del uuid)
//
// El nombre en disco es un UUID generado por el servidor: NADA de lo que envía el usuario (ni el nombre
// del archivo, ni su tipo) forma parte de la ruta, así que no hay recorrido de directorios posible.
// FILES_DIR debe estar FUERA de cualquier carpeta que sirva un servidor web. Permisos 0700/0600.

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const MB = 1024 * 1024;

const root = () => path.resolve(process.env.FILES_DIR || path.join(__dirname, '../../storage'));

const mbEnv = (name, fallbackMb) => {
    const n = Number(process.env[name]);
    return (Number.isFinite(n) && n > 0 ? n : fallbackMb) * MB;
};

// Límites (todos configurables por entorno)
function limits() {
    const perCategory = {
        image: mbEnv('UPLOAD_MAX_IMAGE_MB', 25),
        audio: mbEnv('UPLOAD_MAX_AUDIO_MB', 100),
        video: mbEnv('UPLOAD_MAX_VIDEO_MB', 512),
        document: mbEnv('UPLOAD_MAX_DOCUMENT_MB', 50),
        text: mbEnv('UPLOAD_MAX_TEXT_MB', 5)
    };
    return {
        perCategory,
        maxAny: Math.max(...Object.values(perCategory)),
        userQuotaBytes: mbEnv('UPLOAD_USER_QUOTA_MB', 1024),
        maxFilesPerUser: Number(process.env.UPLOAD_MAX_FILES_PER_USER) || 5000
    };
}

const newStorageName = () => crypto.randomUUID();

function assertName(name) {
    if (typeof name !== 'string' || !UUID.test(name)) throw new Error('Nombre de almacenamiento inválido');
    return name;
}

const tmpPath = (name) => path.join(root(), 'tmp', `${assertName(name)}.part`);
const finalPath = (name) => path.join(root(), 'files', assertName(name).slice(0, 2), `${name}.enc`);

function ensureDirs() {
    fs.mkdirSync(path.join(root(), 'tmp'), { recursive: true, mode: 0o700 });
    fs.mkdirSync(path.join(root(), 'files'), { recursive: true, mode: 0o700 });
}

function createTempWriteStream(name) {
    ensureDirs();
    // 'wx': falla si ya existe (nunca se sobrescribe nada); 0600: solo el propietario
    return fs.createWriteStream(tmpPath(name), { flags: 'wx', mode: 0o600 });
}

async function commit(name) {
    const target = finalPath(name);
    await fs.promises.mkdir(path.dirname(target), { recursive: true, mode: 0o700 });
    await fs.promises.rename(tmpPath(name), target);
}

const removeTemp = (name) => fs.promises.rm(tmpPath(name), { force: true });
const removeFinal = (name) => fs.promises.rm(finalPath(name), { force: true });

// Subidas que se quedaron a medias (caída del proceso, cliente que desapareció...)
async function purgeStaleTemp(maxAgeMs = 60 * 60 * 1000) {
    const dir = path.join(root(), 'tmp');
    let removed = 0;
    let entries;
    try {
        entries = await fs.promises.readdir(dir);
    } catch {
        return 0;
    }
    for (const entry of entries) {
        if (!entry.endsWith('.part')) continue;
        const file = path.join(dir, entry);
        try {
            if (Date.now() - (await fs.promises.stat(file)).mtimeMs > maxAgeMs) {
                await fs.promises.rm(file, { force: true });
                removed++;
            }
        } catch {
            // otro proceso lo borró a la vez
        }
    }
    return removed;
}

module.exports = {
    root, limits, newStorageName, tmpPath, finalPath, ensureDirs, createTempWriteStream,
    commit, removeTemp, removeFinal, purgeStaleTemp, UUID
};
