// Ajustes operativos cambiables EN CALIENTE desde la interfaz web (FASE 2), guardados en la tabla runtime_settings.
//
// Reglas de diseño:
//  - CATÁLOGO CERRADO: solo las claves de DEFINITIONS. Cualquier otra se rechaza (400). Aquí NO entra ningún secreto,
//    clave, TLS, CORS ni DISABLE_IP_BLOCKING (el invariante "nunca actúa en producción" no se toca desde la web).
//  - Sin fila en la BD el valor es el del entorno (.env) o el defecto de siempre: el comportamiento NO cambia hasta que un
//    administrador guarda un ajuste. El valor de entorno se interpreta con la misma regla laxa que usaba cada consumidor.
//  - `get(clave)` es SÍNCRONO (los consumidores lo leen en el momento de uso, no al cargar el módulo) y lee una caché en
//    memoria. Tras start(), una lectura con la caché más vieja que SETTINGS_CACHE_TTL_MS (5 s) lanza un refresco en segundo
//    plano: las réplicas del cluster convergen sin reiniciar. Escribir actualiza la caché local al instante.
//  - Un ajuste que REDUCE la seguridad (weakens) no se aplica solo: lo decide la doble firma (acción settings_change).

// La BD se carga al usarla: storage.limits() y otros consumidores importan este módulo en contextos sin BD ni secretos
// (p. ej. test_s3.js); sin filas, get() devuelve el valor del entorno igual que antes.
const db = { query: (...args) => require('./database').query(...args) };

class SettingsError extends Error {
    constructor(code, message, status = 400) {
        super(message);
        this.code = code;
        this.status = status;
    }
}

// ¿subir el valor reduce la seguridad? (límites de tasa, tamaños) / ¿bajarlo? (umbral de severidad inverso, tope de eventos)
const weakerWhenHigher = (oldV, newV) => newV > oldV;
const weakerWhenLower = (oldV, newV) => newV < oldV;

const SEVERITY_ORDER = ['low', 'medium', 'high', 'critical'];

const DEFINITIONS = [
    {
        key: 'auth.mfa_required_privileged', group: 'Autenticación', label: 'Segundo factor obligatorio para roles con privilegios',
        description: 'Con esta opción activa, auditor, operador y administrador solo operan si iniciaron sesión con segundo factor o SSO.',
        type: 'bool', envVar: 'MFA_REQUIRED_FOR_ADMINS', default: false, unit: null,
        weakens: (oldV, newV) => oldV === true && newV === false
    },
    {
        key: 'files.image_sanitize', group: 'Archivos', label: 'Saneado de imágenes al subirlas',
        description: 'on = se recodifican y pierden EXIF y datos ocultos; off = se aceptan tal cual.',
        type: 'enum', values: ['on', 'off'], envVar: 'IMAGE_SANITIZE', default: 'on', unit: null,
        weakens: (oldV, newV) => oldV === 'on' && newV === 'off'
    },
    {
        key: 'files.pdf_active_content', group: 'Archivos', label: 'PDF con contenido activo',
        description: 'reject = se rechazan los PDF con JavaScript, adjuntos o formularios; allow = se aceptan.',
        type: 'enum', values: ['reject', 'allow'], envVar: 'PDF_ACTIVE_CONTENT', default: 'reject', unit: null,
        weakens: (oldV, newV) => oldV === 'reject' && newV === 'allow'
    },
    {
        key: 'files.upload_max_image_mb', group: 'Archivos', label: 'Tamaño máximo de una imagen',
        description: 'Las subidas de imágenes por encima de este tamaño se rechazan.',
        type: 'int', min: 1, max: 200, envVar: 'UPLOAD_MAX_IMAGE_MB', default: 25, unit: 'MB',
        weakens: weakerWhenHigher
    },
    {
        key: 'files.upload_rate_per_min', group: 'Límites de uso', label: 'Subidas por minuto y usuario',
        description: 'Más subidas en un minuto reciben 429.',
        type: 'int', min: 1, max: 10000, envVar: 'UPLOAD_RATE_PER_MIN', default: 20, unit: 'por minuto',
        weakens: weakerWhenHigher
    },
    {
        key: 'files.download_rate_per_min', group: 'Límites de uso', label: 'Descargas por minuto y usuario',
        description: 'Más descargas en un minuto reciben 429.',
        type: 'int', min: 1, max: 100000, envVar: 'DOWNLOAD_RATE_PER_MIN', default: 600, unit: 'por minuto',
        weakens: weakerWhenHigher
    },
    {
        key: 'security.events_max_per_minute', group: 'Auditoría y alertas', label: 'Tope de eventos de seguridad por minuto y origen',
        description: 'Pasado el tope se dejan de registrar eventos repetidos (queda uno de aviso). Bajarlo reduce la trazabilidad.',
        type: 'int', min: 5, max: 10000, envVar: 'SECURITY_EVENTS_MAX_PER_MINUTE', default: 30, unit: 'eventos/min',
        weakens: weakerWhenLower
    },
    {
        key: 'alerts.notify_min_severity', group: 'Auditoría y alertas', label: 'Severidad mínima para avisar por webhook',
        description: 'Las alertas por debajo de este nivel no se envían al webhook (siguen en el panel). Subirlo reduce los avisos.',
        type: 'enum', values: SEVERITY_ORDER, envVar: 'ALERT_NOTIFY_MIN_SEVERITY', default: 'high', unit: null,
        weakens: (oldV, newV) => SEVERITY_ORDER.indexOf(newV) > SEVERITY_ORDER.indexOf(oldV)
    }
];

const BY_KEY = new Map(DEFINITIONS.map(def => [def.key, def]));
const KEY_PATTERN = /^[a-z][a-z0-9_.]{0,63}$/;

const definition = (key) => (typeof key === 'string' && KEY_PATTERN.test(key) ? BY_KEY.get(key) : undefined) || null;

function requireDefinition(key) {
    const def = definition(key);
    if (!def) throw new SettingsError('UNKNOWN_SETTING', 'Ajuste desconocido: solo se pueden cambiar los del catálogo', 400);
    return def;
}

// Valida y normaliza (estricto: lo que llega de la web debe ser del tipo exacto). Lanza SettingsError 400.
function validate(key, value) {
    const def = requireDefinition(key);
    if (def.type === 'bool') {
        if (typeof value !== 'boolean') throw new SettingsError('INVALID_VALUE', `${def.label}: debe ser verdadero o falso`);
        return value;
    }
    if (def.type === 'int') {
        if (typeof value !== 'number' || !Number.isSafeInteger(value)) throw new SettingsError('INVALID_VALUE', `${def.label}: debe ser un número entero`);
        if (value < def.min || value > def.max) throw new SettingsError('OUT_OF_RANGE', `${def.label}: debe estar entre ${def.min} y ${def.max}`);
        return value;
    }
    if (typeof value !== 'string' || !def.values.includes(value)) {
        throw new SettingsError('INVALID_VALUE', `${def.label}: debe ser uno de ${def.values.join(', ')}`);
    }
    return value;
}

// Valor del entorno con la MISMA regla laxa que usaba cada consumidor (sin recortar por rango): igual que antes.
function envValue(key) {
    const def = requireDefinition(key);
    const raw = process.env[def.envVar];
    if (raw === undefined || raw === '') return { value: def.default, source: 'default' };
    if (def.type === 'bool') {
        if (raw === 'true') return { value: true, source: 'env' };
        if (raw === 'false') return { value: false, source: 'env' };
    } else if (def.type === 'int') {
        const n = Number(raw);
        if (Number.isFinite(n) && n > 0) return { value: n, source: 'env' };
    } else if (def.values.includes(raw)) {
        return { value: raw, source: 'env' };
    }
    return { value: def.default, source: 'default' };
}

const isWeakening = (key, oldValue, newValue) => Boolean(requireDefinition(key).weakens(oldValue, newValue));

// ------------------------------------------------------------------ caché

const ttlMs = () => {
    const n = Number(process.env.SETTINGS_CACHE_TTL_MS);
    return Number.isFinite(n) && n >= 0 ? n : 5000;
};

let cache = new Map();   // key -> { value, updatedBy, updatedAt }
let loadedAt = 0;
let started = false;
let refreshing = null;
let generation = 0;       // sube en cada escritura local: un refresco que empezó antes no pisa la caché

const reportedCorrupt = new Set();
function reportCorruptRow(row) {
    const id = `${row.setting_key}:${row.value_json}`;
    if (reportedCorrupt.has(id)) return;
    reportedCorrupt.add(id);
    try {
        void require('../security/security-events.service').record({
            type: 'SETTING_INVALID_IN_DB', severity: 'high', riskScore: 40,
            details: { key: row.setting_key, note: 'valor de runtime_settings ilegible o fuera de rango: se usa el del entorno' }
        }).catch(() => {});
    } catch { /* sin servicio de eventos (contexto sin BD) */ }
}

function parseRow(row) {
    const def = definition(row.setting_key);
    if (!def) return null;
    try {
        return { value: validate(def.key, JSON.parse(row.value_json)), updatedBy: row.updated_by ?? null, updatedAt: row.updated_at ?? null };
    } catch {
        // Fila corrupta o fuera de rango: vale el entorno, pero NO en silencio (podría ser más débil que lo guardado)
        reportCorruptRow(row);
        return null;
    }
}

async function refresh() {
    const startGeneration = generation;
    const [rows] = await db.query('SELECT setting_key, value_json, updated_by, updated_at FROM runtime_settings');
    if (startGeneration !== generation) { loadedAt = 0; return false; }
    const next = new Map();
    for (const row of rows) {
        const parsed = parseRow(row);
        if (parsed) next.set(row.setting_key, parsed);
    }
    cache = next;
    loadedAt = Date.now();
    return true;
}

function refreshInBackground() {
    if (refreshing) return;
    refreshing = refresh()
        .catch(() => { loadedAt = Date.now(); /* sin BD o sin la tabla: se conserva lo que hay y se reintenta pasado el TTL */ })
        .finally(() => { refreshing = null; });
}

// Valor efectivo. Síncrono; lee la caché y, pasado el TTL, la renueva en segundo plano (solo tras start()).
function get(key) {
    const def = requireDefinition(key);
    if (started && Date.now() - loadedAt >= ttlMs()) refreshInBackground();
    const hit = cache.get(def.key);
    return hit ? hit.value : envValue(def.key).value;
}

function source(key) {
    requireDefinition(key);
    return cache.has(key) ? 'db' : envValue(key).source;
}

// Activa la lectura periódica de la BD (se llama al arrancar el servidor, con la BD ya conectada).
async function start() {
    started = true;
    try { await refresh(); } catch { /* se reintenta con la primera lectura pasado el TTL */ }
}

function stop() {
    started = false;
    cache = new Map();
    loadedAt = 0;
    generation++;
}

// Invalida la caché local: la próxima lectura vuelve a consultar la BD.
function invalidate() {
    loadedAt = 0;
    generation++;
}

// Valor efectivo leído AHORA de la BD (sin caché): para decidir si un cambio debilita frente al valor real, no frente a
// una caché de hasta TTL de antigüedad en esta réplica.
async function getFresh(key) {
    const def = requireDefinition(key);
    const [rows] = await db.query('SELECT setting_key, value_json, updated_by, updated_at FROM runtime_settings WHERE setting_key = ?', [def.key]);
    const parsed = rows[0] ? parseRow(rows[0]) : null;
    return parsed ? { value: parsed.value, source: 'db' } : envValue(def.key);
}

// ------------------------------------------------------------------ escritura

async function set(key, value, { actor = null } = {}) {
    const def = requireDefinition(key);
    const clean = validate(def.key, value);
    const previous = get(def.key);
    await db.query(
        `INSERT INTO runtime_settings (setting_key, value_json, updated_by) VALUES (?, ?, ?)
         ON DUPLICATE KEY UPDATE value_json = VALUES(value_json), updated_by = VALUES(updated_by)`,
        [def.key, JSON.stringify(clean), actor]
    );
    generation++;
    cache.set(def.key, { value: clean, updatedBy: actor, updatedAt: new Date() });
    return { key: def.key, previous, current: clean, source: 'db' };
}

// Vuelve al valor del entorno (o al defecto): borra la fila.
async function reset(key, { actor = null } = {}) {
    const def = requireDefinition(key);
    const previous = get(def.key);
    await db.query('DELETE FROM runtime_settings WHERE setting_key = ?', [def.key]);
    generation++;
    cache.delete(def.key);
    const fallback = envValue(def.key);
    return { key: def.key, previous, current: fallback.value, source: fallback.source, actor };
}

// ------------------------------------------------------------------ lectura para la API

const publicDefinition = (def) => ({
    key: def.key, label: def.label, description: def.description, group: def.group, type: def.type, unit: def.unit,
    ...(def.type === 'int' ? { min: def.min, max: def.max } : {}),
    ...(def.type === 'enum' ? { values: def.values } : {}),
    default: def.default
});

// Catálogo agrupado con el valor efectivo, su origen y quién/cuándo lo cambió. Lee la BD (no la caché) y la renueva.
async function describe() {
    const tripleEncryptor = require('../crypto/tripleEncryptor');
    const startGeneration = generation;
    const [rows] = await db.query(
        `SELECT s.setting_key, s.value_json, s.updated_by, s.updated_at, u.username_encrypted
         FROM runtime_settings s LEFT JOIN users u ON u.id = s.updated_by`
    );
    const fromDb = new Map();
    for (const row of rows) {
        const parsed = parseRow(row);
        if (!parsed) continue;
        let name = null;
        try { name = row.username_encrypted ? tripleEncryptor.decrypt(row.username_encrypted) : null; } catch { name = null; }
        fromDb.set(row.setting_key, { ...parsed, updatedByName: name });
    }
    if (startGeneration === generation) { // refresca la caché local con lo recién leído
        const next = new Map();
        for (const [key, entry] of fromDb) next.set(key, { value: entry.value, updatedBy: entry.updatedBy, updatedAt: entry.updatedAt });
        cache = next;
        loadedAt = Date.now();
    }

    const groups = [];
    for (const def of DEFINITIONS) {
        let group = groups.find(g => g.group === def.group);
        if (!group) { group = { group: def.group, settings: [] }; groups.push(group); }
        const stored = fromDb.get(def.key);
        const env = envValue(def.key);
        group.settings.push({
            ...publicDefinition(def),
            value: stored ? stored.value : env.value,
            source: stored ? 'db' : env.source,
            envValue: env.value,
            updatedBy: stored ? { id: stored.updatedBy, username: stored.updatedByName } : null,
            updatedAt: stored ? stored.updatedAt : null
        });
    }
    return groups;
}

module.exports = {
    SettingsError, DEFINITIONS, definition, validate, envValue, isWeakening, get, getFresh, source, start, stop, refresh, invalidate,
    set, reset, describe
};
