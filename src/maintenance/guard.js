const { Maintenance } = require('./maintenance');

// Guardián del servidor: decide si este proceso puede atender peticiones.
//
// Bloquea (503, falla cerrado) en dos casos:
//   1. MAINTENANCE     existe el lock de mantenimiento (archivo local) o la rotación tiene el lock de
//                      la BD (lo ven también otras máquinas que comparten la BD).
//   2. KEYS_OUT_OF_SYNC la huella de la clave que este proceso tiene en memoria no coincide con la
//                      de la base de datos (crypto_meta). Pasa tras una rotación si este proceso no
//                      ha cargado las claves nuevas: si atendiera peticiones escribiría datos
//                      cifrados con una clave que ya no es la vigente. Antes de bloquear intenta
//                      recargar las claves desde el .env.
//
// Se evalúa cada `intervalMs` (no por petición): el middleware solo lee dos booleanos.

class MaintenanceGuard {
    constructor({ maintenance = new Maintenance(), db = null, secureEnv = null, intervalMs = 5000, onChange = null } = {}) {
        this.maintenance = maintenance;
        this._db = db;
        this._secureEnv = secureEnv;
        this.intervalMs = intervalMs;
        this.onChange = onChange;
        this.state = { maintenance: this.maintenance.isLocked(), outOfSync: false, detail: null };
        this.timer = null;
    }

    get db() { return this._db || require('../config/database'); }
    get secureEnv() { return this._secureEnv || require('../config/secure-env'); }

    // ¿Puede este proceso escribir datos ahora? (para tareas en segundo plano)
    isOpen() {
        return !this.state.maintenance && !this.state.outOfSync;
    }

    middleware() {
        return (req, res, next) => {
            if (this.isOpen()) return next();

            res.setHeader('Retry-After', '300');
            res.status(503).json({
                success: false,
                message: this.state.maintenance
                    ? 'Servicio en mantenimiento. Inténtalo de nuevo en unos minutos.'
                    : 'Servicio no disponible temporalmente.',
                code: this.state.maintenance ? 'MAINTENANCE' : 'KEYS_OUT_OF_SYNC'
            });
        };
    }

    async fingerprintInDb() {
        try {
            const [rows] = await this.db.query('SELECT key_fingerprint FROM crypto_meta WHERE id = 1');
            return rows[0]?.key_fingerprint || null;
        } catch (error) {
            if (error.code === 'ER_NO_SUCH_TABLE') return null;
            throw error;
        }
    }

    async checkKeys() {
        const env = this.secureEnv;
        if (env.mode !== 'stable') return { outOfSync: false, detail: null }; // legacy: no hay marcador

        let dbFingerprint = await this.fingerprintInDb();

        if (dbFingerprint === null) {
            // Primera vez en modo estable: registrar la huella actual como referencia
            try {
                await this.db.query(
                    'INSERT IGNORE INTO crypto_meta (id, key_fingerprint, key_epoch) VALUES (1, ?, ?)',
                    [env.fingerprint, env.epoch]
                );
                dbFingerprint = await this.fingerprintInDb();
            } catch {
                return { outOfSync: false, detail: 'crypto_meta no disponible (aplica database/migrations/002_crypto_meta.sql)' };
            }
        }

        if (dbFingerprint === env.fingerprint) return { outOfSync: false, detail: null };

        // Las claves de la BD son otras: intentar cargar las del .env (rotación hecha por otro proceso)
        try {
            env.reload();
        } catch (error) {
            return { outOfSync: true, detail: `no se pudo recargar el .env: ${error.message}` };
        }

        return dbFingerprint === env.fingerprint
            ? { outOfSync: false, detail: null }
            : { outOfSync: true, detail: 'las claves en el entorno no coinciden con las de la base de datos; actualiza las variables y reinicia' };
    }

    // El lock de la BD (GET_LOCK) lo mantiene la rotación durante toda su ejecución. A diferencia
    // del archivo de lock (local a UNA máquina), lo ven TODAS las instancias que comparten la BD:
    // sin esto, una segunda máquina seguiría escribiendo con la clave antigua mientras se rota.
    async rotationHeldInDatabase() {
        try {
            const [rows] = await this.db.query("SELECT IS_USED_LOCK('secure_server_rotation') AS holder");
            return rows[0]?.holder !== null && rows[0]?.holder !== undefined;
        } catch {
            return false; // sin BD no se puede saber; se conserva la señal del archivo
        }
    }

    async tick() {
        const previous = { ...this.state };

        const locked = this.maintenance.isLocked() || await this.rotationHeldInDatabase();
        let outOfSync = this.state.outOfSync;
        let detail = this.state.detail;

        // Mientras haya lock no se evalúan las claves: la migración está cambiándolas
        if (!locked) {
            try {
                ({ outOfSync, detail } = await this.checkKeys());
            } catch (error) {
                // Sin BD no se puede comparar: se conserva el último estado conocido
                detail = `no se pudo comprobar la huella de claves: ${error.message}`;
            }
        }

        this.state = { maintenance: locked, outOfSync, detail };

        if (this.onChange && (previous.maintenance !== locked || previous.outOfSync !== outOfSync)) {
            this.onChange(this.state, previous);
        }
        return this.state;
    }

    async start() {
        await this.tick();
        this.timer = setInterval(() => this.tick().catch(() => {}), this.intervalMs);
        this.timer.unref();
        return this.state;
    }

    stop() {
        if (this.timer) clearInterval(this.timer);
        this.timer = null;
    }
}

module.exports = { MaintenanceGuard };
