// Elección de LÍDER para las tareas periódicas (limpieza, alertas, rotación programada).
//
// Con varias instancias o procesos (cluster, varias máquinas) cada uno ejecutaría las mismas tareas: N evaluadores de alertas, N
// limpiezas, N planificadores de rotación. Aquí solo las ejecuta UNO. La elección usa un cerrojo de MariaDB (GET_LOCK) retenido en una
// conexión dedicada:
//   - es atómico y vale entre máquinas (todas hablan con la misma BD);
//   - si el líder muere (o pierde la conexión), el servidor libera el cerrojo solo y otro instancia toma el relevo en ≤ LEADER_RETRY_SECONDS;
//   - no hay reloj ni caducidad que ajustar: la propiedad es la conexión.
// Si se pierde la conexión el líder se retira ANTES de que otro pueda tomar el cerrojo (detecta el fallo con un ping y para sus tareas).
//
// Las tareas deben ser idempotentes (lo son: borrados por antigüedad, alertas con clave única, etc.), así que un solapamiento breve
// durante un relevo no es un problema. LEADER_ELECTION=false las ejecuta en todas las instancias (comportamiento anterior).

const db = require('../config/database');

const LOCK_NAME = 'secure-server:leader';
const seconds = (name, fallback) => {
    const n = Number(process.env[name]);
    return (Number.isFinite(n) && n > 0 ? n : fallback) * 1000;
};

class LeaderElection {
    constructor() {
        this.tasks = [];
        this.conn = null;
        this.leader = false;
        this.timer = null;
        this.stopped = true;
        this.ticking = false;
        this.listeners = [];
    }

    isLeader() { return this.leader; }
    onChange(fn) { this.listeners.push(fn); }

    // tasks: [{ name, start(), stop() }]
    async start(tasks) {
        this.tasks = tasks;
        this.stopped = false;
        if (process.env.LEADER_ELECTION === 'false') {
            await this.becomeLeader();
            return;
        }
        await this.tick();
        const period = Math.min(seconds('LEADER_RETRY_SECONDS', 10), seconds('LEADER_PING_SECONDS', 5));
        this.timer = setInterval(() => { this.tick().catch(() => {}); }, period);
        this.timer.unref();
    }

    async tick() {
        if (this.stopped || this.ticking) return;
        this.ticking = true;
        try {
            if (this.leader) await this.check();
            else await this.tryAcquire();
        } finally {
            this.ticking = false;
        }
    }

    async tryAcquire() {
        let conn;
        try {
            conn = await db.pool.getConnection();
            const [[row]] = await conn.query('SELECT GET_LOCK(?, 0) AS got', [LOCK_NAME]);
            if (Number(row.got) === 1) {
                this.conn = conn; // la conexión se queda con el cerrojo: NO se devuelve al pool
                // Una conexión retenida durante horas SE CAERÁ alguna vez (reinicio de la BD, red, KILL): sin un listener de 'error' sería
                // una excepción no capturada que tumba el proceso. Aquí solo se anota; el siguiente ping retira el liderazgo.
                conn.on('error', (error) => console.error('⚠️ Conexión del líder:', error.code || error.message));
                await this.becomeLeader();
                return;
            }
        } catch (error) {
            console.error('⚠️ Elección de líder:', error.code || error.message);
        }
        if (conn && conn !== this.conn) conn.release();
    }

    // El líder comprueba que SIGUE siendo el dueño del cerrojo; si no, se retira y para sus tareas
    async check() {
        try {
            const [[row]] = await this.conn.query('SELECT IS_USED_LOCK(?) = CONNECTION_ID() AS mine', [LOCK_NAME]);
            if (Number(row.mine) === 1) return;
            console.error('⚠️ Se perdió el cerrojo de líder: se detienen las tareas periódicas');
        } catch (error) {
            console.error('⚠️ Se perdió la conexión del líder:', error.code || error.message);
        }
        await this.stepDown({ destroy: true });
    }

    async becomeLeader() {
        this.leader = true;
        console.log('👑 Esta instancia es la LÍDER: ejecuta las tareas periódicas');
        for (const task of this.tasks) {
            try { await task.start(); } catch (error) { console.error(`❌ No se pudo iniciar la tarea ${task.name}:`, error.message); }
        }
        this.listeners.forEach(fn => fn(true));
    }

    async stepDown({ destroy = false } = {}) {
        const wasLeader = this.leader;
        this.leader = false;
        for (const task of [...this.tasks].reverse()) {
            try { await task.stop(); } catch (error) { console.error(`❌ No se pudo parar la tarea ${task.name}:`, error.message); }
        }
        if (this.conn) {
            const conn = this.conn;
            this.conn = null;
            if (destroy) conn.destroy(); // el servidor libera el cerrojo al cerrarse la conexión
            else {
                await conn.query('SELECT RELEASE_LOCK(?)', [LOCK_NAME]).catch(() => {});
                conn.release();
            }
        }
        if (wasLeader) this.listeners.forEach(fn => fn(false));
    }

    async stop() {
        this.stopped = true;
        if (this.timer) clearInterval(this.timer);
        this.timer = null;
        await this.stepDown();
    }
}

module.exports = new LeaderElection();
module.exports.LeaderElection = LeaderElection;
module.exports.LOCK_NAME = LOCK_NAME;
