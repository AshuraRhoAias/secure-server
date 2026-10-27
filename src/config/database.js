const fs = require('fs');
const mysql = require('mysql2/promise');
const credentialBuilder = require('./credential-builder');
const metrics = require('../observability/metrics');
const tracing = require('../observability/tracing');

// Configuración TLS hacia la base de datos (variable DB_SSL):
//   verify     TLS y se VERIFICA el certificado del servidor (por defecto en producción)
//   no-verify  TLS sin verificar el certificado (vulnerable a un intermediario: solo si no hay otra opción)
//   off        sin TLS (por defecto fuera de producción; en producción se avisa en voz alta)
// DB_SSL_CA: ruta a un PEM, o el PEM en sí, de la CA que firmó el certificado del servidor.
function buildSslConfig(nodeEnv) {
    const mode = (process.env.DB_SSL || (nodeEnv === 'production' ? 'verify' : 'off')).toLowerCase();

    if (['off', 'false', '0'].includes(mode)) {
        if (nodeEnv === 'production') {
            console.error('⚠️ DB_SSL=off en producción: la conexión a la base de datos NO está cifrada');
        }
        return false;
    }

    const ssl = { rejectUnauthorized: mode !== 'no-verify' };
    if (!ssl.rejectUnauthorized) {
        console.error('⚠️ DB_SSL=no-verify: no se verifica el certificado de la base de datos (riesgo de intermediario)');
    }

    const ca = process.env.DB_SSL_CA;
    if (ca) ssl.ca = ca.includes('BEGIN CERTIFICATE') ? ca : fs.readFileSync(ca);
    return ssl;
}

const intFromEnv = (name, fallback) => {
    const n = Number(process.env[name]);
    return Number.isInteger(n) && n > 0 ? n : fallback;
};

class DatabaseConfig {
    constructor() {
        this.pool = null;
        this.initializePool();
    }

    getEnvVariable(key) {
        const value = process.env[key];
        if (!value) {
            console.error(`❌ Variable de entorno faltante o vacía: ${key}`);
        } else {
            console.log(`✅ Variable de entorno encontrada: ${key} (${value.length} caracteres)`);
        }
        return value || null;
    }

    poolOptions(ssl) {
        return {
            uri: credentialBuilder.buildDatabaseURL(),
            waitForConnections: true,
            connectionLimit: intFromEnv('DB_POOL_SIZE', 10),
            // Cola acotada: bajo una avalancha se rechaza en vez de acumular peticiones sin límite
            queueLimit: intFromEnv('DB_QUEUE_LIMIT', 500),
            ssl,
            charset: 'utf8mb4',
            connectTimeout: 10000,
            enableKeepAlive: true,
            // Una sentencia por llamada: apila `; DROP TABLE ...` es imposible a nivel de driver
            multipleStatements: false
        };
    }

    initializePool() {
        try {
            credentialBuilder.validateCredentials();
            const nodeEnv = this.getEnvVariable('NODE_ENV');
            this.pool = mysql.createPool(this.poolOptions(buildSslConfig(nodeEnv)));
            console.log('🗄️ Pool de conexiones MySQL inicializado de forma segura');
        } catch (error) {
            console.error('❌ Error inicializando pool de base de datos:', error);
            throw error;
        }
    }

    async getConnection() {
        try {
            return await this.pool.getConnection();
        } catch (error) {
            console.error('❌ Error al obtener conexión:', error.message);
            throw error;
        }
    }

    // Todas las consultas van como sentencias PREPARADAS (`execute`): los valores viajan aparte
    // del SQL, así que nada de lo que envíe un usuario puede cambiar la consulta.
    async query(sql, params = []) {
        let connection;
        try {
            connection = await this.getConnection();
            const [results] = await this.measured(sql, () => connection.execute(sql, params));
            return [results];
        } catch (error) {
            // Se registra el código, no el SQL ni los parámetros (pueden contener datos sensibles)
            console.error(`❌ Error en consulta SQL: ${error.code || error.message}`);
            throw error;
        } finally {
            if (connection) connection.release();
        }
    }

    // Duración y errores por operación (select/insert/...) y un span si la traza está muestreada. Nunca se guarda el
    // texto SQL ni los parámetros: solo la operación, de una lista cerrada.
    async measured(sql, run) {
        const operation = metrics.sqlOperation(sql);
        const end = metrics.dbDuration.startTimer({ operation });
        try {
            return await tracing.withSpan('db.query', { 'db.system': 'mysql', 'db.operation': operation }, run);
        } catch (error) {
            metrics.dbErrors.inc({ operation });
            throw error;
        } finally {
            end();
        }
    }

    // Varias sentencias sobre UNA misma conexión (p. ej. contador atómico + lectura)
    async withConnection(fn) {
        const connection = await this.getConnection();
        try {
            return await fn({ query: async (sql, params = []) => [(await this.measured(sql, () => connection.execute(sql, params)))[0]] });
        } finally {
            connection.release();
        }
    }

    // Transacción: fn recibe { query }; COMMIT si termina, ROLLBACK si lanza
    async transaction(fn) {
        const connection = await this.getConnection();
        try {
            await connection.beginTransaction();
            const result = await fn({ query: async (sql, params = []) => [(await this.measured(sql, () => connection.execute(sql, params)))[0]] });
            await connection.commit();
            return result;
        } catch (error) {
            await connection.rollback().catch(() => {});
            throw error;
        } finally {
            connection.release();
        }
    }

    // Cierra el pool (cierre ordenado: las consultas en curso terminan)
    async close() {
        if (this.pool) {
            const pool = this.pool;
            this.pool = null;
            await pool.end();
        }
    }

    async testConnection() {
        let connection;
        try {
            connection = await this.pool.getConnection();
            await connection.execute('SELECT 1 as test');
            console.log('✅ Conexión a base de datos exitosa');
            return true;
        } catch (error) {
            if (error.code === 'HANDSHAKE_NO_SSL_SUPPORT') {
                // Antes se degradaba en silencio a una conexión sin cifrar. Ahora hay que decidirlo explícitamente.
                console.error('❌ El servidor de base de datos no admite TLS. Habilítalo, o fija DB_SSL=off de forma explícita si aceptas el riesgo.');
                return false;
            }

            console.error('❌ Error de conexión a base de datos:', error.code || error.message);
            return false;
        } finally {
            if (connection) connection.release();
        }
    }

    async secureQuery(sql, params = [], userId = null) {
        const startTime = Date.now();

        try {
            const result = await this.query(sql, params);

            await this.logDatabaseAccess({
                type: 'QUERY_SUCCESS',
                userId,
                duration: Date.now() - startTime,
                affectedRows: result.affectedRows || result.length
            });

            return result;
        } catch (error) {
            await this.logDatabaseAccess({
                type: 'QUERY_FAILED',
                userId,
                duration: Date.now() - startTime,
                error: error.code || 'ERROR'
            });

            throw error;
        }
    }

    async logDatabaseAccess(details) {
        try {
            const tripleEncryptor = require('../crypto/tripleEncryptor');
            const encryptedDetails = tripleEncryptor.encrypt(JSON.stringify(details));

            await this.query(
                `INSERT INTO security_logs (event_type, encrypted_details, ip_address, severity)
                 VALUES (?, ?, 'DATABASE', 'low')`,
                [details.type, encryptedDetails]
            );
        } catch (error) {
            console.error('❌ Error logging database access:', error.message);
        }
    }
}

module.exports = new DatabaseConfig();
