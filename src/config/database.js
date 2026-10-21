const mysql = require('mysql2/promise');
const credentialBuilder = require('./credential-builder');
const capacity = require('./capacity');

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

    initializePool() {
        try {
            // Validar credenciales antes de conectar
            credentialBuilder.validateCredentials();

            // Construir URL de conexión de forma segura
            const databaseURL = credentialBuilder.buildDatabaseURL();

            // Extraer NODE_ENV con chequeo
            const nodeEnv = this.getEnvVariable('NODE_ENV');

            // Configuración SSL más robusta
            let sslConfig = false;
            
            if (nodeEnv === 'production') {
                // En producción, intentar SSL pero permitir fallar a no-SSL
                sslConfig = {
                    rejectUnauthorized: false,
                    // Permitir conexiones no seguras como fallback
                    require: false
                };
            }

            // El tamaño del pool sale del presupuesto de capacidad (media máquina),
            // configurable con DB_POOL_SIZE.
            const connectionLimit = parseInt(process.env.DB_POOL_SIZE, 10) || capacity.dbPool;

            this.pool = mysql.createPool({
                uri: databaseURL,
                waitForConnections: true,
                connectionLimit,
                queueLimit: 0,
                // Remover configuraciones no válidas que causan warnings
                ssl: sslConfig,
                charset: 'utf8mb4',
                // Configuraciones de timeout válidas
                connectTimeout: 60000,
            });

            console.log(`🗄️ Pool de conexiones MySQL inicializado de forma segura (límite: ${connectionLimit})`);
        } catch (error) {
            console.error('❌ Error inicializando pool de base de datos:', error);
            throw error;
        }
    }

    async getConnection() {
        try {
            return await this.pool.getConnection();
        } catch (error) {
            console.error('❌ Error al obtener conexión:', error);
            throw error;
        }
    }

    async query(sql, params = []) {
        let connection;
        try {
            connection = await this.getConnection();
            const [results] = await connection.execute(sql, params);
            return [results]; // Mantener formato consistente
        } catch (error) {
            console.error('❌ Error en consulta SQL:', error);
            throw error;
        } finally {
            if (connection) connection.release();
        }
    }

    async testConnection() {
        let connection;
        try {
            // Intentar conexión con SSL primero, luego sin SSL
            connection = await this.pool.getConnection();
            await connection.execute('SELECT 1 as test');
            console.log('✅ Conexión a base de datos exitosa');
            return true;
        } catch (error) {
            // Si es error de SSL, intentar recrear pool sin SSL
            if (error.code === 'HANDSHAKE_NO_SSL_SUPPORT') {
                console.log('ℹ️ SSL no soportado, reconfigurar para conexión no segura...');
                return await this.recreatePoolWithoutSSL();
            }
            
            console.error('❌ Error de conexión a base de datos:', error);
            return false;
        } finally {
            if (connection) connection.release();
        }
    }

    async recreatePoolWithoutSSL() {
        try {
            // Cerrar pool actual
            if (this.pool) {
                await this.pool.end();
            }

            // Reconstruir URL de conexión
            const databaseURL = credentialBuilder.buildDatabaseURL();

            // Crear nuevo pool sin SSL
            this.pool = mysql.createPool({
                uri: databaseURL,
                waitForConnections: true,
                connectionLimit: parseInt(process.env.DB_POOL_SIZE, 10) || capacity.dbPool,
                queueLimit: 0,
                ssl: false, // Explícitamente deshabilitado
                charset: 'utf8mb4',
                connectTimeout: 60000
            });

            // Probar nueva conexión
            const connection = await this.pool.getConnection();
            await connection.execute('SELECT 1 as test');
            connection.release();

            console.log('✅ Conexión reconfigurada sin SSL exitosamente');
            return true;

        } catch (error) {
            console.error('❌ Error reconfigurando conexión:', error);
            return false;
        }
    }

    async secureQuery(sql, params = [], userId = null) {
        const startTime = Date.now();

        try {
            const result = await this.query(sql, params);

            // Log de consulta exitosa
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
                error: error.message
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
            console.error('❌ Error logging database access:', error);
        }
    }
}

module.exports = new DatabaseConfig();