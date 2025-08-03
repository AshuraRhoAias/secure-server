const mysql = require('mysql2/promise');
const credentialBuilder = require('./credential-builder');

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
            console.log(`✅ Variable de entorno encontrada: ${key} = ${value}`);
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

            this.pool = mysql.createPool({
                uri: databaseURL,
                waitForConnections: true,
                connectionLimit: 10,
                queueLimit: 0,
                acquireTimeout: 60000,
                timeout: 60000,
                ssl: nodeEnv === 'production' ? { rejectUnauthorized: false } : false,
                charset: 'utf8mb4'
            });

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
            console.error('❌ Error al obtener conexión:', error);
            throw error;
        }
    }

    async query(sql, params = []) {
        const connection = await this.getConnection();
        try {
            const [results] = await connection.execute(sql, params);
            return results;
        } catch (error) {
            console.error('❌ Error en consulta SQL:', error);
            throw error;
        } finally {
            connection.release();
        }
    }

    async testConnection() {
        try {
            const [rows] = await this.pool.execute('SELECT 1 as test');
            console.log('✅ Conexión a base de datos exitosa');
            return true;
        } catch (error) {
            console.error('❌ Error de conexión a base de datos:', error);
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
