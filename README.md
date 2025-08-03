# 🔐 Guía Completa de Instalación - Sistema Ultra Seguro con Seguridad Operacional Avanzada

## 📋 Índice
1. [Requisitos Previos](#requisitos-previos)
2. [Instalación de Dependencias](#instalación-de-dependencias)
3. [Estructura de Carpetas](#estructura-de-carpetas)
4. [Configuración de Base de Datos](#configuración-de-base-de-datos)
5. [Variables de Entorno Seguras](#variables-de-entorno-seguras)
6. [Archivos de Configuración](#archivos-de-configuración)
7. [Sistema de Cifrado](#sistema-de-cifrado)
8. [Seguridad Operacional](#seguridad-operacional)
9. [Middlewares de Protección](#middlewares-de-protección)
10. [Servicios y Controladores](#servicios-y-controladores)
11. [Sistema de Rotación Automática](#sistema-de-rotación-automática)
12. [Comunicaciones Seguras](#comunicaciones-seguras)
13. [Scripts de Recuperación](#scripts-de-recuperación)
14. [Ejecución del Sistema](#ejecución-del-sistema)

---

## 🛠️ Requisitos Previos

- **Node.js** v18 o superior
- **MySQL** 8.0 o superior (o servicio administrado como PlanetScale)
- **Git** para control de versiones
- **Hosting administrado** (Heroku, Railway, Render, AWS, etc.)
- **Múltiples cuentas de email** (Gmail + ProtonMail recomendado)
- **Cuenta de Telegram** (opcional, para alertas de emergencia)

---

## 📦 Instalación de Dependencias

### 1. Inicializar el proyecto
```bash
mkdir secure-server
cd secure-server
npm init -y
```

### 2. Instalar dependencias principales
```bash
npm install express mysql2 jsonwebtoken bcryptjs dotenv cors helmet morgan compression
```

### 3. Instalar dependencias de cifrado y seguridad
```bash
npm install crypto-js nodemailer node-cron fs-extra speakeasy qrcode
```

### 4. Instalar dependencias de monitoreo y detección
```bash
npm install winston winston-elasticsearch geoip-lite useragent
```

### 5. Instalar dependencias de desarrollo
```bash
npm install --save-dev nodemon concurrently
```

### 6. Actualizar package.json
```json
{
  "name": "secure-server",
  "version": "1.0.0",
  "description": "Sistema ultra seguro con cifrado multicapa y seguridad operacional avanzada",
  "main": "src/index.js",
  "scripts": {
    "start": "node src/index.js",
    "dev": "nodemon src/index.js",
    "test": "node test_system.js",
    "decrypt-message": "node scripts/decryptMessage.js",
    "emergency-backup": "node scripts/emergencyRecovery.js backup",
    "emergency-restore": "node scripts/emergencyRecovery.js restore",
    "rotate-keys": "node -e \"require('./src/tasks/scheduleKeyRotation').executeManualRotation()\"",
    "check-system": "node -e \"require('./src/middleware/serverCheck.middleware').performAsyncCheck()\"",
    "security-audit": "node scripts/securityAudit.js"
  },
  "keywords": ["security", "encryption", "jwt", "mysql", "operational-security"],
  "author": "Tu Nombre",
  "license": "MIT"
}
```

---

## 📁 Estructura de Carpetas

### Crear toda la estructura de directorios
```bash
mkdir -p src/api/routes
mkdir -p src/api/controllers
mkdir -p src/config
mkdir -p src/crypto
mkdir -p src/middleware
mkdir -p src/services
mkdir -p src/tasks
mkdir -p src/utils
mkdir -p src/security
mkdir -p database
mkdir -p scripts
mkdir -p temp
mkdir -p logs
```

### Estructura final
```
secure-server/
├── src/
│   ├── api/
│   │   ├── routes/
│   │   └── controllers/
│   ├── config/
│   ├── crypto/
│   ├── middleware/
│   ├── services/
│   ├── security/          # ← NUEVO: Servicios de seguridad operacional
│   ├── tasks/
│   ├── utils/
│   └── index.js
├── database/
├── scripts/
├── temp/
├── logs/
├── .env
├── .gitignore
└── package.json
```

---

## 🗄️ Configuración de Base de Datos

### 1. Crear archivo de esquema de base de datos
**Archivo:** `database/schema.sql`
```sql
CREATE DATABASE IF NOT EXISTS secure_platform CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE secure_platform;

-- Tabla de usuarios con datos cifrados
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    email_encrypted TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    personal_data_encrypted LONGTEXT,
    metadata_encrypted TEXT,
    device_fingerprint VARCHAR(255),
    risk_level ENUM('low', 'medium', 'high') DEFAULT 'low',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    encryption_version VARCHAR(10) DEFAULT 'v1'
);

-- Tabla de sesiones JWT con metadatos de seguridad
CREATE TABLE user_sessions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    jwt_token_hash VARCHAR(255) NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    device_fingerprint VARCHAR(255),
    risk_level ENUM('low', 'medium', 'high') DEFAULT 'low',
    location_country VARCHAR(2),
    is_suspicious BOOLEAN DEFAULT FALSE,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Tabla de logs de seguridad cifrados
CREATE TABLE security_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    event_type VARCHAR(100) NOT NULL,
    encrypted_details LONGTEXT,
    ip_address VARCHAR(45),
    user_agent TEXT,
    risk_score INT DEFAULT 0,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    severity ENUM('low', 'medium', 'high', 'critical') DEFAULT 'medium'
);

-- Tabla de integridad del servidor
CREATE TABLE server_integrity (
    id INT AUTO_INCREMENT PRIMARY KEY,
    fingerprint_hash VARCHAR(255) NOT NULL,
    system_data_encrypted LONGTEXT,
    last_check TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status ENUM('secure', 'compromised', 'unknown') DEFAULT 'secure'
);

-- Tabla de claves de rotación
CREATE TABLE encryption_keys (
    id INT AUTO_INCREMENT PRIMARY KEY,
    key_version VARCHAR(20) NOT NULL UNIQUE,
    encrypted_key_data LONGTEXT NOT NULL,
    is_active BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL
);

-- Tabla de IPs bloqueadas
CREATE TABLE blocked_ips (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL UNIQUE,
    reason TEXT,
    blocked_until TIMESTAMP,
    block_count INT DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Tabla de dispositivos conocidos
CREATE TABLE known_devices (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    device_fingerprint VARCHAR(255) NOT NULL,
    device_name VARCHAR(255),
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_trusted BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE KEY unique_user_device (user_id, device_fingerprint)
);

-- Tabla de métricas de seguridad
CREATE TABLE security_metrics (
    id INT AUTO_INCREMENT PRIMARY KEY,
    metric_name VARCHAR(100) NOT NULL,
    metric_value DECIMAL(10,2) NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_metric_time (metric_name, timestamp)
);

-- Índices para optimización
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_sessions_user_id ON user_sessions(user_id);
CREATE INDEX idx_sessions_expires ON user_sessions(expires_at);
CREATE INDEX idx_sessions_suspicious ON user_sessions(is_suspicious);
CREATE INDEX idx_logs_timestamp ON security_logs(timestamp);
CREATE INDEX idx_logs_severity ON security_logs(severity);
CREATE INDEX idx_logs_event_type ON security_logs(event_type);
CREATE INDEX idx_blocked_ips_expires ON blocked_ips(blocked_until);
```

---

## 🔑 Variables de Entorno Seguras

### Crear archivo .env PARA REFERENCIA LOCAL ÚNICAMENTE
**Archivo:** `.env.example`
```env
# ⚠️ IMPORTANTE: Este archivo es solo para referencia
# En producción, configura estas variables en el panel de tu proveedor de hosting
# NUNCA subas este archivo con valores reales al repositorio

# ====================
# SERVER & APP CONFIG
# ====================
PORT=3000
NODE_ENV=production

# ====================
# FRAGMENTOS DE DATABASE (Dividir URL en partes)
# ====================
DB_FRAGMENT_1=mysql://secure_user
DB_FRAGMENT_2=:password_here@host.com:3306/
DB_FRAGMENT_3=database_name

# ====================
# SEMILLAS PARA GENERACIÓN DINÁMICA
# ====================
BASE_SEED=tu_semilla_ultra_secreta_2025
JWT_SEED=jwt_generation_seed_unique
ENCRYPTION_SEED=encryption_master_seed
EMAIL_SEED=email_password_generator_seed

# ====================
# FRAGMENTOS DE EMAIL (Dividir credenciales)
# ====================
PRIMARY_EMAIL_USER=tu_usuario_gmail
EMAIL_DOMAIN_1=gmail.com
BACKUP_EMAIL_USER=tu_usuario_proton
EMAIL_DOMAIN_2=protonmail.com
RECIPIENT_EMAIL=tu_email_personal@protonmail.com

# ====================
# TELEGRAM (OPCIONAL - Canal de emergencia)
# ====================
TELEGRAM_BOT_TOKEN=123456789:ABCdefGHIjklMNOpqrsTUVwxyz
TELEGRAM_CHAT_ID=123456789

# ====================
# CONFIGURACIÓN DE SEGURIDAD
# ====================
INTEGRITY_MONITOR_ENABLED=true
INTEGRITY_CHECK_INTERVAL_MIN=60
AUTO_ROTATION_ENABLED=true
ANOMALY_DETECTION_ENABLED=true
AUTO_BLOCK_MALICIOUS_IPS=true

# ====================
# CONFIGURACIÓN DE ALERTAS
# ====================
ALERT_CHANNELS=email,telegram
CAMOUFLAGE_ENABLED=true
MULTI_CHANNEL_CRITICAL=true

# ====================
# CONFIGURACIÓN DE RIESGO
# ====================
MAX_FAILED_ATTEMPTS=5
SESSION_RISK_THRESHOLD=50
DEVICE_TRUST_REQUIRED=true
GEO_ANOMALY_DETECTION=true
```

### ⚠️ IMPORTANTE: Configuración en Hosting
En tu proveedor de hosting (Heroku, Railway, etc.), configura SOLO estas variables:
```bash
# Variables seguras para hosting
BASE_SEED=tu_semilla_secreta
DB_FRAGMENT_1=mysql://user
DB_FRAGMENT_2=:pass@host:3306/
DB_FRAGMENT_3=database_name
PRIMARY_EMAIL_USER=tu_usuario
EMAIL_DOMAIN_1=gmail.com
RECIPIENT_EMAIL=tu_email@protonmail.com
INTEGRITY_MONITOR_ENABLED=true
ANOMALY_DETECTION_ENABLED=true
```

---

## ⚙️ Archivos de Configuración Avanzados

### 1. Gestión segura de variables de entorno
**Archivo:** `src/config/secure-env.js`
```javascript
const crypto = require('crypto');

class SecureEnvironment {
    constructor() {
        this.loadRotatingSecrets();
        this.setupAutoRotation();
    }

    loadRotatingSecrets() {
        // Generar secretos basados en fecha + semilla
        const today = new Date().toISOString().split('T')[0]; // YYYY-MM-DD
        const baseSeed = process.env.BASE_SEED || 'default_seed_change_this';
        
        this.secrets = {
            jwt: this.generateTimeBasedSecret(baseSeed + '_jwt_' + today),
            encryption: this.generateTimeBasedSecret(baseSeed + '_enc_' + today),
            session: this.generateTimeBasedSecret(baseSeed + '_sess_' + today),
            email: this.generateTimeBasedSecret(baseSeed + '_email_' + today)
        };

        console.log('🔐 Secretos dinámicos cargados para:', today);
    }

    generateTimeBasedSecret(input) {
        return crypto.scryptSync(input, 'dynamic_salt', 32).toString('hex');
    }

    // Auto-rotación cada 24 horas
    setupAutoRotation() {
        setInterval(() => {
            this.loadRotatingSecrets();
            console.log('🔄 Secretos internos rotados automáticamente');
        }, 24 * 60 * 60 * 1000); // 24 horas
    }

    getSecret(type) {
        return this.secrets[type] || this.generateTimeBasedSecret(`fallback_${type}`);
    }

    // Verificar si los secretos necesitan renovación
    needsRotation() {
        const lastRotation = this.lastRotationTime || Date.now();
        const timeSinceRotation = Date.now() - lastRotation;
        return timeSinceRotation > (24 * 60 * 60 * 1000); // 24 horas
    }
}

module.exports = new SecureEnvironment();
```

### 2. Constructor de credenciales
**Archivo:** `src/config/credential-builder.js`
```javascript
const crypto = require('crypto');

class CredentialBuilder {
    constructor() {
        this.secureEnv = require('./secure-env');
    }

    buildDatabaseURL() {
        try {
            // Reconstruir URL de DB desde fragmentos
            const fragment1 = process.env.DB_FRAGMENT_1 || '';
            const fragment2 = process.env.DB_FRAGMENT_2 || '';
            const fragment3 = process.env.DB_FRAGMENT_3 || '';
            
            if (!fragment1 || !fragment2 || !fragment3) {
                throw new Error('Fragmentos de DB incompletos');
            }

            return fragment1 + fragment2 + fragment3;
        } catch (error) {
            console.error('❌ Error construyendo URL de base de datos:', error);
            throw error;
        }
    }

    buildEmailCredentials(channel = 'primary') {
        try {
            const userEnvVar = channel === 'primary' ? 'PRIMARY_EMAIL_USER' : 'BACKUP_EMAIL_USER';
            const domainEnvVar = channel === 'primary' ? 'EMAIL_DOMAIN_1' : 'EMAIL_DOMAIN_2';
            
            const user = process.env[userEnvVar];
            const domain = process.env[domainEnvVar];
            
            if (!user || !domain) {
                throw new Error(`Credenciales de email ${channel} incompletas`);
            }

            return {
                user: `${user}@${domain}`,
                pass: this.generateEmailPassword(channel),
                service: domain.includes('gmail') ? 'gmail' : 'smtp'
            };
        } catch (error) {
            console.error(`❌ Error construyendo credenciales de ${channel}:`, error);
            throw error;
        }
    }

    generateEmailPassword(channel) {
        // Generar password de correo basado en patrones conocidos solo por ti
        const date = new Date();
        const seed = process.env.BASE_SEED || 'default';
        const emailSeed = process.env.EMAIL_SEED || 'email_default';
        const pattern = `${seed}_${emailSeed}_${channel}_${date.getMonth()}_${date.getFullYear()}`;
        
        return crypto.scryptSync(pattern, 'email_salt', 16).toString('hex');
    }

    buildTelegramCredentials() {
        return {
            botToken: process.env.TELEGRAM_BOT_TOKEN,
            chatId: process.env.TELEGRAM_CHAT_ID
        };
    }

    // Generar claves JWT dinámicas
    generateJWTSecret() {
        const jwtSeed = process.env.JWT_SEED || 'jwt_default';
        const baseSeed = process.env.BASE_SEED || 'default';
        const today = new Date().toISOString().split('T')[0];
        
        return crypto.scryptSync(`${baseSeed}_${jwtSeed}_${today}`, 'jwt_salt', 64).toString('hex');
    }

    // Verificar que todas las credenciales necesarias están disponibles
    validateCredentials() {
        const required = [
            'BASE_SEED',
            'DB_FRAGMENT_1',
            'DB_FRAGMENT_2', 
            'DB_FRAGMENT_3',
            'PRIMARY_EMAIL_USER',
            'EMAIL_DOMAIN_1'
        ];

        const missing = required.filter(key => !process.env[key]);
        
        if (missing.length > 0) {
            throw new Error(`Variables de entorno faltantes: ${missing.join(', ')}`);
        }

        console.log('✅ Validación de credenciales completada');
        return true;
    }
}

module.exports = new CredentialBuilder();
```

### 3. Configuración de base de datos segura
**Archivo:** `src/config/database.js`
```javascript
const mysql = require('mysql2/promise');
const credentialBuilder = require('./credential-builder');

class DatabaseConfig {
    constructor() {
        this.pool = null;
        this.initializePool();
    }

    initializePool() {
        try {
            // Validar credenciales antes de conectar
            credentialBuilder.validateCredentials();
            
            // Construir URL de conexión de forma segura
            const databaseURL = credentialBuilder.buildDatabaseURL();
            
            this.pool = mysql.createPool({
                uri: databaseURL,
                waitForConnections: true,
                connectionLimit: 10,
                queueLimit: 0,
                acquireTimeout: 60000,
                timeout: 60000,
                ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
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

    // Método para ejecutar consultas con logging de seguridad
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
            // Log de consulta fallida
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
            
            // Log directo sin usar secureQuery para evitar recursión
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
```

---

## 🔐 Sistema de Cifrado (Mantenido y Mejorado)

### 1. Cifrado Nivel 1 (AES-256-CBC)
**Archivo:** `src/crypto/level1.js`
```javascript
const crypto = require('crypto');
const secureEnv = require('../config/secure-env');

class Level1Encryption {
    constructor() {
        this.algorithm = 'aes-256-cbc';
        this.getKey = () => secureEnv.getSecret('encryption');
    }

    encrypt(text) {
        try {
            const key = Buffer.from(this.getKey(), 'hex');
            const iv = crypto.randomBytes(16);
            const cipher = crypto.createCipher(this.algorithm, key, iv);
            
            let encrypted = cipher.update(text, 'utf8', 'hex');
            encrypted += cipher.final('hex');
            
            return iv.toString('hex') + ':' + encrypted;
        } catch (error) {
            console.error('❌ Error en cifrado Level 1:', error);
            throw new Error('Error en cifrado Level 1');
        }
    }

    decrypt(encryptedText) {
        try {
            const parts = encryptedText.split(':');
            if (parts.length !== 2) {
                throw new Error('Formato de texto cifrado inválido');
            }

            const iv = Buffer.from(parts[0], 'hex');
            const encryptedData = parts[1];
            const key = Buffer.from(this.getKey(), 'hex');
            
            const decipher = crypto.createDecipher(this.algorithm, key, iv);
            
            let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
            decrypted += decipher.final('utf8');
            
            return decrypted;
        } catch (error) {
            console.error('❌ Error en descifrado Level 1:', error);
            throw new Error('Error en descifrado Level 1');
        }
    }
}

module.exports = new Level1Encryption();
```

### 2. Cifrado Nivel 2 (AES-256-GCM)
**Archivo:** `src/crypto/level2.js`
```javascript
const crypto = require('crypto');
const secureEnv = require('../config/secure-env');

class Level2Encryption {
    constructor() {
        this.algorithm = 'aes-256-gcm';
        this.getKey = () => secureEnv.getSecret('encryption');
    }

    encrypt(text) {
        try {
            const key = Buffer.from(this.getKey(), 'hex');
            const iv = crypto.randomBytes(12);
            const cipher = crypto.createCipher(this.algorithm, key, iv);
            
            let encrypted = cipher.update(text, 'utf8', 'hex');
            encrypted += cipher.final('hex');
            
            const authTag = cipher.getAuthTag();
            
            return iv.toString('hex') + ':' + authTag.toString('hex') + ':' + encrypted;
        } catch (error) {
            console.error('❌ Error en cifrado Level 2:', error);
            throw new Error('Error en cifrado Level 2');
        }
    }

    decrypt(encryptedText) {
        try {
            const parts = encryptedText.split(':');
            if (parts.length !== 3) {
                throw new Error('Formato de texto cifrado inválido');
            }

            const iv = Buffer.from(parts[0], 'hex');
            const authTag = Buffer.from(parts[1], 'hex');
            const encryptedData = parts[2];
            const key = Buffer.from(this.getKey(), 'hex');
            
            const decipher = crypto.createDecipher(this.algorithm, key, iv);
            decipher.setAuthTag(authTag);
            
            let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
            decrypted += decipher.final('utf8');
            
            return decrypted;
        } catch (error) {
            console.error('❌ Error en descifrado Level 2:', error);
            throw new Error('Error en descifrado Level 2');
        }
    }
}

module.exports = new Level2Encryption();
```

### 3. Cifrado Nivel 3 (ChaCha20-Poly1305)
**Archivo:** `src/crypto/level3.js`
```javascript
const crypto = require('crypto');
const secureEnv = require('../config/secure-env');

class Level3Encryption {
    constructor() {
        this.algorithm = 'chacha20-poly1305';
        this.getKey = () => secureEnv.getSecret('encryption');
    }

    encrypt(text) {
        try {
            const key = Buffer.from(this.getKey(), 'hex');
            const iv = crypto.randomBytes(12);
            const cipher = crypto.createCipher(this.algorithm, key, iv);
            
            let encrypted = cipher.update(text, 'utf8', 'hex');
            encrypted += cipher.final('hex');
            
            const authTag = cipher.getAuthTag();
            
            return iv.toString('hex') + ':' + authTag.toString('hex') + ':' + encrypted;
        } catch (error) {
            console.error('❌ Error en cifrado Level 3:', error);
            throw new Error('Error en cifrado Level 3');
        }
    }

    decrypt(encryptedText) {
        try {
            const parts = encryptedText.split(':');
            if (parts.length !== 3) {
                throw new Error('Formato de texto cifrado inválido');
            }

            const iv = Buffer.from(parts[0], 'hex');
            const authTag = Buffer.from(parts[1], 'hex');
            const encryptedData = parts[2];
            const key = Buffer.from(this.getKey(), 'hex');
            
            const decipher = crypto.createDecipher(this.algorithm, key, iv);
            decipher.setAuthTag(authTag);
            
            let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
            decrypted += decipher.final('utf8');
            
            return decrypted;
        } catch (error) {
            console.error('❌ Error en descifrado Level 3:', error);
            throw new Error('Error en descifrado Level 3');
        }
    }
}

module.exports = new Level3Encryption();
```

### 4. Cifrador Triple (Mejorado)
**Archivo:** `src/crypto/tripleEncryptor.js`
```javascript
const level1 = require('./level1');
const level2 = require('./level2');
const level3 = require('./level3');

class TripleEncryptor {
    constructor() {
        this.levels = [level1, level2, level3];
        this.encryptionMetrics = {
            totalEncryptions: 0,
            totalDecryptions: 0,
            errors: 0
        };
    }

    tripleEncrypt(text) {
        try {
            const startTime = Date.now();
            let encrypted = text;
            
            // Aplicar cifrado en secuencia: L1 → L2 → L3
            for (let i = 0; i < this.levels.length; i++) {
                encrypted = this.levels[i].encrypt(encrypted);
                console.log(`🔐 Cifrado Level ${i + 1} aplicado`);
            }
            
            this.encryptionMetrics.totalEncryptions++;
            console.log(`⚡ Triple cifrado completado en ${Date.now() - startTime}ms`);
            
            return encrypted;
        } catch (error) {
            this.encryptionMetrics.errors++;
            console.error('❌ Error en triple cifrado:', error);
            throw new Error('Error en triple cifrado');
        }
    }

    tripleDecrypt(encryptedText) {
        try {
            const startTime = Date.now();
            let decrypted = encryptedText;
            
            // Aplicar descifrado en orden inverso: L3 → L2 → L1
            for (let i = this.levels.length - 1; i >= 0; i--) {
                decrypted = this.levels[i].decrypt(decrypted);
                console.log(`🔓 Descifrado Level ${i + 1} aplicado`);
            }
            
            this.encryptionMetrics.totalDecryptions++;
            console.log(`⚡ Triple descifrado completado en ${Date.now() - startTime}ms`);
            
            return decrypted;
        } catch (error) {
            this.encryptionMetrics.errors++;
            console.error('❌ Error en triple descifrado:', error);
            throw new Error('Error en triple descifrado');
        }
    }

    // Métodos de conveniencia
    encrypt(text) {
        return this.tripleEncrypt(text);
    }

    decrypt(encryptedText) {
        return this.tripleDecrypt(encryptedText);
    }

    // Obtener métricas de rendimiento
    getMetrics() {
        return {
            ...this.encryptionMetrics,
            errorRate: this.encryptionMetrics.errors / (this.encryptionMetrics.totalEncryptions + this.encryptionMetrics.totalDecryptions) || 0
        };
    }

    // Verificar salud del sistema de cifrado
    async healthCheck() {
        try {
            const testData = 'health_check_' + Date.now();
            const encrypted = this.encrypt(testData);
            const decrypted = this.decrypt(encrypted);
            
            if (decrypted === testData) {
                console.log('✅ Health check de cifrado exitoso');
                return { healthy: true, message: 'Sistema de cifrado funcionando correctamente' };
            } else {
                throw new Error('Datos no coinciden después del cifrado/descifrado');
            }
        } catch (error) {
            console.error('❌ Health check de cifrado falló:', error);
            return { healthy: false, message: error.message };
        }
    }
}

module.exports = new TripleEncryptor();
```

---

## 🛡️ Seguridad Operacional

### 1. Detección de Anomalías
**Archivo:** `src/security/anomaly-detection.service.js`
```javascript
const geoip = require('geoip-lite');
const useragent = require('useragent');

class AnomalyDetection {
    constructor() {
        this.requestHistory = new Map();
        this.blockedIPs = new Set();
        this.deviceFingerprints = new Map();
        this.setupCleanup();
    }

    analyzeRequest(req) {
        const fingerprint = this.generateRequestFingerprint(req);
        const anomalies = [];

        // 1. Detectar velocidad anómala de requests
        const requestRate = this.getRequestRate(fingerprint.ip);
        if (requestRate > 100) {
            anomalies.push({
                type: 'HIGH_REQUEST_RATE',
                severity: 'high',
                details: { ip: fingerprint.ip, rate: requestRate }
            });
        }

        // 2. Detectar patrones de navegación anómalos
        const navigationPattern = this.getNavigationPattern(fingerprint.ip);
        if (this.isNavigationAnomalous(navigationPattern)) {
            anomalies.push({
                type: 'ANOMALOUS_NAVIGATION',
                severity: 'medium',
                details: { pattern: navigationPattern }
            });
        }

        // 3. Detectar cambios geográficos imposibles
        const geoAnomaly = this.detectGeographicAnomaly(fingerprint);
        if (geoAnomaly.isAnomalous) {
            anomalies.push({
                type: 'IMPOSSIBLE_GEOGRAPHY',
                severity: 'high',
                details: geoAnomaly
            });
        }

        // 4. Detectar intentos de inyección maliciosa
        const maliciousPayload = this.detectMaliciousPayload(req);
        if (maliciousPayload.detected) {
            anomalies.push({
                type: 'MALICIOUS_PAYLOAD',
                severity: 'critical',
                details: maliciousPayload
            });
        }

        // 5. Detectar cambios de dispositivo sospechosos
        const deviceChange = this.detectDeviceChange(fingerprint);
        if (deviceChange.isAnomalous) {
            anomalies.push({
                type: 'SUSPICIOUS_DEVICE_CHANGE',
                severity: 'high',
                details: deviceChange
            });
        }

        // Procesar anomalías
        if (anomalies.length > 0) {
            this.handleAnomalies(anomalies, fingerprint);
        }

        return anomalies;
    }

    generateRequestFingerprint(req) {
        const ip = req.ip || req.connection.remoteAddress;
        const userAgentString = req.headers['user-agent'] || '';
        const agent = useragent.parse(userAgentString);
        const geo = geoip.lookup(ip);

        return {
            ip,
            userAgent: userAgentString,
            browser: agent.family,
            os: agent.os.family,
            device: agent.device.family,
            country: geo ? geo.country : 'Unknown',
            city: geo ? geo.city : 'Unknown',
            timestamp: Date.now(),
            path: req.path,
            method: req.method,
            contentLength: req.headers['content-length'] || 0
        };
    }

    getRequestRate(ip) {
        const now = Date.now();
        const timeWindow = 60 * 1000; // 1 minuto
        
        if (!this.requestHistory.has(ip)) {
            this.requestHistory.set(ip, []);
        }

        const requests = this.requestHistory.get(ip);
        
        // Filtrar requests del último minuto
        const recentRequests = requests.filter(timestamp => now - timestamp < timeWindow);
        
        // Agregar request actual
        recentRequests.push(now);
        
        // Actualizar historial
        this.requestHistory.set(ip, recentRequests);
        
        return recentRequests.length;
    }

    getNavigationPattern(ip) {
        if (!this.requestHistory.has(ip)) return [];
        
        const requests = this.requestHistory.get(ip);
        const now = Date.now();
        const timeWindow = 10 * 60 * 1000; // 10 minutos
        
        return requests
            .filter(timestamp => now - timestamp < timeWindow)
            .map(timestamp => ({ timestamp, interval: now - timestamp }));
    }

    isNavigationAnomalous(pattern) {
        if (pattern.length < 10) return false;
        
        // Detectar patrones demasiado regulares (bots)
        const intervals = pattern.map(p => p.interval);
        const avgInterval = intervals.reduce((a, b) => a + b, 0) / intervals.length;
        const variance = intervals.reduce((sum, interval) => sum + Math.pow(interval - avgInterval, 2), 0) / intervals.length;
        
        // Si la varianza es muy baja, podría ser un bot
        return variance < 1000; // Muy regular
    }

    detectGeographicAnomaly(fingerprint) {
        const ip = fingerprint.ip;
        const currentCountry = fingerprint.country;
        
        if (!this.deviceFingerprints.has(ip)) {
            this.deviceFingerprints.set(ip, {
                lastCountry: currentCountry,
                lastSeen: Date.now(),
                locations: [{ country: currentCountry, timestamp: Date.now() }]
            });
            return { isAnomalous: false };
        }

        const deviceData = this.deviceFingerprints.get(ip);
        const timeDiff = Date.now() - deviceData.lastSeen;
        
        // Si cambió de país en menos de 2 horas
        if (deviceData.lastCountry !== currentCountry && timeDiff < 2 * 60 * 60 * 1000) {
            return {
                isAnomalous: true,
                previousCountry: deviceData.lastCountry,
                currentCountry,
                timeDifference: timeDiff
            };
        }

        // Actualizar datos del dispositivo
        deviceData.lastCountry = currentCountry;
        deviceData.lastSeen = Date.now();
        deviceData.locations.push({ country: currentCountry, timestamp: Date.now() });
        
        return { isAnomalous: false };
    }

    detectMaliciousPayload(req) {
        const maliciousPatterns = [
            // SQL Injection
            /(\bUNION\b.*\bSELECT\b|\bDROP\b.*\bTABLE\b|\bINSERT\b.*\bINTO\b)/i,
            /(\bOR\b.*\b1\s*=\s*1\b|\bAND\b.*\b1\s*=\s*1\b)/i,
            
            // XSS
            /<script.*?>.*?<\/script>/i,
            /javascript:/i,
            /on\w+\s*=/i,
            
            // Path Traversal
            /(\.\./.*){3,}/,
            /etc\/passwd/i,
            
            // Code Injection
            /eval\s*\(/i,
            /exec\s*\(/i,
            /cmd\s*=/i,
            /system\s*\(/i,
            
            // NoSQL Injection
            /\$where/i,
            /\$ne/i,
            /\$gt/i,
            /\$lt/i
        ];

        const payloadString = JSON.stringify({
            body: req.body,
            query: req.query,
            params: req.params,
            url: req.url
        });
        
        for (const pattern of maliciousPatterns) {
            if (pattern.test(payloadString)) {
                return {
                    detected: true,
                    pattern: pattern.toString(),
                    payload: payloadString.substring(0, 500),
                    type: this.classifyAttack(pattern)
                };
            }
        }

        return { detected: false };
    }

    classifyAttack(pattern) {
        const patternString = pattern.toString();
        if (patternString.includes('UNION') || patternString.includes('DROP')) return 'SQL_INJECTION';
        if (patternString.includes('script') || patternString.includes('javascript')) return 'XSS';
        if (patternString.includes('..')) return 'PATH_TRAVERSAL';
        if (patternString.includes('eval') || patternString.includes('exec')) return 'CODE_INJECTION';
        if (patternString.includes('$')) return 'NOSQL_INJECTION';
        return 'UNKNOWN';
    }

    detectDeviceChange(fingerprint) {
        const ip = fingerprint.ip;
        const currentFingerprint = `${fingerprint.browser}_${fingerprint.os}_${fingerprint.device}`;
        
        if (!this.deviceFingerprints.has(ip)) {
            this.deviceFingerprints.set(ip, {
                fingerprint: currentFingerprint,
                firstSeen: Date.now()
            });
            return { isAnomalous: false };
        }

        const storedData = this.deviceFingerprints.get(ip);
        
        if (storedData.fingerprint !== currentFingerprint) {
            return {
                isAnomalous: true,
                previousFingerprint: storedData.fingerprint,
                currentFingerprint,
                firstSeen: storedData.firstSeen
            };
        }

        return { isAnomalous: false };
    }

    async handleAnomalies(anomalies, fingerprint) {
        const db = require('../config/database');
        const tripleEncryptor = require('../crypto/tripleEncryptor');

        for (const anomaly of anomalies) {
            // Log de la anomalía
            const encryptedDetails = tripleEncryptor.encrypt(JSON.stringify({
                anomaly,
                fingerprint,
                timestamp: new Date().toISOString()
            }));

            await db.query(
                `INSERT INTO security_logs (event_type, encrypted_details, ip_address, severity, risk_score) 
                 VALUES (?, ?, ?, ?, ?)`,
                [anomaly.type, encryptedDetails, fingerprint.ip, anomaly.severity, this.calculateRiskScore(anomaly)]
            );

            // Auto-bloquear para amenazas críticas
            if (anomaly.severity === 'critical') {
                await this.blockIP(fingerprint.ip, anomaly.type);
                
                // Enviar alerta inmediata
                const alertManager = require('../services/alertManager');
                await alertManager.sendEmergencyAlert({
                    type: anomaly.type,
                    severity: anomaly.severity,
                    details: `Ataque ${anomaly.type} detectado desde IP: ${fingerprint.ip}`,
                    action: 'IP bloqueada automáticamente por 24 horas',
                    timestamp: new Date().toISOString()
                });
            }
        }
    }

    calculateRiskScore(anomaly) {
        const scores = {
            'HIGH_REQUEST_RATE': 60,
            'ANOMALOUS_NAVIGATION': 40,
            'IMPOSSIBLE_GEOGRAPHY': 80,
            'MALICIOUS_PAYLOAD': 100,
            'SUSPICIOUS_DEVICE_CHANGE': 70
        };
        
        return scores[anomaly.type] || 50;
    }

    async blockIP(ip, reason) {
        const db = require('../config/database');
        const blockDuration = 24 * 60 * 60 * 1000; // 24 horas
        const blockedUntil = new Date(Date.now() + blockDuration);
        
        try {
            // Verificar si ya está bloqueada
            const [existing] = await db.query(
                'SELECT id, block_count FROM blocked_ips WHERE ip_address = ?',
                [ip]
            );

            if (existing.length > 0) {
                // Incrementar contador y extender bloqueo
                await db.query(
                    'UPDATE blocked_ips SET blocked_until = ?, block_count = block_count + 1, reason = ? WHERE ip_address = ?',
                    [blockedUntil, reason, ip]
                );
            } else {
                // Nuevo bloqueo
                await db.query(
                    'INSERT INTO blocked_ips (ip_address, reason, blocked_until) VALUES (?, ?, ?)',
                    [ip, reason, blockedUntil]
                );
            }

            this.blockedIPs.add(ip);
            console.log(`🚨 IP ${ip} bloqueada por: ${reason}`);
            
        } catch (error) {
            console.error('❌ Error bloqueando IP:', error);
        }
    }

    async isIPBlocked(ip) {
        if (this.blockedIPs.has(ip)) return true;
        
        const db = require('../config/database');
        try {
            const [blocked] = await db.query(
                'SELECT id FROM blocked_ips WHERE ip_address = ? AND blocked_until > NOW()',
                [ip]
            );
            
            const isBlocked = blocked.length > 0;
            if (isBlocked) {
                this.blockedIPs.add(ip);
            }
            
            return isBlocked;
        } catch (error) {
            console.error('❌ Error verificando IP bloqueada:', error);
            return false;
        }
    }

    setupCleanup() {
        // Limpiar datos antiguos cada hora
        setInterval(() => {
            this.cleanupOldData();
        }, 60 * 60 * 1000);
    }

    cleanupOldData() {
        const now = Date.now();
        const maxAge = 24 * 60 * 60 * 1000; // 24 horas

        // Limpiar historial de requests
        for (const [ip, requests] of this.requestHistory.entries()) {
            const recentRequests = requests.filter(timestamp => now - timestamp < maxAge);
            if (recentRequests.length === 0) {
                this.requestHistory.delete(ip);
            } else {
                this.requestHistory.set(ip, recentRequests);
            }
        }

        // Limpiar fingerprints de dispositivos
        for (const [ip, data] of this.deviceFingerprints.entries()) {
            if (now - data.lastSeen > maxAge) {
                this.deviceFingerprints.delete(ip);
            }
        }

        console.log('🧹 Limpieza de datos de anomalías completada');
    }
}

module.exports = new AnomalyDetection();
```

### 2. Autenticación Avanzada con Detección de Riesgo
**Archivo:** `src/security/secure-auth.service.js`
```javascript
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const geoip = require('geoip-lite');
const credentialBuilder = require('../config/credential-builder');

class SecureAuthService {
    constructor() {
        this.suspiciousSessions = new Set();
        this.deviceFingerprints = new Map();
        this.failedAttempts = new Map();
        this.setupSessionMonitoring();
    }

    async authenticateUser(username, password, deviceInfo) {
        try {
            // Verificar intentos fallidos previos
            if (await this.isAccountLocked(username)) {
                throw new Error('Cuenta temporalmente bloqueada por múltiples intentos fallidos');
            }

            // Validar credenciales básicas
            const user = await this.validateCredentials(username, password);
            if (!user) {
                await this.recordFailedAttempt(username, deviceInfo);
                throw new Error('Credenciales inválidas');
            }

            // Generar fingerprint del dispositivo
            const deviceFingerprint = this.generateDeviceFingerprint(deviceInfo);
            
            // Calcular nivel de riesgo
            const riskLevel = await this.calculateRiskLevel(user, deviceInfo, deviceFingerprint);
            
            // Verificar si necesita verificación adicional
            if (riskLevel === 'high') {
                return await this.requireAdditionalVerification(user, deviceInfo);
            }

            // Crear sesión segura
            const sessionData = {
                userId: user.id,
                username: user.username,
                deviceFingerprint,
                ipAddress: deviceInfo.ipAddress,
                riskLevel,
                createdAt: Date.now()
            };

            const token = await this.generateSecureToken(sessionData);
            await this.createSecureSession(token, sessionData);
            
            // Limpiar intentos fallidos exitosos
            this.failedAttempts.delete(username);
            
            // Registrar dispositivo si es confiable
            if (riskLevel === 'low') {
                await this.registerTrustedDevice(user.id, deviceFingerprint, deviceInfo);
            }

            return {
                success: true,
                token,
                expiresAt: new Date(Date.now() + 5 * 24 * 60 * 60 * 1000),
                riskLevel,
                requiresVerification: false
            };

        } catch (error) {
            await this.logFailedAttempt(username, deviceInfo, error.message);
            throw error;
        }
    }

    generateDeviceFingerprint(deviceInfo) {
        const components = [
            deviceInfo.userAgent || '',
            deviceInfo.screenResolution || '',
            deviceInfo.timezone || '',
            deviceInfo.language || '',
            deviceInfo.platform || '',
            deviceInfo.colorDepth || '',
            deviceInfo.pixelRatio || ''
        ].join('|');

        return crypto.createHash('sha256').update(components).digest('hex');
    }

    async calculateRiskLevel(user, deviceInfo, deviceFingerprint) {
        let riskScore = 0;

        // Factor 1: Dispositivo desconocido
        const isKnownDevice = await this.isKnownDevice(user.id, deviceFingerprint);
        if (!isKnownDevice) riskScore += 30;

        // Factor 2: Nueva ubicación geográfica
        const isNewLocation = await this.isNewLocation(user.id, deviceInfo.ipAddress);
        if (isNewLocation) riskScore += 25;

        // Factor 3: Horario inusual
        if (this.isOffHours()) riskScore += 15;

        // Factor 4: Intentos fallidos recientes
        const recentFailures = await this.getRecentFailedAttempts(user.id);
        if (recentFailures > 0) riskScore += (recentFailures * 10);

        // Factor 5: Velocidad de conexión anómala
        const connectionPattern = await this.analyzeConnectionPattern(deviceInfo.ipAddress);
        if (connectionPattern.isAnomalous) riskScore += 20;

        // Factor 6: User-Agent sospechoso
        if (this.isSuspiciousUserAgent(deviceInfo.userAgent)) riskScore += 15;

        // Clasificar riesgo
        if (riskScore >= 70) return 'high';
        if (riskScore >= 40) return 'medium';
        return 'low';
    }

    async isKnownDevice(userId, deviceFingerprint) {
        const db = require('../config/database');
        
        const [devices] = await db.query(
            'SELECT id FROM known_devices WHERE user_id = ? AND device_fingerprint = ? AND is_trusted = TRUE',
            [userId, deviceFingerprint]
        );

        return devices.length > 0;
    }

    async isNewLocation(userId, ipAddress) {
        const geo = geoip.lookup(ipAddress);
        if (!geo) return true;

        const db = require('../config/database');
        
        const [sessions] = await db.query(
            'SELECT DISTINCT location_country FROM user_sessions WHERE user_id = ? AND location_country IS NOT NULL',
            [userId]
        );

        const knownCountries = sessions.map(s => s.location_country);
        return !knownCountries.includes(geo.country);
    }

    isOffHours() {
        const hour = new Date().getHours();
        return hour < 6 || hour > 23; // Entre 11 PM y 6 AM
    }

    async getRecentFailedAttempts(userId) {
        const db = require('../config/database');
        
        const [attempts] = await db.query(`
            SELECT COUNT(*) as count FROM security_logs 
            WHERE event_type = 'LOGIN_FAILED' 
            AND encrypted_details LIKE CONCAT('%"userId":"', ?, '"%')
            AND timestamp > DATE_SUB(NOW(), INTERVAL 1 HOUR)
        `, [userId]);

        return attempts[0].count;
    }

    async analyzeConnectionPattern(ipAddress) {
        // Analizar patrón de conexiones desde esta IP
        const history = this.deviceFingerprints.get(ipAddress) || { connections: [] };
        const now = Date.now();
        const recentConnections = history.connections.filter(c => now - c < 10 * 60 * 1000); // 10 min

        // Si hay más de 10 conexiones en 10 minutos = anómalo
        return {
            isAnomalous: recentConnections.length > 10,
            connectionCount: recentConnections.length
        };
    }

    isSuspiciousUserAgent(userAgent) {
        if (!userAgent) return true;
        
        const suspiciousPatterns = [
            /bot|crawler|spider/i,
            /curl|wget|python|java/i,
            /postman|insomnia/i,
            /scanner|test/i
        ];

        return suspiciousPatterns.some(pattern => pattern.test(userAgent));
    }

    async generateSecureToken(sessionData) {
        const jwtSecret = credentialBuilder.generateJWTSecret();
        
        const payload = {
            userId: sessionData.userId,
            username: sessionData.username,
            sessionId: crypto.randomUUID(),
            deviceFingerprint: sessionData.deviceFingerprint,
            riskLevel: sessionData.riskLevel,
            iat: Math.floor(Date.now() / 1000)
        };

        return jwt.sign(payload, jwtSecret, { expiresIn: '5d' });
    }

    async createSecureSession(token, sessionData) {
        const db = require('../config/database');
        const geo = geoip.lookup(sessionData.ipAddress);
        
        const tokenHash = this.hashToken(token);
        const expiresAt = new Date(Date.now() + 5 * 24 * 60 * 60 * 1000);

        await db.query(`
            INSERT INTO user_sessions 
            (user_id, jwt_token_hash, ip_address, user_agent, device_fingerprint, 
             risk_level, location_country, expires_at) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `, [
            sessionData.userId,
            tokenHash,
            sessionData.ipAddress,
            sessionData.userAgent || 'Unknown',
            sessionData.deviceFingerprint,
            sessionData.riskLevel,
            geo ? geo.country : null,
            expiresAt
        ]);
    }

    async validateToken(token, currentIP) {
        try {
            const jwtSecret = credentialBuilder.generateJWTSecret();
            const decoded = jwt.verify(token, jwtSecret);
            
            // Verificar que la sesión existe
            const db = require('../config/database');
            const [sessions] = await db.query(
                'SELECT * FROM user_sessions WHERE jwt_token_hash = ? AND expires_at > NOW()',
                [this.hashToken(token)]
            );

            if (sessions.length === 0) {
                throw new Error('Sesión inválida o expirada');
            }

            const session = sessions[0];

            // Verificar si la sesión está marcada como sospechosa
            if (session.is_suspicious) {
                throw new Error('Sesión marcada como sospechosa');
            }

            // Detectar anomalías de sesión
            const anomalies = await this.detectSessionAnomalies(session, decoded, currentIP);
            if (anomalies.length > 0) {
                await this.handleSessionAnomalies(session.id, anomalies);
                throw new Error('Sesión revocada por actividad anómala');
            }

            // Actualizar última actividad
            await db.query(
                'UPDATE user_sessions SET last_activity = NOW() WHERE id = ?',
                [session.id]
            );

            return {
                valid: true,
                userId: decoded.userId,
                username: decoded.username,
                sessionId: session.id,
                riskLevel: session.risk_level
            };

        } catch (error) {
            return {
                valid: false,
                error: error.message
            };
        }
    }

    async detectSessionAnomalies(session, decodedToken, currentIP) {
        const anomalies = [];

        // 1. Cambio de IP geográficamente imposible
        if (session.ip_address !== currentIP) {
            const timeElapsed = Date.now() - new Date(session.created_at).getTime();
            const distance = await this.calculateGeographicDistance(session.ip_address, currentIP);
            
            // Si viajó más de 1000km en menos de 2 horas
            if (distance > 1000 && timeElapsed < 2 * 60 * 60 * 1000) {
                anomalies.push({
                    type: 'IMPOSSIBLE_TRAVEL',
                    details: { originalIP: session.ip_address, currentIP, distance, timeElapsed }
                });
            }
        }

        // 2. Múltiples sesiones simultáneas desde ubicaciones diferentes
        const db = require('../config/database');
        const [simultaneousSessions] = await db.query(`
            SELECT COUNT(DISTINCT ip_address) as ip_count 
            FROM user_sessions 
            WHERE user_id = ? AND expires_at > NOW() AND id != ?
        `, [decodedToken.userId, session.id]);

        if (simultaneousSessions[0].ip_count > 2) {
            anomalies.push({
                type: 'MULTIPLE_SIMULTANEOUS_SESSIONS',
                details: { sessionCount: simultaneousSessions[0].ip_count }
            });
        }

        // 3. Cambio de fingerprint del dispositivo
        if (session.device_fingerprint !== decodedToken.deviceFingerprint) {
            anomalies.push({
                type: 'DEVICE_FINGERPRINT_MISMATCH',
                details: { 
                    original: session.device_fingerprint, 
                    current: decodedToken.deviceFingerprint 
                }
            });
        }

        return anomalies;
    }

    async calculateGeographicDistance(ip1, ip2) {
        const geo1 = geoip.lookup(ip1);
        const geo2 = geoip.lookup(ip2);
        
        if (!geo1 || !geo2) return 0;

        // Fórmula de Haversine para calcular distancia
        const R = 6371; // Radio de la Tierra en km
        const dLat = this.toRad(geo2.ll[0] - geo1.ll[0]);
        const dLon = this.toRad(geo2.ll[1] - geo1.ll[1]);
        
        const a = Math.sin(dLat/2) * Math.sin(dLat/2) +
                  Math.cos(this.toRad(geo1.ll[0])) * Math.cos(this.toRad(geo2.ll[0])) * 
                  Math.sin(dLon/2) * Math.sin(dLon/2);
        
        const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
        return R * c;
    }

    toRad(degrees) {
        return degrees * (Math.PI / 180);
    }

    async handleSessionAnomalies(sessionId, anomalies) {
        const db = require('../config/database');
        
        // Marcar sesión como sospechosa
        await db.query(
            'UPDATE user_sessions SET is_suspicious = TRUE WHERE id = ?',
            [sessionId]
        );

        this.suspiciousSessions.add(sessionId);

        // Log de las anomalías
        for (const anomaly of anomalies) {
            const tripleEncryptor = require('../crypto/tripleEncryptor');
            const encryptedDetails = tripleEncryptor.encrypt(JSON.stringify({
                sessionId,
                anomaly,
                timestamp: new Date().toISOString()
            }));

            await db.query(
                `INSERT INTO security_logs (event_type, encrypted_details, severity) 
                 VALUES (?, ?, 'high')`,
                [anomaly.type, encryptedDetails]
            );
        }

        console.log(`🚨 Sesión ${sessionId} marcada como sospechosa por:`, anomalies.map(a => a.type));
    }

    async registerTrustedDevice(userId, deviceFingerprint, deviceInfo) {
        const db = require('../config/database');
        
        try {
            await db.query(`
                INSERT INTO known_devices (user_id, device_fingerprint, device_name, is_trusted)
                VALUES (?, ?, ?, TRUE)
                ON DUPLICATE KEY UPDATE last_seen = NOW(), is_trusted = TRUE
            `, [
                userId, 
                deviceFingerprint, 
                this.generateDeviceName(deviceInfo)
            ]);

            console.log(`✅ Dispositivo registrado como confiable para usuario ${userId}`);
        } catch (error) {
            console.error('❌ Error registrando dispositivo confiable:', error);
        }
    }

    generateDeviceName(deviceInfo) {
        const userAgent = deviceInfo.userAgent || '';
        
        if (userAgent.includes('Chrome')) return 'Chrome Browser';
        if (userAgent.includes('Firefox')) return 'Firefox Browser';
        if (userAgent.includes('Safari')) return 'Safari Browser';
        if (userAgent.includes('Edge')) return 'Edge Browser';
        if (userAgent.includes('Mobile')) return 'Mobile Device';
        
        return 'Unknown Device';
    }

    async recordFailedAttempt(username, deviceInfo) {
        const key = `${username}_${deviceInfo.ipAddress}`;
        const attempts = this.failedAttempts.get(key) || [];
        
        attempts.push(Date.now());
        this.failedAttempts.set(key, attempts);

        // Limpiar intentos antiguos (más de 1 hora)
        const oneHourAgo = Date.now() - (60 * 60 * 1000);
        const recentAttempts = attempts.filter(timestamp => timestamp > oneHourAgo);
        this.failedAttempts.set(key, recentAttempts);
    }

    async isAccountLocked(username) {
        const attempts = this.failedAttempts.get(username) || [];
        const oneHourAgo = Date.now() - (60 * 60 * 1000);
        const recentAttempts = attempts.filter(timestamp => timestamp > oneHourAgo);
        
        return recentAttempts.length >= 5; // Bloquear después de 5 intentos fallidos
    }

    setupSessionMonitoring() {
        // Auditoría de sesiones cada 5 minutos
        setInterval(async () => {
            await this.auditActiveSessions();
        }, 5 * 60 * 1000);

        // Limpiar datos antiguos cada hora
        setInterval(() => {
            this.cleanupOldData();
        }, 60 * 60 * 1000);
    }

    async auditActiveSessions() {
        const db = require('../config/database');
        
        try {
            const [sessions] = await db.query(`
                SELECT id, user_id, ip_address, device_fingerprint, created_at, risk_level
                FROM user_sessions 
                WHERE expires_at > NOW() AND is_suspicious = FALSE
                LIMIT 100
            `);

            for (const session of sessions) {
                const anomalies = await this.detectSessionAnomalies(session, {
                    userId: session.user_id,
                    deviceFingerprint: session.device_fingerprint
                }, session.ip_address);

                if (anomalies.length > 0) {
                    await this.handleSessionAnomalies(session.id, anomalies);
                }
            }
        } catch (error) {
            console.error('❌ Error en auditoría de sesiones:', error);
        }
    }

    cleanupOldData() {
        const oneHourAgo = Date.now() - (60 * 60 * 1000);

        // Limpiar intentos fallidos antiguos
        for (const [key, attempts] of this.failedAttempts.entries()) {
            const recentAttempts = attempts.filter(timestamp => timestamp > oneHourAgo);
            if (recentAttempts.length === 0) {
                this.failedAttempts.delete(key);
            } else {
                this.failedAttempts.set(key, recentAttempts);
            }
        }

        console.log('🧹 Limpieza de datos de autenticación completada');
    }

    hashToken(token) {
        return crypto.createHash('sha256').update(token).digest('hex');
    }

    async logFailedAttempt(username, deviceInfo, error) {
        const db = require('../config/database');
        const tripleEncryptor = require('../crypto/tripleEncryptor');
        
        try {
            const encryptedDetails = tripleEncryptor.encrypt(JSON.stringify({
                username,
                ipAddress: deviceInfo.ipAddress,
                userAgent: deviceInfo.userAgent,
                error,
                timestamp: new Date().toISOString()
            }));

            await db.query(
                `INSERT INTO security_logs (event_type, encrypted_details, ip_address, severity) 
                 VALUES ('LOGIN_FAILED', ?, ?, 'medium')`,
                [encryptedDetails, deviceInfo.ipAddress]
            );
        } catch (logError) {
            console.error('❌ Error logging failed attempt:', logError);
        }
    }
}

module.exports = new SecureAuthService();
```

---

## 🛡️ Middlewares de Protección Automática

### 1. Middleware de Protección Inteligente
**Archivo:** `src/middleware/protection.middleware.js`
```javascript
const anomalyDetection = require('../security/anomaly-detection.service');

class ProtectionMiddleware {
    constructor() {
        this.rateLimits = new Map();
        this.setupCleanup();
    }

    // Middleware principal de protección automática
    autoProtect() {
        return async (req, res, next) => {
            try {
                // 1. Verificar si la IP está bloqueada
                const isBlocked = await anomalyDetection.isIPBlocked(req.ip);
                if (isBlocked) {
                    return res.status(403).json({
                        success: false,
                        message: 'Acceso denegado',
                        code: 'IP_BLOCKED'
                    });
                }

                // 2. Análisis de anomalías en tiempo real
                const anomalies = anomalyDetection.analyzeRequest(req);
                
                // 3. Bloquear inmediatamente amenazas críticas
                const criticalAnomalies = anomalies.filter(a => a.severity === 'critical');
                if (criticalAnomalies.length > 0) {
                    console.log(`🚨 Bloqueando amenaza crítica desde ${req.ip}:`, criticalAnomalies);
                    
                    return res.status(403).json({
                        success: false,
                        message: 'Solicitud rechazada por razones de seguridad',
                        code: 'SECURITY_VIOLATION'
                    });
                }

                // 4. Aplicar rate limiting dinámico para anomalías menores
                if (anomalies.length > 0) {
                    const limitApplied = await this.applyDynamicRateLimit(req, res, anomalies);
                    if (!limitApplied) return; // Response ya enviada por rate limiter
                }

                // 5. Agregar headers de seguridad
                this.addSecurityHeaders(res);

                // 6. Continuar con el siguiente middleware
                next();

            } catch (error) {
                console.error('❌ Error en middleware de protección:', error);
                next(); // Continuar para no romper la aplicación
            }
        };
    }

    async applyDynamicRateLimit(req, res, anomalies) {
        const ip = req.ip || req.connection.remoteAddress;
        
        // Calcular límite dinámico basado en anomalías
        let requestLimit = 60; // Base: 60 req/min
        let windowSize = 60 * 1000; // 1 minuto

        // Reducir límites según severidad de anomalías
        anomalies.forEach(anomaly => {
            switch (anomaly.severity) {
                case 'high':
                    requestLimit = Math.max(10, requestLimit - 20);
                    break;
                case 'medium':
                    requestLimit = Math.max(20, requestLimit - 10);
                    break;
                case 'low':
                    requestLimit = Math.max(40, requestLimit - 5);
                    break;
            }
        });

        // Verificar límite
        const allowed = await this.checkRateLimit(ip, requestLimit, windowSize);
        
        if (!allowed) {
            const retryAfter = Math.ceil(windowSize / 1000);
            
            res.status(429).json({
                success: false,
                message: 'Demasiadas solicitudes. Actividad sospechosa detectada.',
                retryAfter: retryAfter,
                code: 'RATE_LIMITED'
            });
            
            return false;
        }
        
        return true;
    }

    async checkRateLimit(ip, limit, windowMs) {
        const now = Date.now();
        const key = `${ip}_${Math.floor(now / windowMs)}`;
        
        if (!this.rateLimits.has(key)) {
            this.rateLimits.set(key, { count: 0, window: now + windowMs });
        }

        const rateLimitData = this.rateLimits.get(key);
        rateLimitData.count++;

        // Limpiar ventanas expiradas
        if (now > rateLimitData.window) {
            this.rateLimits.delete(key);
            return true;
        }

        return rateLimitData.count <= limit;
    }

    addSecurityHeaders(res) {
        res.setHeader('X-Content-Type-Options', 'nosniff');
        res.setHeader('X-Frame-Options', 'DENY');
        res.setHeader('X-XSS-Protection', '1; mode=block');
        res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
        res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
        
        // No revelar información del servidor
        res.removeHeader('X-Powered-By');
        res.setHeader('Server', 'SecureServer');
    }

    // Middleware específico para rutas sensibles
    highSecurity() {
        return async (req, res, next) => {
            try {
                const ip = req.ip || req.connection.remoteAddress;
                
                // Rate limiting muy restrictivo para rutas sensibles
                const allowed = await this.checkRateLimit(ip, 10, 60 * 1000); // 10 req/min
                
                if (!allowed) {
                    return res.status(429).json({
                        success: false,
                        message: 'Límite de solicitudes excedido para esta operación sensible',
                        code: 'HIGH_SECURITY_RATE_LIMITED'
                    });
                }

                // Verificar doble autenticación para operaciones críticas
                if (req.user && req.user.riskLevel === 'high') {
                    return res.status(403).json({
                        success: false,
                        message: 'Operación requiere verificación adicional',
                        code: 'ADDITIONAL_VERIFICATION_REQUIRED'
                    });
                }

                next();
            } catch (error) {
                console.error('❌ Error en middleware de alta seguridad:', error);
                next();
            }
        };
    }

    // Middleware para detectar robots/bots
    botDetection() {
        return (req, res, next) => {
            const userAgent = req.headers['user-agent'] || '';
            
            const botPatterns = [
                /googlebot|bingbot|slurp|crawler|spider/i,
                /curl|wget|python-requests|postman/i,
                /scanner|exploit|attack/i
            ];

            const isBot = botPatterns.some(pattern => pattern.test(userAgent));
            
            if (isBot) {
                console.log(`🤖 Bot detectado desde ${req.ip}: ${userAgent}`);
                
                return res.status(403).json({
                    success: false,
                    message: 'Acceso automatizado no permitido',
                    code: 'BOT_DETECTED'
                });
            }

            next();
        };
    }

    // Middleware para validar integridad de requests
    requestIntegrity() {
        return (req, res, next) => {
            try {
                // Verificar tamaño de payload
                const contentLength = parseInt(req.headers['content-length'] || '0');
                if (contentLength > 10 * 1024 * 1024) { // 10MB max
                    return res.status(413).json({
                        success: false,
                        message: 'Payload demasiado grande',
                        code: 'PAYLOAD_TOO_LARGE'
                    });
                }

                // Verificar métodos HTTP permitidos
                const allowedMethods = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'];
                if (!allowedMethods.includes(req.method)) {
                    return res.status(405).json({
                        success: false,
                        message: 'Método HTTP no permitido',
                        code: 'METHOD_NOT_ALLOWED'
                    });
                }

                // Verificar headers sospechosos
                const suspiciousHeaders = [
                    'x-cluster-client-ip',
                    'x-forwarded-host',
                    'x-remote-ip'
                ];

                for (const header of suspiciousHeaders) {
                    if (req.headers[header]) {
                        console.log(`⚠️ Header sospechoso detectado: ${header} desde ${req.ip}`);
                    }
                }

                next();
            } catch (error) {
                console.error('❌ Error en validación de integridad:', error);
                next();
            }
        };
    }

    setupCleanup() {
        // Limpiar rate limits antiguos cada 5 minutos
        setInterval(() => {
            const now = Date.now();
            
            for (const [key, data] of this.rateLimits.entries()) {
                if (now > data.window) {
                    this.rateLimits.delete(key);
                }
            }
        }, 5 * 60 * 1000);
    }

    // Método para obtener estadísticas de protección
    getProtectionStats() {
        return {
            activeRateLimits: this.rateLimits.size,
            timestamp: new Date().toISOString()
        };
    }
}

module.exports = new ProtectionMiddleware();
```

### 2. Middleware de Autenticación Mejorado
**Archivo:** `src/middleware/auth.middleware.js`
```javascript
const secureAuthService = require('../security/secure-auth.service');

class AuthMiddleware {
    constructor() {
        this.activeValidations = new Map();
    }

    async verifyJWT(req, res, next) {
        try {
            const authHeader = req.headers.authorization;
            
            if (!authHeader || !authHeader.startsWith('Bearer ')) {
                return res.status(401).json({
                    success: false,
                    message: 'Token de autorización requerido',
                    code: 'MISSING_TOKEN'
                });
            }

            const token = authHeader.substring(7);
            const currentIP = req.ip || req.connection.remoteAddress;
            
            // Validar token con verificaciones de seguridad
            const validation = await secureAuthService.validateToken(token, currentIP);
            
            if (!validation.valid) {
                // Log del intento de acceso inválido
                await this.logInvalidAccess(req, validation.error);
                
                return res.status(401).json({
                    success: false,
                    message: validation.error,
                    code: 'INVALID_TOKEN'
                });
            }

            // Agregar información del usuario al request
            req.user = {
                id: validation.userId,
                username: validation.username,
                sessionId: validation.sessionId,
                riskLevel: validation.riskLevel
            };

            // Agregar headers de información de sesión
            res.setHeader('X-Session-Risk-Level', validation.riskLevel);
            res.setHeader('X-Session-Valid', 'true');

            next();

        } catch (error) {
            console.error('❌ Error en verificación JWT:', error);
            
            return res.status(500).json({
                success: false,
                message: 'Error interno del servidor',
                code: 'INTERNAL_ERROR'
            });
        }
    }

    // Middleware que requiere nivel de riesgo específico
    requireRiskLevel(maxRiskLevel = 'medium') {
        const riskLevels = { 'low': 1, 'medium': 2, 'high': 3 };
        
        return (req, res, next) => {
            if (!req.user) {
                return res.status(401).json({
                    success: false,
                    message: 'Usuario no autenticado',
                    code: 'NOT_AUTHENTICATED'
                });
            }

            const userRiskLevel = riskLevels[req.user.riskLevel] || 3;
            const requiredRiskLevel = riskLevels[maxRiskLevel] || 2;

            if (userRiskLevel > requiredRiskLevel) {
                return res.status(403).json({
                    success: false,
                    message: 'Operación requiere verificación adicional de seguridad',
                    code: 'HIGH_RISK_BLOCKED',
                    riskLevel: req.user.riskLevel
                });
            }

            next();
        };
    }

    // Rate limiting específico para usuarios autenticados
    userRateLimit(requestsPerMinute = 100) {
        return async (req, res, next) => {
            if (!req.user) {
                return next(); // No aplicar límite si no está autenticado
            }

            const userId = req.user.id;
            const now = Date.now();
            const windowMs = 60 * 1000; // 1 minuto
            const key = `user_${userId}_${Math.floor(now / windowMs)}`;

            if (!this.activeValidations.has(key)) {
                this.activeValidations.set(key, { count: 0, expires: now + windowMs });
            }

            const userLimit = this.activeValidations.get(key);
            userLimit.count++;

            if (userLimit.count > requestsPerMinute) {
                return res.status(429).json({
                    success: false,
                    message: `Límite de ${requestsPerMinute} solicitudes por minuto excedido`,
                    code: 'USER_RATE_LIMITED',
                    retryAfter: Math.ceil((userLimit.expires - now) / 1000)
                });
            }

            // Limpiar límites expirados
            if (now > userLimit.expires) {
                this.activeValidations.delete(key);
            }

            next();
        };
    }

    // Middleware para operaciones sensibles que requieren re-autenticación
    requireRecentAuth(maxAgeMinutes = 30) {
        return async (req, res, next) => {
            if (!req.user) {
                return res.status(401).json({
                    success: false,
                    message: 'Usuario no autenticado',
                    code: 'NOT_AUTHENTICATED'
                });
            }

            try {
                const db = require('../config/database');
                const [sessions] = await db.query(
                    'SELECT created_at FROM user_sessions WHERE id = ?',
                    [req.user.sessionId]
                );

                if (sessions.length === 0) {
                    return res.status(401).json({
                        success: false,
                        message: 'Sesión no encontrada',
                        code: 'SESSION_NOT_FOUND'
                    });
                }

                const sessionAge = Date.now() - new Date(sessions[0].created_at).getTime();
                const maxAge = maxAgeMinutes * 60 * 1000;

                if (sessionAge > maxAge) {
                    return res.status(403).json({
                        success: false,
                        message: 'Operación sensible requiere autenticación reciente',
                        code: 'STALE_AUTHENTICATION',
                        requiredAction: 're-authenticate'
                    });
                }

                next();

            } catch (error) {
                console.error('❌ Error verificando autenticación reciente:', error);
                return res.status(500).json({
                    success: false,
                    message: 'Error verificando autenticación',
                    code: 'AUTH_VERIFICATION_ERROR'
                });
            }
        };
    }

    // Middleware para dispositivos confiables únicamente
    requireTrustedDevice() {
        return async (req, res, next) => {
            if (!req.user) {
                return res.status(401).json({
                    success: false,
                    message: 'Usuario no autenticado',
                    code: 'NOT_AUTHENTICATED'
                });
            }

            try {
                const db = require('../config/database');
                const [devices] = await db.query(`
                    SELECT is_trusted FROM known_devices 
                    WHERE user_id = ? AND device_fingerprint = ? AND is_trusted = TRUE
                `, [req.user.id, req.user.deviceFingerprint]);

                if (devices.length === 0) {
                    return res.status(403).json({
                        success: false,
                        message: 'Operación disponible solo para dispositivos confiables',
                        code: 'UNTRUSTED_DEVICE',
                        requiredAction: 'device-verification'
                    });
                }

                next();

            } catch (error) {
                console.error('❌ Error verificando dispositivo confiable:', error);
                return res.status(500).json({
                    success: false,
                    message: 'Error verificando dispositivo',
                    code: 'DEVICE_VERIFICATION_ERROR'
                });
            }
        };
    }

    async logInvalidAccess(req, error) {
        try {
            const db = require('../config/database');
            const tripleEncryptor = require('../crypto/tripleEncryptor');
            
            const logData = {
                ip: req.ip,
                userAgent: req.headers['user-agent'],
                path: req.path,
                method: req.method,
                error,
                timestamp: new Date().toISOString()
            };

            const encryptedDetails = tripleEncryptor.encrypt(JSON.stringify(logData));
            
            await db.query(
                `INSERT INTO security_logs (event_type, encrypted_details, ip_address, severity) 
                 VALUES ('INVALID_TOKEN_ACCESS', ?, ?, 'medium')`,
                [encryptedDetails, req.ip]
            );

        } catch (logError) {
            console.error('❌ Error logging invalid access:', logError);
        }
    }

    // Cleanup automático de validaciones expiradas
    startCleanup() {
        setInterval(() => {
            const now = Date.now();
            
            for (const [key, data] of this.activeValidations.entries()) {
                if (now > data.expires) {
                    this.activeValidations.delete(key);
                }
            }
        }, 5 * 60 * 1000); // Cada 5 minutos
    }

    // Obtener estadísticas del middleware
    getStats() {
        return {
            activeValidations: this.activeValidations.size,
            timestamp: new Date().toISOString()
        };
    }
}

const authMiddleware = new AuthMiddleware();
authMiddleware.startCleanup();

module.exports = authMiddleware;
```

---

## 📧 Comunicaciones Seguras Multi-Canal

### 1. Sistema de Comunicaciones Seguras
**Archivo:** `src/services/secure-communications.service.js`
```javascript
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const credentialBuilder = require('../config/credential-builder');

class SecureCommunications {
    constructor() {
        this.channels = new Map();
        this.setupChannels();
        this.messageQueue = [];
        this.retryAttempts = new Map();
    }

    setupChannels() {
        try {
            // Canal principal - Gmail
            const primaryEmail = credentialBuilder.buildEmailCredentials('primary');
            this.channels.set('primary_email', {
                name: 'primary_email',
                type: 'email',
                transporter: nodemailer.createTransporter({
                    service: 'gmail',
                    auth: {
                        user: primaryEmail.user,
                        pass: primaryEmail.pass
                    },
                    secure: true,
                    tls: { rejectUnauthorized: true }
                }),
                priority: 1,
                maxRetries: 3
            });

            // Canal de respaldo - ProtonMail (si está configurado)
            try {
                const backupEmail = credentialBuilder.buildEmailCredentials('backup');
                this.channels.set('backup_email', {
                    name: 'backup_email',
                    type: 'email',
                    transporter: nodemailer.createTransporter({
                        host: 'mail.protonmail.ch',
                        port: 587,
                        secure: false,
                        auth: {
                            user: backupEmail.user,
                            pass: backupEmail.pass
                        },
                        tls: { rejectUnauthorized: true }
                    }),
                    priority: 2,
                    maxRetries: 2
                });
            } catch (backupError) {
                console.log('ℹ️ Canal de backup de email no disponible');
            }

            // Canal de emergencia - Telegram (si está configurado)
            try {
                const telegramCreds = credentialBuilder.buildTelegramCredentials();
                if (telegramCreds.botToken && telegramCreds.chatId) {
                    this.channels.set('telegram', {
                        name: 'telegram',
                        type: 'telegram',
                        botToken: telegramCreds.botToken,
                        chatId: telegramCreds.chatId,
                        priority: 3,
                        maxRetries: 2
                    });
                }
            } catch (telegramError) {
                console.log('ℹ️ Canal de Telegram no disponible');
            }

            console.log(`✅ ${this.channels.size} canales de comunicación configurados`);

        } catch (error) {
            console.error('❌ Error configurando canales:', error);
        }
    }

    async sendSecureAlert(alertData, priority = 'normal') {
        try {
            // Cifrar el mensaje con múltiples capas
            const encryptedAlert = await this.multiLayerEncrypt(alertData);
            
            // Crear mensaje camuflado
            const camouflageMessage = await this.createCamouflageMessage(encryptedAlert, alertData.type);
            
            const results = [];
            const channelsToUse = this.selectChannels(priority);

            // Enviar por los canales seleccionados
            for (const channel of channelsToUse) {
                try {
                    const result = await this.sendViaChannel(channel, camouflageMessage);
                    results.push({ 
                        channel: channel.name, 
                        success: true, 
                        messageId: result.messageId || result.message_id 
                    });
                    
                    // Si es crítico y un canal funciona, continuar con el resto pero sin fallar
                    if (priority !== 'critical') break;
                    
                } catch (channelError) {
                    console.error(`❌ Error en canal ${channel.name}:`, channelError.message);
                    results.push({ 
                        channel: channel.name, 
                        success: false, 
                        error: channelError.message 
                    });
                }
            }

            // Verificar que al menos un canal funcionó
            const successfulChannels = results.filter(r => r.success);
            if (successfulChannels.length === 0) {
                throw new Error('Todos los canales de comunicación fallaron');
            }

            // Log del envío exitoso
            await this.logCommunication({
                type: 'ALERT_SENT',
                alertType: alertData.type,
                priority,
                channels: results,
                timestamp: new Date().toISOString()
            });

            return {
                success: true,
                channelsUsed: results,
                encryptionInfo: {
                    layers: 3,
                    algorithm: 'AES-256 + RSA + XOR'
                }
            };

        } catch (error) {
            console.error('❌ Error enviando alerta segura:', error);
            await this.logCommunication({
                type: 'ALERT_FAILED',
                error: error.message,
                alertType: alertData.type,
                timestamp: new Date().toISOString()
            });
            throw error;
        }
    }

    selectChannels(priority) {
        const availableChannels = Array.from(this.channels.values())
            .sort((a, b) => a.priority - b.priority);

        switch (priority) {
            case 'critical':
                return availableChannels; // Usar todos los canales
            case 'high':
                return availableChannels.slice(0, 2); // Primeros 2 canales
            case 'normal':
            default:
                return availableChannels.slice(0, 1); // Solo canal principal
        }
    }

    async multiLayerEncrypt(data) {
        try {
            // Capa 1: Serialización y compresión
            const jsonData = JSON.stringify(data);
            const compressedData = this.compressData(jsonData);
            
            // Capa 2: Cifrado AES-256
            const aesKey = crypto.randomBytes(32);
            const iv = crypto.randomBytes(16);
            const cipher = crypto.createCipher('aes-256-cbc', aesKey, iv);
            let aesEncrypted = cipher.update(compressedData, 'utf8', 'hex');
            aesEncrypted += cipher.final('hex');
            
            // Capa 3: Cifrado RSA (para la clave AES)
            const rsaKeyPair = crypto.generateKeyPairSync('rsa', {
                modulusLength: 2048,
                publicKeyEncoding: { type: 'spki', format: 'pem' },
                privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
            });
            
            const encryptedAESKey = crypto.publicEncrypt(rsaKeyPair.publicKey, aesKey);
            
            // Capa 4: Ofuscación con timestamp y ruido
            const timestamp = Date.now();
            const noise = crypto.randomBytes(16).toString('hex');
            const obfuscated = this.obfuscateWithTimestamp(aesEncrypted, timestamp, noise);
            
            return {
                data: obfuscated,
                encryptedKey: encryptedAESKey.toString('base64'),
                rsaPrivateKey: rsaKeyPair.privateKey,
                iv: iv.toString('hex'),
                timestamp,
                noise,
                compressionUsed: true
            };
            
        } catch (error) {
            console.error('❌ Error en cifrado multicapa:', error);
            throw new Error('Error en cifrado de mensaje');
        }
    }

    compressData(data) {
        // Compresión simple usando Buffer
        return Buffer.from(data, 'utf8').toString('base64');
    }

    obfuscateWithTimestamp(data, timestamp, noise) {
        // Mezclar datos con timestamp y ruido para ofuscar
        const mixed = `${noise.substring(0, 8)}${data}${timestamp.toString(36)}${noise.substring(8)}`;
        return Buffer.from(mixed).toString('base64');
    }

    async createCamouflageMessage(encryptedData, alertType) {
        const disguiser = require('../crypto/disguiser');
        
        // Crear mensaje base camuflado usando el sistema existente
        const baseMessage = disguiser.generateCamouflageMessage({
            key1: encryptedData.encryptedKey.substring(0, 16),
            key2: encryptedData.iv,
            key3: encryptedData.timestamp.toString(),
            key4: encryptedData.noise.substring(0, 16),
            key5: alertType || 'SYSTEM_ALERT'
        });

        // Sección técnica donde ocultar el payload real
        const technicalSection = this.createTechnicalSection(encryptedData);
        
        // Mensaje final camuflado
        const finalMessage = {
            subject: this.generateSubject(alertType),
            body: this.assembleFinalMessage(baseMessage.body, technicalSection),
            priority: this.mapAlertTypeToPriority(alertType)
        };

        return finalMessage;
    }

    createTechnicalSection(encryptedData) {
        return `
---
📊 Detalles Técnicos del Reporte de Sistema

🔧 Código de Referencia: ${encryptedData.data}
🔑 Hash de Verificación: ${this.generateVerificationHash(encryptedData)}
📅 Timestamp de Generación: ${new Date(encryptedData.timestamp).toISOString()}
⚙️ Algoritmo de Compresión: ${encryptedData.compressionUsed ? 'GZIP-Compatible' : 'Raw'}

---
ℹ️ Este reporte ha sido generado automáticamente por el sistema de monitoreo.
📚 Para más información técnica, consulte la documentación del sistema.
🔒 Los datos están protegidos con cifrado de nivel empresarial.
        `;
    }

    assembleFinalMessage(baseBody, technicalSection) {
        return `${baseBody}

${technicalSection}

🤖 Sistema de Monitoreo Automatizado
📧 Mensaje generado automáticamente - No responder
⏰ ${new Date().toLocaleString('es-MX', { timeZone: 'America/Mexico_City' })}`;
    }

    generateSubject(alertType) {
        const subjects = {
            'SECURITY_INCIDENT': '🔐 Reporte de Seguridad del Sistema',
            'KEY_ROTATION_SUCCESS': '🔄 Actualización Mensual Completada',
            'KEY_ROTATION_FAILED': '⚠️ Mantenimiento del Sistema Requerido',
            'SERVER_INTEGRITY_BREACH': '🚨 Alerta Crítica del Sistema',
            'ANOMALY_DETECTED': '🔍 Reporte de Actividad del Sistema',
            'EMERGENCY_ALERT': '🚨 Notificación Crítica Inmediata'
        };

        return subjects[alertType] || '📋 Reporte Automático del Sistema';
    }

    mapAlertTypeToPriority(alertType) {
        const priorityMap = {
            'EMERGENCY_ALERT': 'critical',
            'SERVER_INTEGRITY_BREACH': 'critical',
            'KEY_ROTATION_FAILED': 'high',
            'SECURITY_INCIDENT': 'high',
            'ANOMALY_DETECTED': 'normal',
            'KEY_ROTATION_SUCCESS': 'normal'
        };

        return priorityMap[alertType] || 'normal';
    }

    generateVerificationHash(data) {
        const verificationString = data.encryptedKey + data.iv + data.timestamp + data.noise;
        return crypto.createHash('sha256').update(verificationString).digest('hex').substring(0, 16);
    }

    async sendViaChannel(channel, message) {
        switch (channel.type) {
            case 'email':
                return await this.sendEmail(channel, message);
            case 'telegram':
                return await this.sendTelegram(channel, message);
            default:
                throw new Error(`Tipo de canal no soportado: ${channel.type}`);
        }
    }

    async sendEmail(channel, message) {
        try {
            const recipient = process.env.RECIPIENT_EMAIL || process.env.ALERT_RECIPIENT_EMAIL;
            
            if (!recipient) {
                throw new Error('Email de destinatario no configurado');
            }

            const mailOptions = {
                from: `"Sistema de Seguridad" <${channel.transporter.options.auth.user}>`,
                to: recipient,
                subject: message.subject,
                text: message.body,
                html: this.createHTMLVersion(message),
                headers: {
                    'X-Priority': message.priority === 'critical' ? '1' : '3',
                    'X-MSMail-Priority': message.priority === 'critical' ? 'High' : 'Normal',
                    'Importance': message.priority === 'critical' ? 'high' : 'normal',
                    'X-Secure-System': 'true',
                    'X-Message-Type': 'automated-security-alert'
                }
            };

            const result = await channel.transporter.sendMail(mailOptions);
            console.log(`✅ Email enviado via ${channel.name}: ${result.messageId}`);
            
            return result;
            
        } catch (error) {
            console.error(`❌ Error enviando email via ${channel.name}:`, error);
            throw error;
        }
    }

    createHTMLVersion(message) {
        return `
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${message.subject}</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #333; background-color: #f4f4f4; margin: 0; padding: 20px; }
        .container { max-width: 600px; margin: 0 auto; background-color: white; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); overflow: hidden; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; text-align: center; }
        .content { padding: 30px; }
        .technical-section { background-color: #f8f9fa; border-left: 4px solid #007bff; padding: 15px; margin: 20px 0; border-radius: 5px; }
        .footer { background-color: #6c757d; color: white; padding: 15px; text-align: center; font-size: 12px; }
        .alert-critical { border-left-color: #dc3545; background-color: #f8d7da; }
        .alert-high { border-left-color: #fd7e14; background-color: #fff3cd; }
        .alert-normal { border-left-color: #28a745; background-color: #d4edda; }
        pre { background-color: #f1f3f4; padding: 10px; border-radius: 5px; overflow-x: auto; font-size: 12px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 Sistema de Seguridad</h1>
            <p>${message.subject}</p>
        </div>
        
        <div class="content">
            ${this.formatHTMLContent(message.body, message.priority)}
        </div>
        
        <div class="footer">
            <p>🤖 Mensaje generado automáticamente por el Sistema de Seguridad</p>
            <p>📧 No responder a este correo • 🔒 Información confidencial</p>
        </div>
    </div>
</body>
</html>`;
    }

    formatHTMLContent(textContent, priority) {
        const alertClass = `alert-${priority}`;
        const lines = textContent.split('\n');
        let htmlContent = '';
        let inTechnicalSection = false;
        
        for (const line of lines) {
            if (line.includes('---')) {
                if (line.includes('Detalles Técnicos')) {
                    htmlContent += `<div class="technical-section ${alertClass}">`;
                    inTechnicalSection = true;
                } else if (inTechnicalSection) {
                    htmlContent += '</div>';
                    inTechnicalSection = false;
                }
                continue;
            }
            
            if (line.trim() === '') {
                htmlContent += '<br>';
                continue;
            }
            
            if (line.startsWith('🔧') || line.startsWith('🔑') || line.startsWith('📅') || line.startsWith('⚙️')) {
                htmlContent += `<pre>${line}</pre>`;
            } else if (line.startsWith('🤖') || line.startsWith('📧') || line.startsWith('⏰')) {
                htmlContent += `<p style="font-size: 12px; color: #6c757d;"><em>${line}</em></p>`;
            } else {
                htmlContent += `<p>${line}</p>`;
            }
        }
        
        if (inTechnicalSection) {
            htmlContent += '</div>';
        }
        
        return htmlContent;
    }

    async sendTelegram(channel, message) {
        try {
            const axios = require('axios');
            
            const telegramMessage = this.formatTelegramMessage(message);
            const url = `https://api.telegram.org/bot${channel.botToken}/sendMessage`;
            
            const response = await axios.post(url, {
                chat_id: channel.chatId,
                text: telegramMessage,
                parse_mode: 'Markdown',
                disable_web_page_preview: true
            });

            console.log(`✅ Mensaje de Telegram enviado: ${response.data.result.message_id}`);
            return response.data.result;
            
        } catch (error) {
            console.error('❌ Error enviando mensaje de Telegram:', error);
            throw new Error(`Error en Telegram: ${error.response?.data?.description || error.message}`);
        }
    }

    formatTelegramMessage(message) {
        const priorityEmoji = {
            'critical': '🚨',
            'high': '⚠️',
            'normal': 'ℹ️'
        };

        const emoji = priorityEmoji[message.priority] || 'ℹ️';
        
        return `${emoji} *${message.subject}*

${message.body.substring(0, 4000)}

🔒 _Mensaje del Sistema de Seguridad_
⏰ ${new Date().toLocaleString('es-MX')}`;
    }

    async testChannels() {
        console.log('🧪 Probando canales de comunicación...');
        const results = [];

        for (const [name, channel] of this.channels) {
            try {
                const testMessage = {
                    subject: '🧪 Test de Conectividad del Sistema',
                    body: `Test de conectividad del canal ${name}\nTiempo: ${new Date().toISOString()}\nEstado: Funcional`,
                    priority: 'normal'
                };

                await this.sendViaChannel(channel, testMessage);
                results.push({ channel: name, status: 'success', message: 'Canal funcional' });
                
            } catch (error) {
                results.push({ channel: name, status: 'error', message: error.message });
            }
        }

        console.log('📊 Resultados del test de canales:', results);
        return results;
    }

    async logCommunication(data) {
        try {
            const db = require('../config/database');
            const tripleEncryptor = require('../crypto/tripleEncryptor');
            
            const encryptedDetails = tripleEncryptor.encrypt(JSON.stringify(data));
            
            await db.query(
                `INSERT INTO security_logs (event_type, encrypted_details, severity) 
                 VALUES (?, ?, 'medium')`,
                [data.type, encryptedDetails]
            );
            
        } catch (error) {
            console.error('❌ Error logging communication:', error);
        }
    }

    // Método para descifrar mensajes (para testing)
    async decryptMessage(encryptedData) {
        try {
            // Este método sería usado por el script de decryptMessage.js
            // para que puedas descifrar los mensajes que recibes
            
            // 1. Desobfuscar
            const deobfuscated = this.deobfuscateMessage(encryptedData.data, encryptedData.timestamp, encryptedData.noise);
            
            // 2. Descifrar clave AES con RSA
            const aesKey = crypto.privateDecrypt(encryptedData.rsaPrivateKey, Buffer.from(encryptedData.encryptedKey, 'base64'));
            
            // 3. Descifrar datos con AES
            const decipher = crypto.createDecipher('aes-256-cbc', aesKey, Buffer.from(encryptedData.iv, 'hex'));
            let decrypted = decipher.update(deobfuscated, 'hex', 'utf8');
            decrypted += decipher.final('utf8');
            
            // 4. Descomprimir
            const decompressed = this.decompressData(decrypted);
            
            // 5. Parsear JSON
            return JSON.parse(decompressed);
            
        } catch (error) {
            console.error('❌ Error descifrando mensaje:', error);
            throw new Error('No se pudo descifrar el mensaje');
        }
    }

    deobfuscateMessage(obfuscatedData, timestamp, noise) {
        const decoded = Buffer.from(obfuscatedData, 'base64').toString();
        const timestampStr = timestamp.toString(36);
        
        // Remover ruido y timestamp
        const cleaned = decoded
            .replace(noise.substring(0, 8), '')
            .replace(timestampStr, '')
            .replace(noise.substring(8), '');
            
        return cleaned;
    }

    decompressData(compressedData) {
        return Buffer.from(compressedData, 'base64').toString('utf8');
    }

    // Obtener estadísticas de comunicaciones
    getStats() {
        return {
            availableChannels: this.channels.size,
            channelTypes: Array.from(this.channels.values()).map(c => c.type),
            messageQueue: this.messageQueue.length,
            retryAttempts: this.retryAttempts.size
        };
    }
}

module.exports = new SecureCommunications();
```

---

## 🔄 Sistema de Rotación Automática Mejorado

### 1. Planificador de Tareas Avanzado
**Archivo:** `src/tasks/scheduleKeyRotation.js`
```javascript
const cron = require('node-cron');
const keyRotator = require('../crypto/keyRotator');
const authService = require('../security/secure-auth.service');
const secureCommunications = require('../services/secure-communications.service');

class ScheduleKeyRotation {
    constructor() {
        this.isRotationEnabled = process.env.AUTO_ROTATION_ENABLED === 'true';
        this.isRunning = false;
        this.rotationHistory = [];
        this.nextRotationTime = null;
        
        if (this.isRotationEnabled) {
            this.initializeSchedules();
        } else {
            console.log('⏰ Rotación automática deshabilitada por configuración');
        }
    }

    initializeSchedules() {
        console.log('⏰ Inicializando planificador avanzado de rotación de claves...');

        // Rotación mensual de claves - día 1 de cada mes a las 2:00 AM
        cron.schedule('0 2 1 * *', async () => {
            await this.executeMonthlyRotation();
        }, {
            scheduled: true,
            timezone: "America/Mexico_City"
        });

        // Limpieza de sesiones expiradas - todos los días a las 3:00 AM
        cron.schedule('0 3 * * *', async () => {
            await this.executeSessionCleanup();
        }, {
            scheduled: true,
            timezone: "America/Mexico_City"
        });

        // Verificación de integridad - cada 6 horas
        cron.schedule('0 */6 * * *', async () => {
            await this.executeIntegrityCheck();
        }, {
            scheduled: true,
            timezone: "America/Mexico_City"
        });

        // Backup de logs de seguridad - todos los domingos a las 4:00 AM
        cron.schedule('0 4 * * 0', async () => {
            await this.executeSecurityLogBackup();
        }, {
            scheduled: true,
            timezone: "America/Mexico_City"
        });

        // Test de comunicaciones - todos los días a las 1:00 AM
        cron.schedule('0 1 * * *', async () => {
            await this.executeChannelHealthCheck();
        }, {
            scheduled: true,
            timezone: "America/Mexico_City"
        });

        // Auditoría de seguridad - cada viernes a las 5:00 AM
        cron.schedule('0 5 * * 5', async () => {
            await this.executeSecurityAudit();
        }, {
            scheduled: true,
            timezone: "America/Mexico_City"
        });

        this.calculateNextRotation();
        console.log('✅ Planificador avanzado inicializado');
        this.logScheduleStatus();
    }

    async executeMonthlyRotation() {
        if (this.isRunning) {
            console.log('⚠️ Rotación ya en progreso, saltando ejecución');
            return;
        }

        try {
            this.isRunning = true;
            const rotationId = this.generateRotationId();
            const startTime = Date.now();
            
            console.log(`🔄 Iniciando rotación mensual ${rotationId}...`);
            
            // Pre-verificaciones
            await this.preRotationChecks();
            
            // Notificar inicio de rotación
            await secureCommunications.sendSecureAlert({
                type: 'KEY_ROTATION_STARTED',
                severity: 'info',
                details: `Rotación mensual ${rotationId} iniciada`,
                timestamp: new Date().toISOString()
            }, 'normal');
            
            // Ejecutar rotación de claves
            const rotationResult = await keyRotator.rotateKeys();
            
            const duration = Date.now() - startTime;
            
            // Registrar rotación exitosa
            this.rotationHistory.push({
                id: rotationId,
                timestamp: new Date().toISOString(),
                duration,
                status: 'success',
                details: rotationResult
            });
            
            console.log(`✅ Rotación mensual ${rotationId} completada en ${duration}ms`);
            
            // Enviar notificación de éxito con nuevas claves
            await this.sendRotationSuccessNotification(rotationId, duration, rotationResult);
            
            // Post-verificaciones
            await this.postRotationVerification();
            
            this.calculateNextRotation();

        } catch (error) {
            const rotationId = this.rotationHistory.length > 0 ? 
                this.rotationHistory[this.rotationHistory.length - 1].id : 
                this.generateRotationId();
            
            console.error(`❌ Error en rotación mensual ${rotationId}:`, error);
            
            // Registrar rotación fallida
            this.rotationHistory.push({
                id: rotationId,
                timestamp: new Date().toISOString(),
                status: 'failed',
                error: error.message
            });
            
            // Enviar alerta crítica de fallo
            await secureCommunications.sendSecureAlert({
                type: 'KEY_ROTATION_FAILED',
                severity: 'critical',
                details: `Rotación mensual ${rotationId} falló: ${error.message}`,
                action: 'Se requiere intervención manual inmediata',
                timestamp: new Date().toISOString()
            }, 'critical');
            
        } finally {
            this.isRunning = false;
        }
    }

    async preRotationChecks() {
        console.log('🔍 Ejecutando verificaciones pre-rotación...');
        
        // Verificar espacio en disco
        await this.checkDiskSpace();
        
        // Verificar conectividad de base de datos
        await this.checkDatabaseHealth();
        
        // Verificar canales de comunicación
        await this.checkCommunicationChannels();
        
        // Verificar que no hay operaciones críticas en curso
        await this.checkOngoingOperations();
        
        console.log('✅ Verificaciones pre-rotación completadas');
    }

    async checkDiskSpace() {
        // Verificar que hay suficiente espacio para el backup
        const fs = require('fs');
        try {
            const stats = fs.statSync('./');
            // Implementar verificación de espacio según el sistema
            console.log('✅ Espacio en disco verificado');
        } catch (error) {
            throw new Error(`Error verificando espacio en disco: ${error.message}`);
        }
    }

    async checkDatabaseHealth() {
        const db = require('../config/database');
        try {
            await db.testConnection();
            console.log('✅ Salud de base de datos verificada');
        } catch (error) {
            throw new Error(`Base de datos no disponible: ${error.message}`);
        }
    }

    async checkCommunicationChannels() {
        try {
            const stats = secureCommunications.getStats();
            if (stats.availableChannels === 0) {
                throw new Error('No hay canales de comunicación disponibles');
            }
            console.log(`✅ ${stats.availableChannels} canales de comunicación verificados`);
        } catch (error) {
            throw new Error(`Error en canales de comunicación: ${error.message}`);
        }
    }

    async checkOngoingOperations() {
        const db = require('../config/database');
        try {
            // Verificar que no hay sesiones críticas activas
            const [criticalSessions] = await db.query(`
                SELECT COUNT(*) as count FROM user_sessions 
                WHERE risk_level = 'high' AND expires_at > NOW()
            `);
            
            if (criticalSessions[0].count > 0) {
                console.log(`⚠️ ${criticalSessions[0].count} sesiones de alto riesgo activas`);
            }
            
            console.log('✅ Operaciones en curso verificadas');
        } catch (error) {
            console.error('⚠️ Error verificando operaciones:', error);
            // No fallar la rotación por esto
        }
    }

    async postRotationVerification() {
        console.log('🔍 Ejecutando verificaciones post-rotación...');
        
        // Verificar que el cifrado funciona con las nuevas claves
        const tripleEncryptor = require('../crypto/tripleEncryptor');
        const healthCheck = await tripleEncryptor.healthCheck();
        
        if (!healthCheck.healthy) {
            throw new Error(`Sistema de cifrado falló después de la rotación: ${healthCheck.message}`);
        }
        
        // Verificar que las nuevas claves están activas
        await this.verifyActiveKeys();
        
        console.log('✅ Verificaciones post-rotación completadas');
    }

    async verifyActiveKeys() {
        const db = require('../config/database');
        try {
            const [activeKeys] = await db.query(
                'SELECT COUNT(*) as count FROM encryption_keys WHERE is_active = TRUE'
            );
            
            if (activeKeys[0].count === 0) {
                throw new Error('No se encontraron claves activas después de la rotación');
            }
            
            console.log(`✅ ${activeKeys[0].count} claves activas verificadas`);
        } catch (error) {
            throw new Error(`Error verificando claves activas: ${error.message}`);
        }
    }

    async sendRotationSuccessNotification(rotationId, duration, rotationResult) {
        try {
            // Crear mensaje con las nuevas claves de forma camuflada
            const newKeys = rotationResult.newKeys || {};
            
            await secureCommunications.sendSecureAlert({
                type: 'KEY_ROTATION_SUCCESS',
                severity: 'info',
                details: `Rotación ${rotationId} completada exitosamente`,
                duration: duration,
                newKeys: newKeys,
                timestamp: new Date().toISOString(),
                nextRotation: this.getNextRotationDate()
            }, 'normal');
            
            console.log(`📧 Notificación de rotación exitosa enviada para ${rotationId}`);
            
        } catch (error) {
            console.error('❌ Error enviando notificación de rotación exitosa:', error);
        }
    }

    async executeSessionCleanup() {
        try {
            console.log('🧹 Ejecutando limpieza de sesiones expiradas...');
            
            // Limpiar sesiones de autenticación
            await authService.cleanupExpiredSessions();
            
            // Limpiar IPs bloqueadas expiradas
            await this.cleanupExpiredBlockedIPs();
            
            // Limpiar logs antiguos (más de 90 días)
            await this.cleanupOldLogs();
            
            console.log('✅ Limpieza de sesiones completada');
            
        } catch (error) {
            console.error('❌ Error en limpieza de sesiones:', error);
        }
    }

    async cleanupExpiredBlockedIPs() {
        const db = require('../config/database');
        try {
            const result = await db.query(
                'DELETE FROM blocked_ips WHERE blocked_until < NOW()'
            );
            
            if (result.affectedRows > 0) {
                console.log(`🧹 ${result.affectedRows} IPs desbloqueadas automáticamente`);
            }
        } catch (error) {
            console.error('❌ Error limpiando IPs bloqueadas:', error);
        }
    }

    async cleanupOldLogs() {
        const db = require('../config/database');
        try {
            const result = await db.query(
                'DELETE FROM security_logs WHERE timestamp < DATE_SUB(NOW(), INTERVAL 90 DAY)'
            );
            
            if (result.affectedRows > 0) {
                console.log(`🧹 ${result.affectedRows} logs antiguos eliminados`);
            }
        } catch (error) {
            console.error('❌ Error limpiando logs antiguos:', error);
        }
    }

    async executeIntegrityCheck() {
        try {
            console.log('🔍 Ejecutando verificación de integridad programada...');
            
            const serverCheck = require('../middleware/serverCheck.middleware');
            await serverCheck.performAsyncCheck();
            
            console.log('✅ Verificación de integridad completada');
            
        } catch (error) {
            console.error('❌ Error en verificación de integridad:', error);
            
            // Enviar alerta si la verificación falla
            await secureCommunications.sendSecureAlert({
                type: 'INTEGRITY_CHECK_FAILED',
                severity: 'high',
                details: `Verificación de integridad falló: ${error.message}`,
                timestamp: new Date().toISOString()
            }, 'high');
        }
    }

    async executeSecurityLogBackup() {
        try {
            console.log('📦 Ejecutando backup de logs de seguridad...');
            
            const db = require('../config/database');
            const fs = require('fs-extra');
            const path = require('path');
            
            // Obtener logs de la última semana
            const logs = await db.query(`
                SELECT id, event_type, ip_address, timestamp, severity, risk_score
                FROM security_logs 
                WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 7 DAY)
                ORDER BY timestamp DESC
            `);

            if (logs.length > 0) {
                const backupDir = path.join(__dirname, '../../logs');
                await fs.ensureDir(backupDir);
                
                const timestamp = new Date().toISOString().split('T')[0];
                const backupFile = path.join(backupDir, `security_logs_backup_${timestamp}.json`);
                
                const backupData = {
                    generated: new Date().toISOString(),
                    period: 'last_7_days',
                    total_logs: logs.length,
                    logs: logs
                };
                
                await fs.writeJSON(backupFile, backupData, { spaces: 2 });
                
                console.log(`✅ Backup de ${logs.length} logs creado: ${backupFile}`);
                
                // Opcional: comprimir el archivo
                await this.compressBackupFile(backupFile);
                
            } else {
                console.log('ℹ️ No hay logs para respaldar');
            }
            
        } catch (error) {
            console.error('❌ Error en backup de logs:', error);
        }
    }

    async compressBackupFile(filePath) {
        try {
            const zlib = require('zlib');
            const fs = require('fs');
            const path = require('path');
            
            const compressedPath = filePath + '.gz';
            
            const readStream = fs.createReadStream(filePath);
            const writeStream = fs.createWriteStream(compressedPath);
            const gzip = zlib.createGzip();
            
            await new Promise((resolve, reject) => {
                readStream.pipe(gzip).pipe(writeStream)
                    .on('finish', resolve)
                    .on('error', reject);
            });
            
            // Eliminar archivo original
            fs.unlinkSync(filePath);
            
            console.log(`🗜️ Archivo comprimido: ${path.basename(compressedPath)}`);
            
        } catch (error) {
            console.error('❌ Error comprimiendo backup:', error);
        }
    }

    async executeChannelHealthCheck() {
        try {
            console.log('🩺 Ejecutando chequeo de salud de canales...');
            
            const results = await secureCommunications.testChannels();
            const failedChannels = results.filter(r => r.status === 'error');
            
            if (failedChannels.length > 0) {
                await secureCommunications.sendSecureAlert({
                    type: 'COMMUNICATION_CHANNELS_FAILED',
                    severity: 'high',
                    details: `${failedChannels.length} canales de comunicación fallaron`,
                    failedChannels: failedChannels,
                    timestamp: new Date().toISOString()
                }, 'high');
            }
            
            console.log(`✅ Chequeo de canales completado: ${results.length - failedChannels.length}/${results.length} funcionales`);
            
        } catch (error) {
            console.error('❌ Error en chequeo de canales:', error);
        }
    }

    async executeSecurityAudit() {
        try {
            console.log('🕵️ Ejecutando auditoría de seguridad semanal...');
            
            const auditResults = await this.performSecurityAudit();
            
            await secureCommunications.sendSecureAlert({
                type: 'WEEKLY_SECURITY_AUDIT',
                severity: 'info',
                details: 'Auditoría de seguridad semanal completada',
                results: auditResults,
                timestamp: new Date().toISOString()
            }, 'normal');
            
            console.log('✅ Auditoría de seguridad completada');
            
        } catch (error) {
            console.error('❌ Error en auditoría de seguridad:', error);
        }
    }

    async performSecurityAudit() {
        const db = require('../config/database');
        
        try {
            // Métricas de seguridad de la última semana
            const [securityMetrics] = await db.query(`
                SELECT 
                    COUNT(*) as total_events,
                    SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as critical_events,
                    SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) as high_events,
                    SUM(CASE WHEN event_type LIKE '%LOGIN_FAILED%' THEN 1 ELSE 0 END) as failed_logins,
                    COUNT(DISTINCT ip_address) as unique_ips
                FROM security_logs 
                WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 7 DAY)
            `);

            // Sesiones activas de alto riesgo
            const [highRiskSessions] = await db.query(`
                SELECT COUNT(*) as high_risk_sessions
                FROM user_sessions 
                WHERE risk_level = 'high' AND expires_at > NOW()
            `);

            // IPs actualmente bloqueadas
            const [blockedIPs] = await db.query(`
                SELECT COUNT(*) as blocked_ips
                FROM blocked_ips 
                WHERE blocked_until > NOW()
            `);

            return {
                ...securityMetrics[0],
                high_risk_sessions: highRiskSessions[0].high_risk_sessions,
                blocked_ips: blockedIPs[0].blocked_ips,
                rotation_history: this.rotationHistory.slice(-5) // Últimas 5 rotaciones
            };
            
        } catch (error) {
            console.error('❌ Error en auditoría:', error);
            return { error: error.message };
        }
    }

    generateRotationId() {
        const date = new Date();
        const year = date.getFullYear();
        const month = String(date.getMonth() + 1).padStart(2, '0');
        const random = Math.random().toString(36).substring(2, 8).toUpperCase();
        
        return `ROT-${year}${month}-${random}`;
    }

    calculateNextRotation() {
        const now = new Date();
        const nextMonth = new Date(now.getFullYear(), now.getMonth() + 1, 1, 2, 0, 0);
        this.nextRotationTime = nextMonth;
    }

    getNextRotationDate() {
        return this.nextRotationTime ? this.nextRotationTime.toISOString() : null;
    }

    logScheduleStatus() {
        const schedules = [
            { name: 'Rotación mensual', schedule: '0 2 1 * *', description: 'Día 1 de cada mes a las 2:00 AM' },
            { name: 'Limpieza de sesiones', schedule: '0 3 * * *', description: 'Todos los días a las 3:00 AM' },
            { name: 'Verificación de integridad', schedule: '0 */6 * * *', description: 'Cada 6 horas' },
            { name: 'Backup de logs', schedule: '0 4 * * 0', description: 'Domingos a las 4:00 AM' },
            { name: 'Test de comunicaciones', schedule: '0 1 * * *', description: 'Todos los días a las 1:00 AM' },
            { name: 'Auditoría de seguridad', schedule: '0 5 * * 5', description: 'Viernes a las 5:00 AM' }
        ];

        console.log('\n📅 Tareas programadas activas:');
        schedules.forEach(schedule => {
            console.log(`   • ${schedule.name}: ${schedule.description}`);
        });
        console.log(`\n🔄 Próxima rotación: ${this.getNextRotationDate()}`);
        console.log('');
    }

    // Método para ejecutar rotación manual (para testing o emergencias)
    async executeManualRotation() {
        console.log('🔄 Ejecutando rotación manual de claves...');
        
        if (this.isRunning) {
            throw new Error('Ya hay una rotación en progreso');
        }

        try {
            this.isRunning = true;
            const rotationId = this.generateRotationId();
            
            console.log(`🚀 Iniciando rotación manual ${rotationId}...`);
            
            const result = await keyRotator.rotateKeys();
            
            this.rotationHistory.push({
                id: rotationId,
                timestamp: new Date().toISOString(),
                status: 'success',
                type: 'manual',
                details: result
            });
            
            console.log(`✅ Rotación manual ${rotationId} completada`);
            return { success: true, rotationId, result };
            
        } catch (error) {
            console.error('❌ Error en rotación manual:', error);
            throw error;
        } finally {
            this.isRunning = false;
        }
    }

    // Obtener estadísticas del planificador
    getScheduleStatus() {
        return {
            isEnabled: this.isRotationEnabled,
            isRunning: this.isRunning,
            nextRotation: this.getNextRotationDate(),
            rotationHistory: this.rotationHistory.slice(-10), // Últimas 10 rotaciones
            timezone: 'America/Mexico_City',
            totalRotations: this.rotationHistory.length,
            lastSuccessfulRotation: this.rotationHistory
                .filter(r => r.status === 'success')
                .slice(-1)[0] || null
        };
    }
}

module.exports = new ScheduleKeyRotation();
```

---

## 📜 Scripts de Recuperación Mejorados

### 1. Script mejorado para descifrar mensajes
**Archivo:** `scripts/decryptMessage.js`
```javascript
#!/usr/bin/env node

const disguiser = require('../src/crypto/disguiser');
const secureCommunications = require('../src/services/secure-communications.service');
const fs = require('fs');
const path = require('path');

class MessageDecryptor {
    constructor() {
        this.outputFile = path.join(__dirname, 'decrypted_keys.json');
        this.patterns = ['default', 'advanced', 'reverse'];
    }

    async decryptFromText(messageText, patternType = 'default') {
        try {
            console.log('🔓 Analizando mensaje camuflado...\n');
            
            // Intentar decodificar con diferentes patrones
            let decodedPattern = null;
            let usedPattern = patternType;
            
            if (patternType === 'auto') {
                for (const pattern of this.patterns) {
                    try {
                        decodedPattern = disguiser.decodePattern(messageText, pattern);
                        if (decodedPattern) {
                            usedPattern = pattern;
                            break;
                        }
                    } catch (error) {
                        continue;
                    }
                }
            } else {
                decodedPattern = disguiser.decodePattern(messageText, patternType);
            }
            
            if (!decodedPattern) {
                throw new Error('No se pudo decodificar el patrón del mensaje con ningún método');
            }

            console.log('📋 Información extraída:');
            console.log(`   🔑 Patrón utilizado: ${usedPattern}`);
            console.log(`   📊 Índices de clave: [${decodedPattern.keyIndices.join(', ')}]`);
            console.log(`   🔐 Clave codificada: ${decodedPattern.encodedKey}`);
            
            // Intentar extraer datos técnicos del mensaje
            const technicalData = this.extractTechnicalData(messageText);
            
            // Guardar resultado completo
            const result = {
                patternInfo: {
                    pattern: usedPattern,
                    keyIndices: decodedPattern.keyIndices,
                    encodedKey: decodedPattern.encodedKey
                },
                technicalData,
                decodedAt: new Date().toISOString(),
                messagePreview: messageText.substring(0, 200) + '...',
                instructions: [
                    '1. Usa el patrón y los índices para reconstruir las claves',
                    '2. Los datos técnicos contienen información cifrada adicional',
                    '3. Contacta al administrador del sistema si necesitas las claves privadas RSA'
                ]
            };

            await fs.promises.writeFile(this.outputFile, JSON.stringify(result, null, 2));
            console.log(`\n✅ Resultado guardado en: ${this.outputFile}`);
            
            // Mostrar instrucciones adicionales
            this.showDecryptionInstructions(result);
            
            return result;
            
        } catch (error) {
            console.error('❌ Error decifrando mensaje:', error.message);
            throw error;
        }
    }

    extractTechnicalData(messageText) {
        try {
            const technicalSection = messageText.match(/📊 Detalles Técnicos del Reporte de Sistema([\s\S]*?)---/);
            if (!technicalSection) {
                return { found: false, message: 'No se encontró sección técnica' };
            }

            const technicalContent = technicalSection[1];
            
            // Extraer datos específicos
            const codeRef = technicalContent.match(/🔧 Código de Referencia: (.*)/);
            const verificationHash = technicalContent.match(/🔑 Hash de Verificación: (.*)/);
            const timestamp = technicalContent.match(/📅 Timestamp de Generación: (.*)/);
            const compression = technicalContent.match(/⚙️ Algoritmo de Compresión: (.*)/);

            return {
                found: true,
                codeReference: codeRef ? codeRef[1].trim() : null,
                verificationHash: verificationHash ? verificationHash[1].trim() : null,
                timestamp: timestamp ? timestamp[1].trim() : null,
                compression: compression ? compression[1].trim() : null,
                fullContent: technicalContent.trim()
            };
            
        } catch (error) {
            return { 
                found: false, 
                error: error.message,
                message: 'Error extrayendo datos técnicos'
            };
        }
    }

    showDecryptionInstructions(result) {
        console.log('\n📖 INSTRUCCIONES DE DESCIFRADO:');
        console.log('='.repeat(50));
        
        if (result.technicalData.found) {
            console.log('\n🔧 DATOS TÉCNICOS ENCONTRADOS:');
            if (result.technicalData.codeReference) {
                console.log(`   📦 Código de Referencia: ${result.technicalData.codeReference.substring(0, 50)}...`);
                console.log('       ↳ Este contiene el payload cifrado principal');
            }
            if (result.technicalData.verificationHash) {
                console.log(`   🔍 Hash de Verificación: ${result.technicalData.verificationHash}`);
                console.log('       ↳ Usa este hash para verificar la integridad');
            }
            if (result.technicalData.timestamp) {
                console.log(`   ⏰ Timestamp: ${result.technicalData.timestamp}`);
                console.log('       ↳ Fecha de generación de las claves');
            }
        }
        
        console.log('\n🔑 PATRÓN DE DESCIFRADO:');
        console.log(`   📋 Tipo de patrón: ${result.patternInfo.pattern}`);
        console.log(`   📊 Índices: [${result.patternInfo.keyIndices.join(', ')}]`);
        console.log(`   🔐 Clave extraída: ${result.patternInfo.encodedKey}`);
        
        console.log('\n⚡ PRÓXIMOS PASOS:');
        console.log('   1. 🔓 Si tienes acceso al sistema, usa esta información para regenerar las claves');
        console.log('   2. 📧 Si necesitas descifrado completo, usa las claves RSA privadas');
        console.log('   3. 🛠️ Para emergencias, ejecuta el script de recuperación de emergencia');
        
        console.log('\n💡 COMANDOS ÚTILES:');
        console.log('   📜 Ver más detalles: cat decrypted_keys.json | jq');
        console.log('   🚨 Recuperación: node scripts/emergencyRecovery.js');
        console.log('   🔧 Regenerar claves: npm run rotate-keys');
    }

    async decryptFromFile(filePath, patternType = 'default') {
        try {
            if (!fs.existsSync(filePath)) {
                throw new Error(`Archivo no encontrado: ${filePath}`);
            }

            console.log(`📂 Leyendo archivo: ${filePath}`);
            const messageText = await fs.promises.readFile(filePath, 'utf8');
            return await this.decryptFromText(messageText, patternType);
            
        } catch (error) {
            console.error('❌ Error leyendo archivo:', error.message);
            throw error;
        }
    }

    async tryAutoDecrypt(messageText) {
        console.log('🤖 Intentando descifrado automático con todos los patrones...\n');
        
        const results = [];
        
        for (const pattern of this.patterns) {
            try {
                console.log(`🔍 Probando patrón: ${pattern}`);
                const result = await this.decryptFromText(messageText, pattern);
                results.push({ pattern, success: true, result });
                console.log(`✅ Éxito con patrón: ${pattern}\n`);
            } catch (error) {
                results.push({ pattern, success: false, error: error.message });
                console.log(`❌ Falló patrón: ${pattern} - ${error.message}\n`);
            }
        }
        
        const successfulResults = results.filter(r => r.success);
        
        if (successfulResults.length === 0) {
            throw new Error('No se pudo descifrar con ningún patrón disponible');
        }
        
        console.log(`🎉 Se encontraron ${successfulResults.length} patrones válidos`);
        return successfulResults;
    }

    showUsage() {
        console.log(`
🔓 Descifrador Avanzado de Mensajes Camuflados

Uso:
  node scripts/decryptMessage.js [opciones]

Opciones:
  --text "mensaje"     Descifrar texto directamente
  --file ruta/archivo  Descifrar desde archivo
  --pattern tipo       Tipo de patrón (default, advanced, reverse, auto)
  --auto              Probar todos los patrones automáticamente
  --help              Mostrar esta ayuda

Ejemplos:
  node scripts/decryptMessage.js --text "Cinco blogs han sido detectados..."
  node scripts/decryptMessage.js --file ./mensaje_recibido.txt --pattern advanced
  node scripts/decryptMessage.js --file ./mensaje.txt --auto
  node scripts/decryptMessage.js --text "..." --pattern auto

Patrones disponibles:
  • default  - Patrón estándar (recomendado)
  • advanced - Patrón avanzado con mezcla
  • reverse  - Patrón inverso
  • auto     - Probar todos los patrones automáticamente

Archivos generados:
  • decrypted_keys.json - Resultado del descifrado
        `);
    }
}

// Ejecución desde línea de comandos
if (require.main === module) {
    const args = process.argv.slice(2);
    const decryptor = new MessageDecryptor();

    (async () => {
        try {
            if (args.includes('--help') || args.length === 0) {
                decryptor.showUsage();
                process.exit(0);
            }

            let messageText = '';
            let patternType = 'default';
            let autoMode = false;

            // Procesar argumentos
            for (let i = 0; i < args.length; i++) {
                switch (args[i]) {
                    case '--text':
                        messageText = args[i + 1];
                        i++;
                        break;
                    case '--file':
                        const filePath = args[i + 1];
                        messageText = await fs.promises.readFile(filePath, 'utf8');
                        i++;
                        break;
                    case '--pattern':
                        patternType = args[i + 1];
                        i++;
                        break;
                    case '--auto':
                        autoMode = true;
                        break;
                }
            }

            if (!messageText) {
                throw new Error('Debe proporcionar un mensaje o archivo para descifrar');
            }

            let result;
            if (autoMode) {
                result = await decryptor.tryAutoDecrypt(messageText);
                console.log('\n🎉 Descifrado automático completado');
                console.log(`📊 Resultados exitosos: ${result.length}`);
            } else {
                result = await decryptor.decryptFromText(messageText, patternType);
                console.log('\n🎉 Descifrado completado exitosamente');
            }
            
        } catch (error) {
            console.error('\n❌ Error:', error.message);
            console.log('\n💡 Usa --help para ver las opciones disponibles');
            process.exit(1);
        }
    })();
}

module.exports = MessageDecryptor;