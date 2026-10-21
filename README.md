# 🔐 Guía Completa de Instalación - Sistema Ultra Seguro con Seguridad Operacional Avanzada

> **Secure Server** es una API REST en Node.js (Express 5 + MySQL) pensada para guardar y servir datos sensibles. Todo lo que se persiste se cifra con tres capas (AES-256-CBC → AES-256-GCM → ChaCha20-Poly1305), cada petición pasa por detección de anomalías y rate limiting, y las claves se rotan automáticamente.

## 🧭 Descripción del proyecto

| Capa | Qué hace | Dónde está |
|------|----------|------------|
| **Entrada** | helmet, CORS, compresión, logs (morgan), parseo JSON | `src/index.js` |
| **Protección** | Bloqueo de IPs, detección de payloads maliciosos y anomalías, rate limiting dinámico | `src/middleware/protection.middleware.js`, `src/security/anomaly-detection.service.js` |
| **Autenticación** | JWT (5 días) ligado a una sesión en BD, análisis de riesgo por dispositivo/ubicación/horario, bloqueo de cuentas | `src/security/secure-auth.service.js`, `src/middleware/auth.middleware.js` |
| **Autorización** | Roles `user` / `admin` leídos de la BD en cada petición | `src/middleware/role.middleware.js` |
| **APIs** | Cada `*.routes.js` se monta solo en `/api/<nombre>` | `src/api/routes/`, `src/api/controllers/` |
| **Datos** | Pool MySQL; los campos sensibles se guardan cifrados | `src/config/database.js`, `src/crypto/tripleEncryptor.js` |
| **Auditoría** | Cada acción relevante se registra cifrada en `security_logs` | `src/services/audit.service.js` |
| **Operaciones** | Rotación mensual de claves, verificación de integridad, alertas multicanal camufladas, scripts de recuperación | `src/tasks/`, `src/crypto/keyRotator.js`, `src/services/secure-communications.service.js`, `scripts/` |

### Flujo de una petición

```
Cliente
  │
  ▼
helmet · CORS · compression · morgan · express.json          (src/index.js)
  │
  ▼
autoProtect()  ── IP bloqueada → 403 · amenaza crítica → 403 · anomalías → rate limit 429
  │
  ▼
registerRoutes()  ── verifyJWT (salvo router.access = 'public' | 'custom') → 401
  │
  ▼
router  ──  requireRole('admin') → 403  ·  validate.body/query/params → 400
  │
  ▼
controller  ──  db.query() · tripleEncryptor.encrypt/decrypt() · audit.log()
  │
  ▼
manejador de errores global (4xx del cliente se respetan; el resto → 500 sin detalles)
```

### Endpoints disponibles

| Método | Ruta | Acceso | Descripción |
|--------|------|--------|-------------|
| GET | `/health` | público | Estado del servidor |
| POST | `/api/auth/register` | público (10 req/min) | Registro de usuario |
| POST | `/api/auth/login` | público (10 req/min) | Devuelve `token` JWT |
| POST | `/api/auth/logout` | JWT | Invalida la sesión actual |
| GET | `/api/auth/profile` | JWT | Perfil descifrado y sesiones activas |
| POST | `/api/notes` | JWT | Crea una nota (cifrada) |
| GET | `/api/notes?page=1&limit=20` | JWT | Lista tus notas, paginadas |
| GET | `/api/notes/:id` | JWT | Lee una nota tuya |
| PUT | `/api/notes/:id` | JWT | Edita `title` y/o `content` |
| DELETE | `/api/notes/:id` | JWT | Borra una nota tuya |
| GET | `/api/system/status` | JWT + admin | Integridad, cifrado, protección, anomalías, rotación |
| GET | `/api/system/logs?page=&limit=&severity=` | JWT + admin | Logs de seguridad (máx. 200 por página) |
| GET | `/api/system/blocked-ips` | JWT + admin | IPs bloqueadas |
| DELETE | `/api/system/blocked-ips/:ip` | JWT + admin | Desbloquea una IP |
| POST | `/api/system/integrity-check` | JWT + admin (10 req/min) | Fuerza verificación de integridad |
| GET | `/api/system/rotation` | JWT + admin | Estado de claves, mantenimiento y backups (sin claves ni datos) |
| POST | `/api/system/rotate-keys` | JWT + admin | `501`: la rotación se lanza con `npm run rotate-keys` (ver [Rotación de claves](#rotación-de-claves-migración-de-datos-y-backups)) |
| POST | `/api/system/test-communications` | JWT + admin (10 req/min) | Prueba los canales de alerta |

> `/api/notes` es una API **de ejemplo funcional**: sirve de plantilla para las tuyas (ver [Cómo crear una API nueva](#cómo-crear-una-api-nueva)).

### Puesta en marcha rápida

```bash
npm install
# 1. Crea la BD y aplica el esquema (instalaciones nuevas)
mysql -u <usuario> -p <base_de_datos> < database/schema.sql
#    …o, si ya tenías la BD de antes, solo la migración (añade users.role y user_notes):
mysql -u <usuario> -p <base_de_datos> < database/migrations/001_roles_and_notes.sql
# 2. Configura .env (ver "Variables de Entorno Seguras") y arranca
npm start
# 3. Convierte a un usuario ya registrado en administrador (para /api/system/*)
npm run set-role -- --user-id 1 --role admin
# 4. Tests de la capa de APIs (no necesitan MySQL)
npm run test:api
```

---

## 📋 Índice
0. [Descripción del proyecto](#descripción-del-proyecto)
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
15. [Referencia de la API y cómo crear APIs nuevas](#referencia-de-la-api-y-cómo-crear-apis-nuevas)
16. [Defensa contra exfiltración por ICMP](#defensa-contra-exfiltración-por-icmp)
17. [Rotación de claves, migración de datos y backups](#rotación-de-claves-migración-de-datos-y-backups)

---

> **Nota:** las secciones de instalación paso a paso (desde *Requisitos Previos*) conservan el código de la guía original como referencia histórica. La fuente de verdad es el código del repositorio; en particular el montaje de rutas ya no vive en `src/index.js` sino en `src/api/routes/index.js`.

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
│   │   ├── routes/        # *.routes.js se montan solos en /api/<nombre> (index.js = cargador)
│   │   ├── controllers/
│   │   └── utils/         # validate.js (validación de entrada)
│   ├── config/
│   ├── crypto/
│   ├── middleware/
│   ├── maintenance/       # modo mantenimiento, guardián de claves y rotación
│   ├── backup/            # archivo de backup (compresión + AES-GCM), keyring, snapshot
│   ├── services/
│   ├── security/          # ← NUEVO: Servicios de seguridad operacional
│   ├── tasks/
│   ├── utils/
│   └── index.js
├── database/
│   ├── schema.sql
│   └── migrations/        # cambios de esquema incrementales
├── scripts/               # + rotateKeys.js, maintenance-firewall.sh, icmpMonitor.js, icmp-firewall.sh
├── test_api.js            # tests de la capa de APIs (npm run test:api)
├── test_icmp.js           # tests de la defensa ICMP (npm run test:icmp)
├── test_rotation.js       # rotación, backups y mantenimiento (npm run test:rotation, usa MariaDB)
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
```

---

## 🔐 Sistema de Cifrado

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

### 5. Sistema de Camuflaje de Mensajes
**Archivo:** `src/crypto/disguiser.js`
```javascript
const crypto = require('crypto');

class MessageDisguiser {
    constructor() {
        this.templates = {
            email: {
                subjects: [
                    'Reporte Mensual de Actividad',
                    'Actualización del Sistema de Monitoreo',
                    'Notificación de Mantenimiento Programado',
                    'Resumen de Métricas del Servidor',
                    'Análisis de Rendimiento Automático'
                ],
                intros: [
                    'El sistema de monitoreo ha generado automáticamente el siguiente reporte',
                    'Se ha completado el análisis programado con los siguientes resultados',
                    'Como parte del mantenimiento rutinario, se proporciona la siguiente información',
                    'El análisis de métricas del período actual muestra',
                    'La verificación automática del sistema ha producido estos datos'
                ]
            }
        };
    }

    generateCamouflageMessage(keyData) {
        try {
            // Crear un mensaje de camuflaje que parece legítimo
            const template = this.selectTemplate();
            
            // Codificar las claves en el mensaje de forma sutil
            const encodedMessage = this.encodeKeysInMessage(keyData, template);
            
            return {
                subject: template.subject,
                body: encodedMessage,
                timestamp: new Date().toISOString()
            };
            
        } catch (error) {
            console.error('❌ Error generando mensaje camuflado:', error);
            throw error;
        }
    }

    selectTemplate() {
        const subjects = this.templates.email.subjects;
        const intros = this.templates.email.intros;
        
        return {
            subject: subjects[Math.floor(Math.random() * subjects.length)],
            intro: intros[Math.floor(Math.random() * intros.length)]
        };
    }

    encodeKeysInMessage(keyData, template) {
        // Crear un mensaje que parece un reporte técnico normal
        // pero que contiene las claves codificadas en patrones específicos
        
        const keyIndices = this.generateKeyIndices(keyData);
        const encodedKey = this.encodeKeyData(keyData);
        
        return `${template.intro}.

Durante las últimas 24 horas, el sistema ha procesado múltiples transacciones y verificaciones de seguridad. Los principales indicadores de rendimiento muestran estabilidad en todos los componentes monitoreados.

MÉTRICAS DE SISTEMA:
- Procesamiento de datos: ${keyIndices[0]} transacciones por segundo
- Uso de memoria: ${keyIndices[1]}% de capacidad total  
- Conexiones activas: ${keyIndices[2]} sesiones concurrentes
- Índice de eficiencia: ${keyIndices[3]}.${keyIndices[4]} puntos

El análisis detallado revela que cinco blogs han sido detectados como fuentes principales de tráfico, con patrones de acceso distribuidos uniformemente. La evaluación de seguridad no ha identificado anomalías significativas en ninguno de los vectores monitoreados.

DATOS ADICIONALES:
Los algoritmos de optimización han identificado ${encodedKey.length} vectores de mejora potencial. La implementación de estas optimizaciones está programada para la próxima ventana de mantenimiento.

Para consultas técnicas específicas, refiera al código de referencia: ${encodedKey}

Este reporte se genera automáticamente cada 24 horas como parte del protocolo de monitoreo continuo del sistema.`;
    }

    generateKeyIndices(keyData) {
        // Generar índices que parecen métricas normales pero que realmente codifican información
        const baseIndices = [47, 83, 156, 92, 7];
        
        // Modificar ligeramente basado en keyData para crear un patrón único
        if (keyData.key1) {
            const hash = crypto.createHash('md5').update(keyData.key1).digest('hex');
            const modifier = parseInt(hash.substring(0, 2), 16) % 10;
            baseIndices[0] += modifier;
        }
        
        return baseIndices;
    }

    encodeKeyData(keyData) {
        try {
            // Combinar todas las claves en una cadena
            const combinedKeys = Object.values(keyData).join('|');
            
            // Codificar en base64 y luego aplicar cifrado simple
            const base64 = Buffer.from(combinedKeys).toString('base64');
            
            // Aplicar un cifrado Caesar simple para ofuscar más
            const caesarEncoded = this.applyCaesarCipher(base64, 7);
            
            return caesarEncoded;
        } catch (error) {
            console.error('❌ Error codificando claves:', error);
            return 'SYS_' + Date.now().toString(36).toUpperCase();
        }
    }

    applyCaesarCipher(text, shift) {
        return text.split('').map(char => {
            if (char.match(/[a-zA-Z]/)) {
                const start = char <= 'Z' ? 65 : 97;
                return String.fromCharCode(((char.charCodeAt(0) - start + shift) % 26) + start);
            }
            return char;
        }).join('');
    }

    // Método para decodificar (usado por scripts de recuperación)
    decodePattern(messageText, patternType = 'default') {
        try {
            // Extraer los índices del mensaje
            const keyIndices = this.extractKeyIndices(messageText);
            
            // Extraer la clave codificada
            const encodedKey = this.extractEncodedKey(messageText);
            
            if (!keyIndices || !encodedKey) {
                throw new Error('No se pudieron extraer los patrones del mensaje');
            }
            
            return {
                keyIndices,
                encodedKey,
                pattern: patternType
            };
            
        } catch (error) {
            console.error('❌ Error decodificando patrón:', error);
            throw error;
        }
    }

    extractKeyIndices(messageText) {
        try {
            // Buscar los patrones de métricas en el mensaje
            const metricsSection = messageText.match(/MÉTRICAS DE SISTEMA:(.*?)DATOS ADICIONALES:/s);
            if (!metricsSection) return null;

            const numbers = metricsSection[1].match(/\d+/g);
            return numbers ? numbers.map(n => parseInt(n)) : null;
        } catch (error) {
            return null;
        }
    }

    extractEncodedKey(messageText) {
        try {
            // Buscar el código de referencia
            const refCodeMatch = messageText.match(/código de referencia:\s*([A-Za-z0-9+/=]+)/i);
            if (refCodeMatch) {
                // Decodificar Caesar y luego base64
                const caesarDecoded = this.applyCaesarCipher(refCodeMatch[1], -7);
                return caesarDecoded;
            }
            return null;
        } catch (error) {
            return null;
        }
    }
}

module.exports = new MessageDisguiser();
```

### 6. Rotador de Claves
**Archivo:** `src/crypto/keyRotator.js`
```javascript
const crypto = require('crypto');
const tripleEncryptor = require('./tripleEncryptor');

class KeyRotator {
    constructor() {
        this.rotationInProgress = false;
        this.rotationHistory = [];
    }

    async rotateKeys() {
        if (this.rotationInProgress) {
            throw new Error('Ya hay una rotación de claves en progreso');
        }

        try {
            this.rotationInProgress = true;
            console.log('🔄 Iniciando rotación de claves...');

            // Generar nuevas claves
            const newKeys = this.generateNewKeys();
            
            // Verificar que las nuevas claves funcionan
            await this.validateNewKeys(newKeys);
            
            // Backup de claves actuales
            const backupResult = await this.backupCurrentKeys();
            
            // Actualizar claves en base de datos
            await this.updateKeysInDatabase(newKeys);
            
            // Marcar rotación como exitosa
            const rotationRecord = {
                timestamp: new Date().toISOString(),
                newKeyVersions: newKeys.versions,
                backupId: backupResult.backupId,
                status: 'success'
            };
            
            this.rotationHistory.push(rotationRecord);
            
            console.log('✅ Rotación de claves completada exitosamente');
            
            return {
                success: true,
                newKeys: newKeys,
                backupId: backupResult.backupId,
                rotationId: rotationRecord.timestamp
            };

        } catch (error) {
            console.error('❌ Error en rotación de claves:', error);
            
            // Registrar fallo
            this.rotationHistory.push({
                timestamp: new Date().toISOString(),
                status: 'failed',
                error: error.message
            });
            
            throw error;
        } finally {
            this.rotationInProgress = false;
        }
    }

    generateNewKeys() {
        try {
            const timestamp = Date.now();
            const version = `v${Math.floor(timestamp / 1000)}`;
            
            return {
                encryption: crypto.randomBytes(32).toString('hex'),
                jwt: crypto.randomBytes(64).toString('hex'), 
                session: crypto.randomBytes(32).toString('hex'),
                backup: crypto.randomBytes(32).toString('hex'),
                versions: {
                    encryption: `enc_${version}`,
                    jwt: `jwt_${version}`,
                    session: `sess_${version}`,
                    backup: `bkp_${version}`
                },
                timestamp
            };
        } catch (error) {
            console.error('❌ Error generando nuevas claves:', error);
            throw new Error('Error generando nuevas claves');
        }
    }

    async validateNewKeys(newKeys) {
        try {
            // Crear un encriptador temporal con las nuevas claves
            const testData = `key_validation_test_${Date.now()}`;
            
            // Simular cifrado con las nuevas claves
            const testEncryption = crypto.createCipher('aes-256-cbc', Buffer.from(newKeys.encryption, 'hex'));
            let encrypted = testEncryption.update(testData, 'utf8', 'hex');
            encrypted += testEncryption.final('hex');
            
            // Simular descifrado
            const testDecryption = crypto.createDecipher('aes-256-cbc', Buffer.from(newKeys.encryption, 'hex'));
            let decrypted = testDecryption.update(encrypted, 'hex', 'utf8');
            decrypted += testDecryption.final('utf8');
            
            if (decrypted !== testData) {
                throw new Error('Las nuevas claves no pasan la validación');
            }
            
            console.log('✅ Nuevas claves validadas correctamente');
            return true;
            
        } catch (error) {
            console.error('❌ Error validando nuevas claves:', error);
            throw new Error('Validación de nuevas claves falló');
        }
    }

    async backupCurrentKeys() {
        try {
            const db = require('../config/database');
            
            // Obtener claves activas actuales
            const [currentKeys] = await db.query(
                'SELECT * FROM encryption_keys WHERE is_active = TRUE'
            );

            if (currentKeys.length === 0) {
                console.log('ℹ️ No hay claves activas para respaldar');
                return { backupId: 'no_backup_needed' };
            }

            // Crear backup cifrado
            const backupId = `backup_${Date.now()}`;
            const backupData = {
                keys: currentKeys,
                timestamp: new Date().toISOString(),
                backupId
            };

            const encryptedBackup = tripleEncryptor.encrypt(JSON.stringify(backupData));
            
            // Guardar backup en tabla especial
            await db.query(
                `INSERT INTO encryption_keys (key_version, encrypted_key_data, is_active, expires_at) 
                 VALUES (?, ?, FALSE, DATE_ADD(NOW(), INTERVAL 1 YEAR))`,
                [backupId, encryptedBackup]
            );

            console.log(`✅ Backup de claves creado: ${backupId}`);
            return { backupId };

        } catch (error) {
            console.error('❌ Error creando backup de claves:', error);
            throw new Error('Error en backup de claves actuales');
        }
    }

    async updateKeysInDatabase(newKeys) {
        const db = require('../config/database');
        const connection = await db.getConnection();
        
        try {
            await connection.beginTransaction();
            
            // Desactivar claves actuales
            await connection.execute(
                'UPDATE encryption_keys SET is_active = FALSE WHERE is_active = TRUE'
            );
            
            // Insertar nuevas claves
            for (const [keyType, keyValue] of Object.entries(newKeys)) {
                if (keyType === 'versions' || keyType === 'timestamp') continue;
                
                const encryptedKeyData = tripleEncryptor.encrypt(JSON.stringify({
                    type: keyType,
                    value: keyValue,
                    createdAt: new Date().toISOString()
                }));

                await connection.execute(
                    `INSERT INTO encryption_keys (key_version, encrypted_key_data, is_active, expires_at) 
                     VALUES (?, ?, TRUE, DATE_ADD(NOW(), INTERVAL 6 MONTH))`,
                    [newKeys.versions[keyType], encryptedKeyData]
                );
            }
            
            await connection.commit();
            console.log('✅ Claves actualizadas en base de datos');
            
        } catch (error) {
            await connection.rollback();
            console.error('❌ Error actualizando claves en DB:', error);
            throw new Error('Error actualizando claves en base de datos');
        } finally {
            connection.release();
        }
    }

    async getActiveKeys() {
        try {
            const db = require('../config/database');
            const [keys] = await db.query(
                'SELECT key_version, encrypted_key_data FROM encryption_keys WHERE is_active = TRUE'
            );

            const decryptedKeys = {};
            for (const keyRecord of keys) {
                try {
                    const decryptedData = JSON.parse(tripleEncryptor.decrypt(keyRecord.encrypted_key_data));
                    decryptedKeys[decryptedData.type] = decryptedData.value;
                } catch (decryptError) {
                    console.error(`❌ Error descifrando clave ${keyRecord.key_version}:`, decryptError);
                }
            }

            return decryptedKeys;
        } catch (error) {
            console.error('❌ Error obteniendo claves activas:', error);
            throw error;
        }
    }

    async restoreFromBackup(backupId) {
        try {
            const db = require('../config/database');
            
            // Buscar el backup
            const [backup] = await db.query(
                'SELECT encrypted_key_data FROM encryption_keys WHERE key_version = ? AND is_active = FALSE',
                [backupId]
            );

            if (backup.length === 0) {
                throw new Error(`Backup ${backupId} no encontrado`);
            }

            // Descifrar backup
            const backupData = JSON.parse(tripleEncryptor.decrypt(backup[0].encrypted_key_data));
            
            console.log(`🔄 Restaurando desde backup: ${backupId}`);
            
            // Implementar lógica de restauración aquí
            // Esto sería similar a updateKeysInDatabase pero usando los datos del backup
            
            return { success: true, backupId, restoredKeys: backupData.keys.length };

        } catch (error) {
            console.error('❌ Error restaurando desde backup:', error);
            throw error;
        }
    }

    getRotationHistory(limit = 10) {
        return this.rotationHistory.slice(-limit);
    }

    isRotationNeeded() {
        // Verificar si es necesaria una rotación basada en tiempo o eventos
        const lastRotation = this.rotationHistory
            .filter(r => r.status === 'success')
            .pop();

        if (!lastRotation) return true;

        const daysSinceRotation = (Date.now() - new Date(lastRotation.timestamp).getTime()) / (1000 * 60 * 60 * 24);
        return daysSinceRotation >= 30; // Rotar cada 30 días
    }
}

module.exports = new KeyRotator();
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
            }
        }
    }

    async blockIP(ip, reason) {
        const db = require('../config/database');
        const blockDuration = 24 * 60 * 60 * 1000; // 24 horas
        const blockedUntil = new Date(Date.now() + blockDuration);
        
        try {
            await db.query(
                'INSERT INTO blocked_ips (ip_address, reason, blocked_until) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE blocked_until = ?, block_count = block_count + 1',
                [ip, reason, blockedUntil, blockedUntil]
            );

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

        console.log('🧹 Limpieza de datos de anomalías completada');
    }
}

module.exports = new AnomalyDetection();
```

### 2. Servicio de Autenticación Segura
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

    async validateCredentials(username, password) {
        const db = require('../config/database');
        const tripleEncryptor = require('../crypto/tripleEncryptor');
        
        try {
            const [users] = await db.query(
                'SELECT id, username, password_hash FROM users WHERE username = ?',
                [username]
            );

            if (users.length === 0) {
                return null;
            }

            const user = users[0];
            const isValidPassword = await bcrypt.compare(password, user.password_hash);
            
            if (!isValidPassword) {
                return null;
            }

            return user;
        } catch (error) {
            console.error('❌ Error validating credentials:', error);
            return null;
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

        // Clasificar riesgo
        if (riskScore >= 70) return 'high';
        if (riskScore >= 40) return 'medium';
        return 'low';
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

    hashToken(token) {
        return crypto.createHash('sha256').update(token).digest('hex');
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
        // Implementar auditoría de sesiones activas
        console.log('🔍 Auditando sesiones activas...');
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

## 🛡️ Middlewares de Protección

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

                next();
            } catch (error) {
                console.error('❌ Error en middleware de alta seguridad:', error);
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
}

module.exports = new ProtectionMiddleware();
```

### 2. Middleware de Autenticación
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
}

const authMiddleware = new AuthMiddleware();

module.exports = authMiddleware;
```

### 3. Middleware de Verificación de Integridad del Servidor
**Archivo:** `src/middleware/serverCheck.middleware.js`
```javascript
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

class ServerCheckMiddleware {
    constructor() {
        this.lastIntegrityCheck = null;
        this.serverFingerprint = null;
        this.criticalFiles = [
            'src/index.js',
            'src/config/database.js',
            'src/crypto/tripleEncryptor.js',
            'src/security/secure-auth.service.js'
        ];
        this.initializeFingerprint();
    }

    initializeFingerprint() {
        try {
            this.serverFingerprint = this.calculateServerFingerprint();
            console.log('🔒 Fingerprint del servidor inicializado');
        } catch (error) {
            console.error('❌ Error inicializando fingerprint del servidor:', error);
        }
    }

    calculateServerFingerprint() {
        try {
            const fileHashes = [];
            
            for (const filePath of this.criticalFiles) {
                if (fs.existsSync(filePath)) {
                    const fileContent = fs.readFileSync(filePath, 'utf8');
                    const hash = crypto.createHash('sha256').update(fileContent).digest('hex');
                    fileHashes.push(`${filePath}:${hash}`);
                }
            }

            const combinedHash = crypto.createHash('sha256')
                .update(fileHashes.join('|'))
                .digest('hex');

            return combinedHash;
        } catch (error) {
            console.error('❌ Error calculando fingerprint:', error);
            return null;
        }
    }

    async performIntegrityCheck() {
        try {
            const currentFingerprint = this.calculateServerFingerprint();
            
            if (!currentFingerprint) {
                throw new Error('No se pudo calcular el fingerprint actual');
            }

            if (this.serverFingerprint !== currentFingerprint) {
                console.log('🚨 ¡ALERTA! Cambio de integridad detectado en el servidor');
                
                // Registrar el incidente
                await this.logIntegrityBreach(this.serverFingerprint, currentFingerprint);
                
                // Enviar alerta inmediata
                await this.sendIntegrityAlert();
                
                return {
                    compromised: true,
                    originalFingerprint: this.serverFingerprint,
                    currentFingerprint: currentFingerprint
                };
            }

            this.lastIntegrityCheck = Date.now();
            
            // Registrar verificación exitosa
            await this.logIntegrityCheck(currentFingerprint);

            return {
                compromised: false,
                fingerprint: currentFingerprint,
                lastCheck: this.lastIntegrityCheck
            };

        } catch (error) {
            console.error('❌ Error en verificación de integridad:', error);
            throw error;
        }
    }

    async logIntegrityCheck(fingerprint) {
        try {
            const db = require('../config/database');
            const tripleEncryptor = require('../crypto/tripleEncryptor');
            
            const systemData = {
                fingerprint,
                timestamp: new Date().toISOString(),
                criticalFiles: this.criticalFiles,
                processInfo: {
                    nodeVersion: process.version,
                    platform: process.platform,
                    uptime: process.uptime()
                }
            };

            const encryptedSystemData = tripleEncryptor.encrypt(JSON.stringify(systemData));

            await db.query(
                `INSERT INTO server_integrity (fingerprint_hash, system_data_encrypted, status) 
                 VALUES (?, ?, 'secure') 
                 ON DUPLICATE KEY UPDATE 
                 system_data_encrypted = VALUES(system_data_encrypted), 
                 last_check = NOW(), 
                 status = 'secure'`,
                [fingerprint, encryptedSystemData]
            );

        } catch (error) {
            console.error('❌ Error logging integrity check:', error);
        }
    }

    async logIntegrityBreach(originalFingerprint, currentFingerprint) {
        try {
            const db = require('../config/database');
            const tripleEncryptor = require('../crypto/tripleEncryptor');
            
            const breachData = {
                event: 'INTEGRITY_BREACH',
                originalFingerprint,
                currentFingerprint,
                timestamp: new Date().toISOString(),
                criticalFiles: this.criticalFiles,
                severity: 'CRITICAL'
            };

            const encryptedBreachData = tripleEncryptor.encrypt(JSON.stringify(breachData));

            // Log en security_logs
            await db.query(
                `INSERT INTO security_logs (event_type, encrypted_details, severity) 
                 VALUES ('SERVER_INTEGRITY_BREACH', ?, 'critical')`,
                [encryptedBreachData]
            );

            // Actualizar tabla de integridad
            await db.query(
                `UPDATE server_integrity SET status = 'compromised', last_check = NOW() 
                 WHERE fingerprint_hash = ?`,
                [originalFingerprint]
            );

        } catch (error) {
            console.error('❌ Error logging integrity breach:', error);
        }
    }

    async sendIntegrityAlert() {
        try {
            const secureCommunications = require('../services/secure-communications.service');
            
            await secureCommunications.sendSecureAlert({
                type: 'SERVER_INTEGRITY_BREACH',
                severity: 'critical',
                details: 'Se ha detectado un cambio no autorizado en archivos críticos del servidor',
                action: 'Verificación inmediata requerida',
                timestamp: new Date().toISOString()
            }, 'critical');

        } catch (error) {
            console.error('❌ Error enviando alerta de integridad:', error);
        }
    }

    // Middleware para verificar integridad en cada request crítico
    checkIntegrity() {
        return async (req, res, next) => {
            try {
                // Solo verificar en operaciones críticas
                const criticalPaths = ['/api/users', '/api/auth', '/api/admin'];
                const isCriticalPath = criticalPaths.some(path => req.path.startsWith(path));
                
                if (!isCriticalPath) {
                    return next();
                }

                // Verificar si ha pasado suficiente tiempo desde la última verificación
                const timeSinceLastCheck = Date.now() - (this.lastIntegrityCheck || 0);
                const checkInterval = 60 * 60 * 1000; // 1 hora

                if (timeSinceLastCheck > checkInterval) {
                    const result = await this.performIntegrityCheck();
                    
                    if (result.compromised) {
                        return res.status(503).json({
                            success: false,
                            message: 'Servicio temporalmente no disponible por razones de seguridad',
                            code: 'INTEGRITY_COMPROMISED'
                        });
                    }
                }

                next();

            } catch (error) {
                console.error('❌ Error en middleware de integridad:', error);
                next(); // Continuar para no romper la aplicación
            }
        };
    }

    // Método para verificación asíncrona (usado por cron jobs)
    async performAsyncCheck() {
        try {
            console.log('🔍 Ejecutando verificación de integridad programada...');
            const result = await this.performIntegrityCheck();
            
            if (result.compromised) {
                console.log('🚨 SERVIDOR COMPROMETIDO - Alerta enviada');
            } else {
                console.log('✅ Integridad del servidor verificada');
            }
            
            return result;
        } catch (error) {
            console.error('❌ Error en verificación asíncrona:', error);
            throw error;
        }
    }

    getStatus() {
        return {
            serverFingerprint: this.serverFingerprint,
            lastIntegrityCheck: this.lastIntegrityCheck,
            criticalFiles: this.criticalFiles,
            checkInterval: '1 hour'
        };
    }
}

module.exports = new ServerCheckMiddleware();
```

---

## 🚀 Servicios y Controladores

### 1. Controlador Principal de Autenticación
**Archivo:** `src/api/controllers/auth.controller.js`
```javascript
const secureAuthService = require('../../security/secure-auth.service');
const tripleEncryptor = require('../../crypto/tripleEncryptor');
const bcrypt = require('bcryptjs');

class AuthController {
    async register(req, res) {
        try {
            const { username, email, password, deviceInfo } = req.body;

            // Validaciones básicas
            if (!username || !email || !password) {
                return res.status(400).json({
                    success: false,
                    message: 'Todos los campos son requeridos'
                });
            }

            // Verificar si el usuario ya existe
            const db = require('../../config/database');
            const [existingUsers] = await db.query(
                'SELECT id FROM users WHERE username = ?',
                [username]
            );

            if (existingUsers.length > 0) {
                return res.status(409).json({
                    success: false,
                    message: 'El usuario ya existe'
                });
            }

            // Cifrar datos personales
            const encryptedEmail = tripleEncryptor.encrypt(email);
            const passwordHash = await bcrypt.hash(password, 12);
            
            // Generar fingerprint del dispositivo
            const deviceFingerprint = secureAuthService.generateDeviceFingerprint(deviceInfo || {});

            // Crear usuario
            const result = await db.query(
                `INSERT INTO users (username, email_encrypted, password_hash, device_fingerprint) 
                 VALUES (?, ?, ?, ?)`,
                [username, encryptedEmail, passwordHash, deviceFingerprint]
            );

            // Log del registro
            await this.logUserAction('USER_REGISTERED', {
                userId: result.insertId,
                username,
                ipAddress: req.ip
            });

            res.status(201).json({
                success: true,
                message: 'Usuario registrado exitosamente',
                userId: result.insertId
            });

        } catch (error) {
            console.error('❌ Error en registro:', error);
            res.status(500).json({
                success: false,
                message: 'Error interno del servidor'
            });
        }
    }

    async login(req, res) {
        try {
            const { username, password, deviceInfo } = req.body;

            if (!username || !password) {
                return res.status(400).json({
                    success: false,
                    message: 'Username y password son requeridos'
                });
            }

            // Preparar información del dispositivo
            const enrichedDeviceInfo = {
                ...deviceInfo,
                ipAddress: req.ip,
                userAgent: req.headers['user-agent']
            };

            // Autenticar usuario
            const authResult = await secureAuthService.authenticateUser(
                username, 
                password, 
                enrichedDeviceInfo
            );

            // Log del login exitoso
            await this.logUserAction('USER_LOGIN_SUCCESS', {
                username,
                ipAddress: req.ip,
                riskLevel: authResult.riskLevel
            });

            res.json({
                success: true,
                message: 'Autenticación exitosa',
                token: authResult.token,
                expiresAt: authResult.expiresAt,
                riskLevel: authResult.riskLevel
            });

        } catch (error) {
            console.error('❌ Error en login:', error);
            
            // Log del login fallido
            await this.logUserAction('USER_LOGIN_FAILED', {
                username: req.body.username,
                ipAddress: req.ip,
                error: error.message
            });

            res.status(401).json({
                success: false,
                message: error.message
            });
        }
    }

    async logout(req, res) {
        try {
            // Invalidar sesión
            const db = require('../../config/database');
            const authHeader = req.headers.authorization;
            
            if (authHeader && authHeader.startsWith('Bearer ')) {
                const token = authHeader.substring(7);
                const tokenHash = secureAuthService.hashToken(token);
                
                await db.query(
                    'UPDATE user_sessions SET expires_at = NOW() WHERE jwt_token_hash = ?',
                    [tokenHash]
                );
            }

            // Log del logout
            await this.logUserAction('USER_LOGOUT', {
                userId: req.user?.id,
                username: req.user?.username,
                ipAddress: req.ip
            });

            res.json({
                success: true,
                message: 'Sesión cerrada exitosamente'
            });

        } catch (error) {
            console.error('❌ Error en logout:', error);
            res.status(500).json({
                success: false,
                message: 'Error cerrando sesión'
            });
        }
    }

    async getProfile(req, res) {
        try {
            const db = require('../../config/database');
            const [users] = await db.query(
                'SELECT id, username, created_at, risk_level FROM users WHERE id = ?',
                [req.user.id]
            );

            if (users.length === 0) {
                return res.status(404).json({
                    success: false,
                    message: 'Usuario no encontrado'
                });
            }

            const user = users[0];

            // Obtener sesiones activas
            const [sessions] = await db.query(
                `SELECT ip_address, location_country, risk_level, created_at 
                 FROM user_sessions 
                 WHERE user_id = ? AND expires_at > NOW() 
                 ORDER BY created_at DESC`,
                [req.user.id]
            );

            res.json({
                success: true,
                user: {
                    id: user.id,
                    username: user.username,
                    createdAt: user.created_at,
                    riskLevel: user.risk_level,
                    activeSessions: sessions.length,
                    sessions: sessions
                }
            });

        } catch (error) {
            console.error('❌ Error obteniendo perfil:', error);
            res.status(500).json({
                success: false,
                message: 'Error obteniendo perfil'
            });
        }
    }

    async logUserAction(action, details) {
        try {
            const db = require('../../config/database');
            const tripleEncryptor = require('../../crypto/tripleEncryptor');
            
            const encryptedDetails = tripleEncryptor.encrypt(JSON.stringify({
                ...details,
                timestamp: new Date().toISOString()
            }));

            await db.query(
                `INSERT INTO security_logs (event_type, encrypted_details, ip_address, severity) 
                 VALUES (?, ?, ?, 'low')`,
                [action, encryptedDetails, details.ipAddress]
            );

        } catch (error) {
            console.error('❌ Error logging user action:', error);
        }
    }
}

module.exports = new AuthController();
```

### 2. Rutas de Autenticación
**Archivo:** `src/api/routes/auth.routes.js`
```javascript
const express = require('express');
const router = express.Router();
const authController = require('../controllers/auth.controller');
const authMiddleware = require('../../middleware/auth.middleware');
const protectionMiddleware = require('../../middleware/protection.middleware');

// Aplicar protección automática a todas las rutas
router.use(protectionMiddleware.autoProtect());

// Rutas públicas (sin autenticación)
router.post('/register', 
    protectionMiddleware.highSecurity(),
    authController.register
);

router.post('/login', 
    protectionMiddleware.highSecurity(),
    authController.login
);

// Rutas protegidas (requieren autenticación)
router.use(authMiddleware.verifyJWT);

router.post('/logout', authController.logout);
router.get('/profile', authController.getProfile);

module.exports = router;
```

### 3. Controlador de Sistema
**Archivo:** `src/api/controllers/system.controller.js`
```javascript
const serverCheck = require('../../middleware/serverCheck.middleware');
const keyRotator = require('../../crypto/keyRotator');
const secureCommunications = require('../../services/secure-communications.service');

class SystemController {
    async getSystemStatus(req, res) {
        try {
            const integrityStatus = serverCheck.getStatus();
            const encryptionMetrics = require('../../crypto/tripleEncryptor').getMetrics();
            const protectionStats = require('../../middleware/protection.middleware').getProtectionStats();
            
            res.json({
                success: true,
                status: {
                    integrity: integrityStatus,
                    encryption: encryptionMetrics,
                    protection: protectionStats,
                    uptime: process.uptime(),
                    nodeVersion: process.version,
                    timestamp: new Date().toISOString()
                }
            });

        } catch (error) {
            console.error('❌ Error obteniendo estado del sistema:', error);
            res.status(500).json({
                success: false,
                message: 'Error obteniendo estado del sistema'
            });
        }
    }

    async performIntegrityCheck(req, res) {
        try {
            const result = await serverCheck.performAsyncCheck();
            
            res.json({
                success: true,
                message: 'Verificación de integridad completada',
                result
            });

        } catch (error) {
            console.error('❌ Error en verificación de integridad:', error);
            res.status(500).json({
                success: false,
                message: 'Error en verificación de integridad'
            });
        }
    }

    async rotateKeys(req, res) {
        try {
            const result = await keyRotator.rotateKeys();
            
            res.json({
                success: true,
                message: 'Rotación de claves completada',
                rotationId: result.rotationId
            });

        } catch (error) {
            console.error('❌ Error en rotación de claves:', error);
            res.status(500).json({
                success: false,
                message: error.message
            });
        }
    }

    async testCommunications(req, res) {
        try {
            const results = await secureCommunications.testChannels();
            
            res.json({
                success: true,
                message: 'Test de comunicaciones completado',
                results
            });

        } catch (error) {
            console.error('❌ Error en test de comunicaciones:', error);
            res.status(500).json({
                success: false,
                message: 'Error en test de comunicaciones'
            });
        }
    }

    async getSecurityLogs(req, res) {
        try {
            const { page = 1, limit = 50, severity } = req.query;
            const offset = (page - 1) * limit;
            
            const db = require('../../config/database');
            let query = `
                SELECT id, event_type, ip_address, timestamp, severity, risk_score 
                FROM security_logs 
            `;
            let params = [];
            
            if (severity) {
                query += ' WHERE severity = ?';
                params.push(severity);
            }
            
            query += ' ORDER BY timestamp DESC LIMIT ? OFFSET ?';
            params.push(parseInt(limit), parseInt(offset));
            
            const [logs] = await db.query(query, params);
            
            // Contar total
            let countQuery = 'SELECT COUNT(*) as total FROM security_logs';
            let countParams = [];
            
            if (severity) {
                countQuery += ' WHERE severity = ?';
                countParams.push(severity);
            }
            
            const [countResult] = await db.query(countQuery, countParams);
            const total = countResult[0].total;
            
            res.json({
                success: true,
                logs,
                pagination: {
                    page: parseInt(page),
                    limit: parseInt(limit),
                    total,
                    pages: Math.ceil(total / limit)
                }
            });

        } catch (error) {
            console.error('❌ Error obteniendo logs de seguridad:', error);
            res.status(500).json({
                success: false,
                message: 'Error obteniendo logs de seguridad'
            });
        }
    }
}

module.exports = new SystemController();
```

---

## 🔄 Sistema de Rotación Automática

### 1. Planificador de Tareas
**Archivo:** `src/tasks/scheduleKeyRotation.js`
```javascript
const cron = require('node-cron');
const keyRotator = require('../crypto/keyRotator');
const secureAuthService = require('../security/secure-auth.service');
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
        console.log('⏰ Inicializando planificador de rotación de claves...');

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

        this.calculateNextRotation();
        console.log('✅ Planificador inicializado');
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
            
            // Enviar notificación de éxito
            await this.sendRotationSuccessNotification(rotationId, duration, rotationResult);
            
            this.calculateNextRotation();

        } catch (error) {
            const rotationId = this.generateRotationId();
            
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

    async sendRotationSuccessNotification(rotationId, duration, rotationResult) {
        try {
            await secureCommunications.sendSecureAlert({
                type: 'KEY_ROTATION_SUCCESS',
                severity: 'info',
                details: `Rotación ${rotationId} completada exitosamente`,
                duration: duration,
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
            
            const db = require('../config/database');
            
            // Limpiar sesiones expiradas
            const result = await db.query(
                'DELETE FROM user_sessions WHERE expires_at < NOW()'
            );
            
            if (result.affectedRows > 0) {
                console.log(`🧹 ${result.affectedRows} sesiones expiradas eliminadas`);
            }
            
            // Limpiar IPs bloqueadas expiradas
            const ipResult = await db.query(
                'DELETE FROM blocked_ips WHERE blocked_until < NOW()'
            );
            
            if (ipResult.affectedRows > 0) {
                console.log(`🧹 ${ipResult.affectedRows} IPs desbloqueadas automáticamente`);
            }
            
            console.log('✅ Limpieza de sesiones completada');
            
        } catch (error) {
            console.error('❌ Error en limpieza de sesiones:', error);
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

    // Método para ejecutar rotación manual
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

    getScheduleStatus() {
        return {
            isEnabled: this.isRotationEnabled,
            isRunning: this.isRunning,
            nextRotation: this.getNextRotationDate(),
            rotationHistory: this.rotationHistory.slice(-10),
            totalRotations: this.rotationHistory.length
        };
    }
}

module.exports = new ScheduleKeyRotation();
```

---

## 📧 Comunicaciones Seguras

### 1. Sistema de Comunicaciones Multi-Canal
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

            // Canal de emergencia - Telegram (si está configurado)
            try {
                const telegramCreds = credentialBuilder.buildTelegramCredentials();
                if (telegramCreds.botToken && telegramCreds.chatId) {
                    this.channels.set('telegram', {
                        name: 'telegram',
                        type: 'telegram',
                        botToken: telegramCreds.botToken,
                        chatId: telegramCreds.chatId,
                        priority: 2,
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
            // Crear mensaje camuflado
            const camouflageMessage = await this.createCamouflageMessage(alertData);
            
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
                channelsUsed: results
            };

        } catch (error) {
            console.error('❌ Error enviando alerta segura:', error);
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
                return availableChannels.slice(0, 2);
            case 'normal':
            default:
                return availableChannels.slice(0, 1);
        }
    }

    async createCamouflageMessage(alertData) {
        const disguiser = require('../crypto/disguiser');
        
        // Crear mensaje base camuflado
        const baseMessage = disguiser.generateCamouflageMessage({
            type: alertData.type,
            severity: alertData.severity,
            timestamp: alertData.timestamp,
            details: alertData.details
        });

        return {
            subject: this.generateSubject(alertData.type),
            body: baseMessage.body,
            priority: this.mapAlertTypeToPriority(alertData.type)
        };
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
            const recipient = process.env.RECIPIENT_EMAIL;
            
            if (!recipient) {
                throw new Error('Email de destinatario no configurado');
            }

            const mailOptions = {
                from: `"Sistema de Seguridad" <${channel.transporter.options.auth.user}>`,
                to: recipient,
                subject: message.subject,
                text: message.body,
                headers: {
                    'X-Priority': message.priority === 'critical' ? '1' : '3',
                    'X-Secure-System': 'true'
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

    async sendTelegram(channel, message) {
        try {
            const axios = require('axios');
            
            const url = `https://api.telegram.org/bot${channel.botToken}/sendMessage`;
            
            const response = await axios.post(url, {
                chat_id: channel.chatId,
                text: `${message.subject}\n\n${message.body}`,
                parse_mode: 'Markdown'
            });

            console.log(`✅ Mensaje de Telegram enviado: ${response.data.result.message_id}`);
            return response.data.result;
            
        } catch (error) {
            console.error('❌ Error enviando mensaje de Telegram:', error);
            throw error;
        }
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

## 📜 Scripts de Recuperación

### 1. Script de Descifrado de Mensajes
**Archivo:** `scripts/decryptMessage.js`
```javascript
#!/usr/bin/env node

const disguiser = require('../src/crypto/disguiser');
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
                throw new Error('No se pudo decodificar el patrón del mensaje');
            }

            console.log('📋 Información extraída:');
            console.log(`   🔑 Patrón utilizado: ${usedPattern}`);
            console.log(`   📊 Índices de clave: [${decodedPattern.keyIndices?.join(', ') || 'N/A'}]`);
            console.log(`   🔐 Clave codificada: ${decodedPattern.encodedKey || 'N/A'}`);
            
            // Guardar resultado completo
            const result = {
                patternInfo: {
                    pattern: usedPattern,
                    keyIndices: decodedPattern.keyIndices,
                    encodedKey: decodedPattern.encodedKey
                },
                decodedAt: new Date().toISOString(),
                messagePreview: messageText.substring(0, 200) + '...'
            };

            await fs.promises.writeFile(this.outputFile, JSON.stringify(result, null, 2));
            console.log(`\n✅ Resultado guardado en: ${this.outputFile}`);
            
            return result;
            
        } catch (error) {
            console.error('❌ Error decifrando mensaje:', error.message);
            throw error;
        }
    }

    showUsage() {
        console.log(`
🔓 Descifrador de Mensajes Camuflados

Uso:
  node scripts/decryptMessage.js [opciones]

Opciones:
  --text "mensaje"     Descifrar texto directamente
  --file ruta/archivo  Descifrar desde archivo
  --pattern tipo       Tipo de patrón (default, advanced, reverse, auto)
  --help              Mostrar esta ayuda

Ejemplos:
  node scripts/decryptMessage.js --text "Cinco blogs han sido detectados..."
  node scripts/decryptMessage.js --file ./mensaje_recibido.txt
  node scripts/decryptMessage.js --text "..." --pattern auto
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
                }
            }

            if (!messageText) {
                throw new Error('Debe proporcionar un mensaje o archivo para descifrar');
            }

            const result = await decryptor.decryptFromText(messageText, patternType);
            console.log('\n🎉 Descifrado completado exitosamente');
            
        } catch (error) {
            console.error('\n❌ Error:', error.message);
            console.log('\n💡 Usa --help para ver las opciones disponibles');
            process.exit(1);
        }
    })();
}

module.exports = MessageDecryptor;
```

### 2. Script de Recuperación de Emergencia
**Archivo:** `scripts/emergencyRecovery.js`
```javascript
#!/usr/bin/env node

const fs = require('fs-extra');
const path = require('path');

class EmergencyRecovery {
    constructor() {
        this.backupDir = path.join(__dirname, '../backups');
        this.tempDir = path.join(__dirname, '../temp');
    }

    async createEmergencyBackup() {
        try {
            console.log('🚨 Creando backup de emergencia...');
            
            await fs.ensureDir(this.backupDir);
            
            const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
            const backupFile = path.join(this.backupDir, `emergency_backup_${timestamp}.json`);
            
            // Obtener datos críticos del sistema
            const systemData = await this.collectSystemData();
            
            // Crear backup cifrado
            const tripleEncryptor = require('../src/crypto/tripleEncryptor');
            const encryptedBackup = tripleEncryptor.encrypt(JSON.stringify(systemData));
            
            await fs.writeJSON(backupFile, {
                timestamp: new Date().toISOString(),
                type: 'emergency_backup',
                data: encryptedBackup
            }, { spaces: 2 });
            
            console.log(`✅ Backup de emergencia creado: ${backupFile}`);
            return { success: true, backupFile };
            
        } catch (error) {
            console.error('❌ Error creando backup de emergencia:', error);
            throw error;
        }
    }

    async restoreFromBackup(backupFile) {
        try {
            console.log(`🔄 Restaurando desde backup: ${backupFile}`);
            
            if (!fs.existsSync(backupFile)) {
                throw new Error(`Archivo de backup no encontrado: ${backupFile}`);
            }
            
            const backupData = await fs.readJSON(backupFile);
            
            // Descifrar datos
            const tripleEncryptor = require('../src/crypto/tripleEncryptor');
            const systemData = JSON.parse(tripleEncryptor.decrypt(backupData.data));
            
            console.log('📋 Datos de backup:');
            console.log(`   📅 Fecha: ${systemData.timestamp}`);
            console.log(`   🗄️ Usuarios: ${systemData.users?.length || 0}`);
            console.log(`   🔑 Claves: ${systemData.keys?.length || 0}`);
            
            // Aquí implementarías la lógica de restauración según necesites
            console.log('✅ Datos de backup verificados');
            
            return { success: true, data: systemData };
            
        } catch (error) {
            console.error('❌ Error restaurando backup:', error);
            throw error;
        }
    }

    async collectSystemData() {
        try {
            const db = require('../src/config/database');
            
            // Recopilar datos críticos
            const [users] = await db.query('SELECT id, username, created_at FROM users');
            const [activeKeys] = await db.query('SELECT key_version, created_at FROM encryption_keys WHERE is_active = TRUE');
            const [recentLogs] = await db.query('SELECT event_type, timestamp, severity FROM security_logs ORDER BY timestamp DESC LIMIT 100');
            
            return {
                timestamp: new Date().toISOString(),
                users: users,
                keys: activeKeys,
                recentLogs: recentLogs,
                systemInfo: {
                    nodeVersion: process.version,
                    platform: process.platform,
                    uptime: process.uptime()
                }
            };
            
        } catch (error) {
            console.error('❌ Error recopilando datos del sistema:', error);
            return {
                timestamp: new Date().toISOString(),
                error: error.message
            };
        }
    }

    async performSystemCheck() {
        try {
            console.log('🔍 Realizando verificación completa del sistema...');
            
            const checks = {
                database: false,
                encryption: false,
                communications: false,
                integrity: false
            };
            
            // Verificar base de datos
            try {
                const db = require('../src/config/database');
                await db.testConnection();
                checks.database = true;
                console.log('✅ Base de datos: OK');
            } catch (error) {
                console.log('❌ Base de datos: ERROR -', error.message);
            }
            
            // Verificar cifrado
            try {
                const tripleEncryptor = require('../src/crypto/tripleEncryptor');
                const healthCheck = await tripleEncryptor.healthCheck();
                checks.encryption = healthCheck.healthy;
                console.log('✅ Sistema de cifrado: OK');
            } catch (error) {
                console.log('❌ Sistema de cifrado: ERROR -', error.message);
            }
            
            // Verificar comunicaciones
            try {
                const secureCommunications = require('../src/services/secure-communications.service');
                const stats = secureCommunications.getStats();
                checks.communications = stats.availableChannels > 0;
                console.log(`✅ Comunicaciones: ${stats.availableChannels} canales disponibles`);
            } catch (error) {
                console.log('❌ Comunicaciones: ERROR -', error.message);
            }
            
            // Verificar integridad
            try {
                const serverCheck = require('../src/middleware/serverCheck.middleware');
                const result = await serverCheck.performAsyncCheck();
                checks.integrity = !result.compromised;
                console.log('✅ Integridad del servidor: OK');
            } catch (error) {
                console.log('❌ Integridad del servidor: ERROR -', error.message);
            }
            
            const allChecksPass = Object.values(checks).every(check => check === true);
            
            console.log('\n📊 RESUMEN DE VERIFICACIÓN:');
            console.log(`   🗄️ Base de datos: ${checks.database ? '✅' : '❌'}`);
            console.log(`   🔐 Cifrado: ${checks.encryption ? '✅' : '❌'}`);
            console.log(`   📧 Comunicaciones: ${checks.communications ? '✅' : '❌'}`);
            console.log(`   🛡️ Integridad: ${checks.integrity ? '✅' : '❌'}`);
            console.log(`\n   Estado general: ${allChecksPass ? '✅ SALUDABLE' : '⚠️ REQUIERE ATENCIÓN'}`);
            
            return { success: true, checks, healthy: allChecksPass };
            
        } catch (error) {
            console.error('❌ Error en verificación del sistema:', error);
            return { success: false, error: error.message };
        }
    }

    showUsage() {
        console.log(`
🚨 Script de Recuperación de Emergencia

Uso:
  node scripts/emergencyRecovery.js [comando] [opciones]

Comandos:
  backup                    Crear backup de emergencia
  restore [archivo]         Restaurar desde backup
  check                     Verificar estado del sistema

Ejemplos:
  node scripts/emergencyRecovery.js backup
  node scripts/emergencyRecovery.js restore backups/emergency_backup_2025-01-01.json
  node scripts/emergencyRecovery.js check
        `);
    }
}

// Ejecución desde línea de comandos
if (require.main === module) {
    const recovery = new EmergencyRecovery();
    const command = process.argv[2];
    const args = process.argv.slice(3);

    (async () => {
        try {
            switch (command) {
                case 'backup':
                    await recovery.createEmergencyBackup();
                    break;
                case 'restore':
                    if (!args[0]) {
                        console.error('❌ Archivo de backup requerido');
                        process.exit(1);
                    }
                    await recovery.restoreFromBackup(args[0]);
                    break;
                case 'check':
                    await recovery.performSystemCheck();
                    break;
                default:
                    recovery.showUsage();
                    process.exit(0);
            }
        } catch (error) {
            console.error('❌ Error:', error.message);
            process.exit(1);
        }
    })();
}

module.exports = EmergencyRecovery;
```

---

## 🚀 Ejecución del Sistema

### 1. Archivo Principal del Servidor
**Archivo:** `src/index.js`
```javascript
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const compression = require('compression');

// Importar configuraciones
const credentialBuilder = require('./config/credential-builder');
const database = require('./config/database');

// Importar middlewares
const protectionMiddleware = require('./middleware/protection.middleware');
const serverCheck = require('./middleware/serverCheck.middleware');

// Importar rutas
const authRoutes = require('./api/routes/auth.routes');

// Importar servicios
const secureCommunications = require('./services/secure-communications.service');

// Importar tareas programadas
const scheduleKeyRotation = require('./tasks/scheduleKeyRotation');

class SecureServer {
    constructor() {
        this.app = express();
        this.port = process.env.PORT || 3000;
        this.initializeServer();
    }

    async initializeServer() {
        try {
            console.log('🚀 Inicializando Servidor Ultra Seguro...');
            
            // Validar configuración inicial
            await this.validateConfiguration();
            
            // Configurar middlewares
            this.setupMiddlewares();
            
            // Configurar rutas
            this.setupRoutes();
            
            // Configurar manejo de errores
            this.setupErrorHandling();
            
            // Verificar sistemas
            await this.performInitialChecks();
            
            // Iniciar servidor
            this.startServer();
            
        } catch (error) {
            console.error('❌ Error iniciando servidor:', error);
            process.exit(1);
        }
    }

    async validateConfiguration() {
        try {
            console.log('🔍 Validando configuración...');
            
            // Validar credenciales
            credentialBuilder.validateCredentials();
            
            // Verificar conexión a base de datos
            const dbConnected = await database.testConnection();
            if (!dbConnected) {
                throw new Error('No se pudo conectar a la base de datos');
            }
            
            console.log('✅ Configuración validada');
        } catch (error) {
            console.error('❌ Error en validación de configuración:', error);
            throw error;
        }
    }

    setupMiddlewares() {
        console.log('⚙️ Configurando middlewares de seguridad...');
        
        // Middlewares de seguridad básicos
        this.app.use(helmet({
            contentSecurityPolicy: {
                directives: {
                    defaultSrc: ["'self'"],
                    styleSrc: ["'self'", "'unsafe-inline'"],
                    scriptSrc: ["'self'"],
                    imgSrc: ["'self'", "data:", "https:"]
                }
            },
            hsts: {
                maxAge: 31536000,
                includeSubDomains: true,
                preload: true
            }
        }));
        
        this.app.use(cors({
            origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'],
            credentials: true,
            methods: ['GET', 'POST', 'PUT', 'DELETE'],
            allowedHeaders: ['Content-Type', 'Authorization']
        }));
        
        this.app.use(compression());
        this.app.use(morgan('combined'));
        this.app.use(express.json({ limit: '10mb' }));
        this.app.use(express.urlencoded({ extended: true, limit: '10mb' }));
        
        // Middlewares de protección personalizados
        this.app.use(protectionMiddleware.autoProtect());
        
        console.log('✅ Middlewares configurados');
    }

    setupRoutes() {
        console.log('🛣️ Configurando rutas...');
        
        // Ruta de salud del sistema
        this.app.get('/health', async (req, res) => {
            try {
                const healthStatus = {
                    status: 'healthy',
                    timestamp: new Date().toISOString(),
                    uptime: process.uptime(),
                    version: '1.0.0'
                };
                
                res.json(healthStatus);
            } catch (error) {
                res.status(500).json({
                    status: 'unhealthy',
                    error: error.message
                });
            }
        });
        
        // Rutas de autenticación
        this.app.use('/api/auth', authRoutes);
        
        // Ruta de información del sistema (protegida)
        this.app.get('/api/system/status', 
            require('./middleware/auth.middleware').verifyJWT,
            async (req, res) => {
                try {
                    const systemStatus = {
                        server: {
                            uptime: process.uptime(),
                            nodeVersion: process.version,
                            platform: process.platform
                        },
                        security: {
                            integrityCheck: serverCheck.getStatus(),
                            communications: secureCommunications.getStats(),
                            rotationSchedule: scheduleKeyRotation.getScheduleStatus()
                        }
                    };
                    
                    res.json({
                        success: true,
                        status: systemStatus
                    });
                } catch (error) {
                    res.status(500).json({
                        success: false,
                        message: 'Error obteniendo estado del sistema'
                    });
                }
            }
        );
        
        // Ruta 404
        this.app.use('*', (req, res) => {
            res.status(404).json({
                success: false,
                message: 'Ruta no encontrada'
            });
        });
        
        console.log('✅ Rutas configuradas');
    }

    setupErrorHandling() {
        console.log('🛡️ Configurando manejo de errores...');
        
        // Manejo de errores generales
        this.app.use((error, req, res, next) => {
            console.error('❌ Error no manejado:', error);
            
            // Log del error
            this.logError(error, req);
            
            res.status(500).json({
                success: false,
                message: 'Error interno del servidor',
                ...(process.env.NODE_ENV === 'development' && { error: error.message })
            });
        });
        
        // Manejo de promesas rechazadas
        process.on('unhandledRejection', (reason, promise) => {
            console.error('❌ Promesa rechazada no manejada:', reason);
        });
        
        // Manejo de excepciones no capturadas
        process.on('uncaughtException', (error) => {
            console.error('❌ Excepción no capturada:', error);
            process.exit(1);
        });
        
        console.log('✅ Manejo de errores configurado');
    }

    async performInitialChecks() {
        console.log('🔍 Realizando verificaciones iniciales...');
        
        try {
            // Verificar integridad del servidor
            await serverCheck.performAsyncCheck();
            
            // Verificar sistema de cifrado
            const tripleEncryptor = require('./crypto/tripleEncryptor');
            const encryptionHealth = await tripleEncryptor.healthCheck();
            
            if (!encryptionHealth.healthy) {
                throw new Error('Sistema de cifrado no funciona correctamente');
            }
            
            // Verificar canales de comunicación
            const commStats = secureCommunications.getStats();
            if (commStats.availableChannels === 0) {
                console.log('⚠️ Advertencia: No hay canales de comunicación configurados');
            }
            
            console.log('✅ Verificaciones iniciales completadas');
            
        } catch (error) {
            console.error('❌ Error en verificaciones iniciales:', error);
            throw error;
        }
    }

    startServer() {
        this.server = this.app.listen(this.port, () => {
            console.log('\n🎉 ========================================');
            console.log('🔐 SERVIDOR ULTRA SEGURO INICIADO');
            console.log('🎉 ========================================');
            console.log(`🌐 Puerto: ${this.port}`);
            console.log(`🔒 Modo: ${process.env.NODE_ENV || 'development'}`);
            console.log(`⏰ Tiempo de inicio: ${new Date().toLocaleString('es-MX')}`);
            console.log('🔄 Rotación automática:', scheduleKeyRotation.getScheduleStatus().isEnabled ? 'ACTIVADA' : 'DESACTIVADA');
            console.log('📧 Canales de comunicación:', secureCommunications.getStats().availableChannels);
            console.log('========================================\n');
            
            // Enviar notificación de inicio (si hay canales configurados)
            this.sendStartupNotification();
        });
        
        // Manejo graceful de cierre
        process.on('SIGTERM', () => this.gracefulShutdown());
        process.on('SIGINT', () => this.gracefulShutdown());
    }

    async sendStartupNotification() {
        try {
            const commStats = secureCommunications.getStats();
            if (commStats.availableChannels > 0) {
                await secureCommunications.sendSecureAlert({
                    type: 'SYSTEM_STARTUP',
                    severity: 'info',
                    details: `Servidor ultra seguro iniciado correctamente en puerto ${this.port}`,
                    timestamp: new Date().toISOString()
                }, 'normal');
            }
        } catch (error) {
            console.log('ℹ️ No se pudo enviar notificación de inicio (normal si no hay canales configurados)');
        }
    }

    async gracefulShutdown() {
        console.log('\n🛑 Iniciando cierre graceful del servidor...');
        
        try {
            // Enviar notificación de cierre
            const commStats = secureCommunications.getStats();
            if (commStats.availableChannels > 0) {
                await secureCommunications.sendSecureAlert({
                    type: 'SYSTEM_SHUTDOWN',
                    severity: 'info',
                    details: 'Servidor iniciando proceso de cierre',
                    timestamp: new Date().toISOString()
                }, 'normal');
            }
            
            // Cerrar servidor
            this.server.close(() => {
                console.log('✅ Servidor cerrado correctamente');
                process.exit(0);
            });
            
            // Timeout de emergencia
            setTimeout(() => {
                console.log('⚠️ Forzando cierre del servidor');
                process.exit(1);
            }, 10000);
            
        } catch (error) {
            console.error('❌ Error en cierre graceful:', error);
            process.exit(1);
        }
    }

    async logError(error, req = null) {
        try {
            const db = require('./config/database');
            const tripleEncryptor = require('./crypto/tripleEncryptor');
            
            const errorData = {
                message: error.message,
                stack: error.stack,
                timestamp: new Date().toISOString(),
                ...(req && {
                    url: req.url,
                    method: req.method,
                    ip: req.ip,
                    userAgent: req.headers['user-agent']
                })
            };
            
            const encryptedError = tripleEncryptor.encrypt(JSON.stringify(errorData));
            
            await db.query(
                `INSERT INTO security_logs (event_type, encrypted_details, severity) 
                 VALUES ('SERVER_ERROR', ?, 'high')`,
                [encryptedError]
            );
            
        } catch (logError) {
            console.error('❌ Error logging error:', logError);
        }
    }
}

// Inicializar servidor
new SecureServer();
```

### 2. Archivo .gitignore
**Archivo:** `.gitignore`
```
# Dependencies
node_modules/
npm-debug.log*
yarn-debug.log*
yarn-error.log*

# Environment variables
.env
.env.local
.env.development.local
.env.test.local
.env.production.local

# Logs
logs/
*.log

# Temporary files
temp/
tmp/

# Backup files
backups/
*.backup

# OS generated files
.DS_Store
.DS_Store?
._*
.Spotlight-V100
.Trashes
ehthumbs.db
Thumbs.db

# IDE files
.vscode/
.idea/
*.swp
*.swo

# Scripts output
scripts/decrypted_keys.json

# PM2
.pm2/

# Coverage directory used by tools like istanbul
coverage/

# Runtime data
pids/
*.pid
*.seed
*.pid.lock
```

### 3. Script de Test del Sistema
**Archivo:** `test_system.js`
```javascript
const crypto = require('crypto');

async function testSystem() {
    console.log('🧪 Iniciando tests del sistema ultra seguro...\n');
    
    let passedTests = 0;
    let totalTests = 0;
    
    // Test 1: Cifrado Triple
    totalTests++;
    try {
        console.log('🔐 Test 1: Sistema de cifrado triple');
        const tripleEncryptor = require('./src/crypto/tripleEncryptor');
        
        const testData = 'Test de cifrado ultra seguro ' + Date.now();
        const encrypted = tripleEncryptor.encrypt(testData);
        const decrypted = tripleEncryptor.decrypt(encrypted);
        
        if (decrypted === testData) {
            console.log('✅ Cifrado triple: PASS');
            passedTests++;
        } else {
            console.log('❌ Cifrado triple: FAIL');
        }
    } catch (error) {
        console.log('❌ Cifrado triple: ERROR -', error.message);
    }
    
    // Test 2: Base de datos
    totalTests++;
    try {
        console.log('🗄️ Test 2: Conexión a base de datos');
        const database = require('./src/config/database');
        
        const connected = await database.testConnection();
        
        if (connected) {
            console.log('✅ Base de datos: PASS');
            passedTests++;
        } else {
            console.log('❌ Base de datos: FAIL');
        }
    } catch (error) {
        console.log('❌ Base de datos: ERROR -', error.message);
    }
    
    // Test 3: Generación de credenciales
    totalTests++;
    try {
        console.log('🔑 Test 3: Generación de credenciales');
        const credentialBuilder = require('./src/config/credential-builder');
        
        const jwtSecret = credentialBuilder.generateJWTSecret();
        
        if (jwtSecret && jwtSecret.length > 0) {
            console.log('✅ Credenciales: PASS');
            passedTests++;
        } else {
            console.log('❌ Credenciales: FAIL');
        }
    } catch (error) {
        console.log('❌ Credenciales: ERROR -', error.message);
    }
    
    // Test 4: Sistema de camuflaje
    totalTests++;
    try {
        console.log('🎭 Test 4: Sistema de camuflaje de mensajes');
        const disguiser = require('./src/crypto/disguiser');
        
        const testKeys = {
            key1: 'test_key_1',
            key2: 'test_key_2',
            key3: 'test_key_3'
        };
        
        const camouflageMessage = disguiser.generateCamouflageMessage(testKeys);
        
        if (camouflageMessage && camouflageMessage.body && camouflageMessage.subject) {
            console.log('✅ Camuflaje: PASS');
            passedTests++;
        } else {
            console.log('❌ Camuflaje: FAIL');
        }
    } catch (error) {
        console.log('❌ Camuflaje: ERROR -', error.message);
    }
    
    // Test 5: Verificación de integridad
    totalTests++;
    try {
        console.log('🛡️ Test 5: Verificación de integridad');
        const serverCheck = require('./src/middleware/serverCheck.middleware');
        
        const status = serverCheck.getStatus();
        
        if (status && status.serverFingerprint) {
            console.log('✅ Integridad: PASS');
            passedTests++;
        } else {
            console.log('❌ Integridad: FAIL');
        }
    } catch (error) {
        console.log('❌ Integridad: ERROR -', error.message);
    }
    
    // Resumen
    console.log('\n📊 RESUMEN DE TESTS:');
    console.log('='.repeat(30));
    console.log(`✅ Tests pasados: ${passedTests}/${totalTests}`);
    console.log(`❌ Tests fallidos: ${totalTests - passedTests}/${totalTests}`);
    console.log(`📈 Porcentaje de éxito: ${Math.round((passedTests / totalTests) * 100)}%`);
    
    if (passedTests === totalTests) {
        console.log('\n🎉 ¡TODOS LOS TESTS PASARON! Sistema listo para producción.');
    } else {
        console.log('\n⚠️ Algunos tests fallaron. Revisa la configuración antes de continuar.');
    }
}

// Ejecutar tests
testSystem().catch(error => {
    console.error('❌ Error ejecutando tests:', error);
    process.exit(1);
});
```

---

## 🧩 Referencia de la API y cómo crear APIs nuevas

### Probar el sistema con curl

```bash
# 1. Registro
curl -X POST http://localhost:3000/api/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"username":"ana","email":"ana@example.com","password":"una-clave-larga","deviceInfo":{}}'

# 2. Login → guarda el token de la respuesta
TOKEN=$(curl -s -X POST http://localhost:3000/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"ana","password":"una-clave-larga","deviceInfo":{}}' | jq -r .token)

# 3. Usar una API protegida
curl -X POST http://localhost:3000/api/notes \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"title":"Mi primera nota","content":"Se guarda cifrada"}'

curl -H "Authorization: Bearer $TOKEN" http://localhost:3000/api/notes
```

Todas las respuestas siguen el mismo formato: `{ "success": true, ... }` o
`{ "success": false, "message": "...", "code": "VALIDATION_ERROR" }`. Códigos habituales:
`400` datos inválidos, `401` token ausente/inválido, `403` sin permisos o IP bloqueada,
`404` no existe (o no es tuyo), `429` rate limit, `503` migración pendiente.

### Cómo funciona el cargador de rutas

`src/api/routes/index.js` busca todos los archivos `*.routes.js` de esa carpeta y monta cada uno en
`/api/<nombre-del-archivo>`. **No hace falta tocar `src/index.js`.**

| `router.access` | Efecto |
|-----------------|--------|
| *(sin definir)* o `'protected'` | JWT obligatorio (`verifyJWT`). **Es el valor por defecto: seguro por omisión.** |
| `'public'` | Sin login (por ejemplo, un endpoint de estado público). |
| `'custom'` | El router gestiona su propia autenticación (lo usa `/api/auth`, que mezcla rutas públicas y protegidas). |

La protección global (`autoProtect`: IPs bloqueadas, anomalías, rate limiting) se aplica siempre, también a las rutas públicas.

### Herramientas que puedes reutilizar

| Herramienta | Para qué | Uso |
|-------------|----------|-----|
| `req.user` | Usuario autenticado: `{ id, username, sessionId, riskLevel }` | `req.user.id` |
| `roleMiddleware.requireRole('admin')` | Restringir por rol (se consulta la BD, no el token) | `router.use(roleMiddleware.requireRole('admin'))` |
| `validate.body / query / params` | Validar y limpiar la entrada; descarta campos no declarados | `validate.body({ title: { type: 'string', required: true, max: 200 } })` |
| `tripleEncryptor.encrypt / decrypt` | Cifrar antes de guardar, descifrar al leer | `tripleEncryptor.encrypt(texto)` |
| `audit.log(evento, detalles, { req, severity, riskScore })` | Registrar la acción, cifrada, en `security_logs` | `await audit.log('TASK_CREATED', { id }, { req })` |
| `protectionMiddleware.highSecurity()` | Rate limit estricto (10 req/min) para operaciones sensibles | `router.post('/x', protectionMiddleware.highSecurity(), handler)` |
| `db.query(sql, params)` | Consultas parametrizadas; devuelve `[filas]` (o `[ResultSetHeader]` en INSERT/UPDATE/DELETE) | `const [rows] = await db.query('SELECT …', [id])` |

Tipos que acepta `validate`: `string`, `email`, `number`, `integer`, `boolean` y `enum` (con `values`); opciones `required`, `min`, `max`, `default`.
En `validate.query` el resultado limpio queda en `req.validated.query` (en Express 5 `req.query` es de solo lectura); en `validate.body` se reemplaza `req.body`.

### Cómo crear una API nueva

Ejemplo: una API de **tareas** (`/api/tasks`). La API de notas (`notes.routes.js` + `notes.controller.js`) es la referencia completa y funcional.

**1. Tabla en la base de datos** — crea un archivo en `database/migrations/` y añade la misma tabla a `database/schema.sql`. Los datos sensibles van en columnas `*_encrypted` (`longtext`), y la tabla cuelga de `users` con `ON DELETE CASCADE`:

```sql
CREATE TABLE IF NOT EXISTS `user_tasks` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `user_id` int(11) NOT NULL,
  `title_encrypted` longtext NOT NULL,
  `done` tinyint(1) NOT NULL DEFAULT 0,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `idx_tasks_user_id` (`user_id`),
  CONSTRAINT `user_tasks_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
```

**1b. Registra la columna cifrada** en `src/crypto/encrypted-columns.js` (si no, la próxima rotación de claves la dejaría ilegible):

```js
user_tasks: { primaryKey: 'id', columns: ['title_encrypted'] },
```

**2. Controlador** — `src/api/controllers/tasks.controller.js`. Reglas de oro: filtra **siempre** por `user_id = req.user.id`, cifra lo sensible, audita las escrituras y devuelve 404 (no 403) cuando algo no es del usuario:

```js
const db = require('../../config/database');
const tripleEncryptor = require('../../crypto/tripleEncryptor');
const audit = require('../../services/audit.service');

class TasksController {
    constructor() {
        this.create = this.create.bind(this);   // se usan como handlers de Express
        this.list = this.list.bind(this);
    }

    async create(req, res) {
        const { title } = req.body;                       // ya validado por validate.body
        const [result] = await db.query(
            'INSERT INTO user_tasks (user_id, title_encrypted) VALUES (?, ?)',
            [req.user.id, tripleEncryptor.encrypt(title)]
        );
        await audit.log('TASK_CREATED', { taskId: result.insertId }, { req });
        res.status(201).json({ success: true, task: { id: result.insertId, title, done: false } });
    }

    async list(req, res) {
        const [rows] = await db.query(
            'SELECT id, title_encrypted, done FROM user_tasks WHERE user_id = ? ORDER BY id DESC',
            [req.user.id]
        );
        res.json({
            success: true,
            tasks: rows.map(r => ({ id: r.id, title: tripleEncryptor.decrypt(r.title_encrypted), done: !!r.done }))
        });
    }
}

module.exports = new TasksController();
```

> En Express 5 los errores de funciones `async` se propagan solos al manejador global: no hace falta `try/catch` ni `asyncHandler` (solo si quieres una respuesta de error propia).

**3. Rutas** — `src/api/routes/tasks.routes.js`. El nombre del archivo define la URL:

```js
const express = require('express');
const router = express.Router();
const tasksController = require('../controllers/tasks.controller');
const validate = require('../utils/validate');

router.post('/',
    validate.body({ title: { type: 'string', required: true, min: 1, max: 200 } }),
    tasksController.create
);
router.get('/', tasksController.list);

// router.access = 'public';              // opcional: sin login
// router.use(roleMiddleware.requireRole('admin'));   // opcional: solo administradores

module.exports = router;
```

**4. Listo.** Reinicia el servidor: en el arranque verás `↳ /api/tasks (protected)`. Ya hereda JWT, rate limiting, detección de anomalías, cifrado y auditoría.

**5. Test** — añade casos a `test_api.js` (usa una BD simulada en memoria, así que no necesita MySQL) y ejecuta `npm run test:api`. Comprueba como mínimo: 401 sin token, validación 400, que otro usuario no ve tus datos y que en BD no queda texto plano.

### Checklist de seguridad para cada API nueva

- [ ] Cada consulta que toca datos de usuario filtra por `user_id = req.user.id`
- [ ] Todo dato sensible se guarda con `tripleEncryptor.encrypt` (nada de texto plano en BD)
- [ ] Cada columna cifrada está registrada en `src/crypto/encrypted-columns.js` (`npm run test:rotation` lo comprueba)
- [ ] Entrada validada con `validate.*` (límites de longitud incluidos)
- [ ] SQL siempre con parámetros `?` (nunca concatenar datos del usuario). Excepción: `LIMIT`/`OFFSET` se interpolan solo tras validarlos como enteros acotados
- [ ] Escrituras y borrados auditados con `audit.log`
- [ ] Operaciones administrativas detrás de `requireRole('admin')` y, si son sensibles, `highSecurity()`
- [ ] Las respuestas nunca incluyen claves, hashes ni datos de otros usuarios
- [ ] Rutas públicas (`router.access = 'public'`) solo cuando sea imprescindible

### Roles y administradores

Los usuarios nuevos tienen `role = 'user'`. Para dar acceso a `/api/system/*`:

```bash
npm run set-role -- --user-id 1 --role admin
```

El rol se consulta en la BD en cada petición: si lo quitas, el acceso desaparece al instante aunque el JWT siga vigente. Si olvidas aplicar la migración, las rutas con `requireRole` responden `503 MIGRATION_REQUIRED`.

---

## 🛰️ Defensa contra exfiltración por ICMP

### El ataque

Con `ping -c 1 -p <patrón> <ip>` el atacante rellena el payload del echo-request con un patrón de hasta **16 bytes** (32 caracteres hex; no 16 bits). Cada ping lleva un trozo del archivo y una máquina que escucha reconstruye el documento a partir de los payloads. Es lento, pero casi ningún firewall ni antivirus mira dentro del ICMP.

Un ping legítimo no se parece a eso: Linux/macOS/BSD rellenan con bytes incrementales (`0x10, 0x11, …`) y Windows con `abcdefghijklmnopqrstuvwabcdefghi`. Un payload que repite un patrón arbitrario y **cambia de un ping al siguiente** es la firma del canal encubierto.

### Qué se puede (y qué no) hacer desde Node

Una aplicación Node **no ve paquetes ICMP**: eso ocurre en el kernel. Por eso la defensa va en capas y la que de verdad corta el canal vive en el host, no en el código de la API:

| Capa | Qué hace | Dónde |
|------|----------|-------|
| **1. Prevención** | Un proceso comprometido no puede emitir ICMP, o solo hacia destinos de confianza y con tasa limitada | `scripts/icmp-firewall.sh`, `sysctl`, quitar `CAP_NET_RAW` |
| **2. Detección** | Analiza los payloads ICMP y alerta de patrones repetidos, patrones que cambian, alta entropía, tamaños anormales y replies alterados | `scripts/icmpMonitor.js`, `src/security/icmp-covert-channel.service.js` |
| **3. Respuesta** | Alerta camuflada por los canales existentes, evento cifrado en `security_logs`, bloqueo HTTP de IPs externas | `scripts/icmpMonitor.js` |
| **4. Postura** | `/api/system/status` informa de qué puede hacer el proceso en red; el servidor no puede lanzar procesos | `src/security/network-hardening.check.js` |

### Capa 1 — Prevención en el host

**a) Firewall (la medida más eficaz).** `scripts/icmp-firewall.sh` crea cadenas propias (`ICMP_GUARD_IN` / `ICMP_GUARD_OUT`) para IPv4 e IPv6:

- **Salida**: `echo-request` solo hacia `ICMP_ALLOWED_DESTS`, de tamaño estándar y máx. 6/min; el resto se registra (`ICMP_GUARD_DROP_OUT`) y se descarta. Con la lista vacía (por defecto) un servidor comprometido no puede emitir pings.
- **Entrada**: `echo-request` de tamaño estándar con límite de tasa (o descartados del todo con `ICMP_ALLOW_INBOUND_PING=0`); los `echo-reply` que no responden a un ping nuestro se descartan.

```bash
# 1. Ver qué haría (no modifica nada)
ICMP_ALLOWED_DESTS="1.1.1.1 8.8.8.8" npm run icmp-firewall
# 2. Aplicar (root). Idempotente: se puede ejecutar varias veces
sudo ICMP_ALLOWED_DESTS="1.1.1.1 8.8.8.8" npm run icmp-firewall -- --apply
# 3. Deshacer: quita solo sus cadenas, sin tocar el resto del firewall
sudo npm run icmp-firewall -- --remove
```

> Las reglas no persisten tras un reinicio: guárdalas con tu mecanismo habitual (`iptables-persistent`, `netfilter-persistent save`, un servicio systemd que ejecute el script…). Si la máquina enruta tráfico, replica las reglas en `FORWARD`.

**b) Sin capacidad de ICMP para el proceso.** El atacante necesita `CAP_NET_RAW` o que el kernel permita ping sin privilegios:

```bash
# Desactivar ping para usuarios sin privilegios (persistente)
echo 'net.ipv4.ping_group_range = 1 0' | sudo tee /etc/sysctl.d/90-icmp-guard.conf && sudo sysctl --system
```
```yaml
# docker-compose.yml
services:
  secure-server:
    user: "1000:1000"          # nunca root
    cap_drop: [ALL]            # o, como mínimo, NET_RAW
    read_only: true
```
```ini
# systemd: [Service]
User=secureserver
CapabilityBoundingSet=
NoNewPrivileges=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
```

`GET /api/system/status` (admin) devuelve `security.networkPosture` con `capNetRaw`, `unprivilegedPing`, `runningAsRoot`, `hardened` y una lista de `recommendations`. Hasta que el host esté endurecido te dirá exactamente qué falta.

### Capa 2 — Detección: `icmp-monitor`

Captura echo-request/echo-reply con `tcpdump` y los analiza. **Debe correr como proceso aparte**, nunca dentro del servidor web, porque capturar exige root o `CAP_NET_RAW`:

```bash
sudo apt install tcpdump
sudo npm run icmp-monitor                                    # todas las interfaces
sudo npm run icmp-monitor -- --interface eth0
sudo npm run icmp-monitor -- --allowlist 10.0.0.9,10.0.0.10  # IPs de monitoreo legítimas
# Analizar una captura guardada, sin privilegios y sin tocar BD ni enviar alertas:
npm run icmp-monitor -- --file captura.txt --dry-run
```

| Señal | Qué significa | Nivel |
|-------|---------------|-------|
| `PATTERN_STEPPING` | ≥ 8 patrones distintos en 10 min entre las mismas IPs (≥ 20 → crítico): los datos "avanzan" ping a ping | high / critical |
| `SLOW_PATTERN_STEPPING` | ≥ 40 patrones distintos en 6 h (≥ 100 → crítico): exfiltración lenta para esquivar la ventana corta | high / critical |
| `HIGH_ENTROPY_PAYLOAD` | Payloads con aspecto de datos cifrados/comprimidos (túneles ICMP) | high / critical |
| `OVERSIZED_PAYLOAD` | Varios payloads no estándar de más de 128 bytes | high / critical |
| `MODIFIED_REPLY` | El echo-reply no refleja el payload del request (las pilas legítimas lo reflejan siempre) | high |
| `NON_STANDARD_FLOOD` | ≥ 60 pings no estándar por minuto | medium |

Cada alerta indica la dirección (`egress` = sale de esta máquina → **investiga el host**; `ingress` = entra), las razones, estadísticas y una muestra de patrones como evidencia. El mismo par de IPs no vuelve a alertar del mismo nivel hasta pasar 30 min.

Al detectar una alerta (sin `--dry-run`) el monitor la guarda cifrada en `security_logs` (visible en `GET /api/system/logs`) y envía una alerta camuflada por los canales configurados. Con `--autoblock` además bloquea en la capa HTTP las IPs externas (`ingress`) con alertas ≥ high. **Está desactivado por defecto** porque la IP de origen de un paquete ICMP se puede falsificar: un atacante podría hacer que bloquees a una IP inocente. **Nunca bloquea nada en `egress`**: la IP es la propia máquina y lo que hay que hacer es aislarla e investigar.

Servicio systemd para el monitor (usuario propio con solo la capacidad de captura):

```ini
[Service]
User=icmpmon
WorkingDirectory=/opt/secure-server
ExecStart=/usr/bin/node scripts/icmpMonitor.js --interface eth0
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN
NoNewPrivileges=true
Restart=always
```

### Despliegue recomendado

1. `npm run icmp-firewall` (dry-run) y revisa las reglas con tus destinos reales.
2. Ejecuta `icmp-monitor` unos días con `--dry-run` y ajusta la `--allowlist` si alguna herramienta de monitoreo legítima genera alertas (algunas usan payloads propios).
3. Aplica el firewall (`--apply`) y activa el monitor como servicio.
4. Endurece el proceso (sin root, sin `NET_RAW`, `ping_group_range`) hasta que `networkPosture.hardened` sea `true`.

### Capa 4 — El servidor no puede lanzar `ping`

Para ejecutar `ping -p` desde el servidor, el atacante primero necesita ejecución de comandos. Por eso `src/` **no usa `child_process`** y un test (`npm run test:icmp`) falla si alguien lo añade. Si algún día necesitas ejecutar un proceso, hazlo en un servicio aparte con sus propios permisos. El monitor (`scripts/`) sí lanza `tcpdump`, con argumentos fijos y sin shell.

### Límites que conviene conocer

- **Es heurístico.** Detecta el uso de `ping -p` y herramientas parecidas; no demuestra que no haya exfiltración. Un atacante que envíe pings con el payload estándar y codifique datos en otros campos (`id`/`seq`) o en los tiempos entre pings no queda cubierto por el análisis de payload; el firewall de la capa 1 sí limita ese canal por tasa y destino.
- **Solo ICMP.** La exfiltración por DNS, HTTP(S) u otros protocolos necesita su propia vigilancia de salida (un firewall con política de salida denegada por defecto es la base).
- **El ancho de banda del ataque es mínimo** (≤ 16 bytes por ping): con el firewall limitando a 6 pings/min hacia destinos de confianza, un archivo de 1 MB tardaría más de 7 días en salir… si el atacante tuviera a dónde enviarlo.
- **Qué está probado.** `npm run test:icmp` (24 tests, sin privilegios) cubre el análisis, el detector, el parser y el monitor sobre capturas sintéticas. El firewall se verificó en un namespace de red aislado con paquetes ICMP reales (pasa lo permitido, descarta tamaño excesivo y destinos no autorizados). **La captura en vivo con `tcpdump` y los payloads estándar de cada sistema operativo no se han probado contra tráfico real**: valida con una captura tuya (`--dry-run`) antes de confiar en las alertas.

---

## 🔄 Rotación de claves, migración de datos y backups

### ⚠️ Leer primero: las claves cambiaban cada día

Hasta ahora las claves de cifrado se derivaban de `BASE_SEED` **y de la fecha UTC de hoy**. Un dato cifrado un martes no se podía descifrar el miércoles (se comprobó: `Error en triple descifrado`), y los JWT dejaban de valer a medianoche aunque duraran 5 días. Para que cualquier rotación tenga sentido las claves tienen que ser **estables** hasta que decidas rotarlas. Ahora lo son si defines `KEY_EPOCH`:

| Variable | Qué es | ¿La cambia la rotación? |
|----------|--------|-------------------------|
| `KEY_EPOCH` | Etiqueta de la generación de claves (p. ej. `E20261101T020000Z`). **Su presencia activa el modo estable.** | Sí |
| `ENCRYPTION_SEED` | Semilla de la clave de cifrado de datos | Sí |
| `JWT_SEED` | Semilla del secreto de los JWT | Sí |
| `BASE_SEED` | Sal de `users.username_hash` (búsqueda de login) y parte de todas las claves | **No**: cambiarla invalidaría todos los hashes de login |

Sin `KEY_EPOCH` el sistema sigue en **modo legacy** (comportamiento anterior, claves diarias) para no romper instalaciones existentes. `npm run rotate-keys -- status` te dice en qué modo estás.

**Si ya tienes datos cifrados (modo legacy), migra así:**

```bash
# 1. Esquema: marcador de claves y columna de auditoría (esta última arregla además un bug, ver abajo)
mysql ... < database/migrations/002_crypto_meta.sql
mysql ... < database/migrations/003_security_logs_encrypted_timestamp.sql
# 2. Copia de seguridad de la BD y del .env con tus herramientas habituales (mysqldump...)
# 3. Ensayo: busca la clave de cada fila en los últimos 30 días SIN cambiar nada
npm run rotate-keys -- analyze --legacy-scan-days 30
# 4. Migración real a claves estables
npm run rotate-keys -- rotate --confirm --legacy-scan-days 30
```

Cada fila se prueba primero con las claves de la fecha de sus propias marcas de tiempo (±1 día) y después hacia atrás desde hoy. Si alguna fila se cifró con una clave anterior al rango, **toda la migración aborta sin cambiar nada** y te dice qué fila (`tabla.columna`, `id`) para que amplíes `--legacy-scan-days` o la repares.

> **Bug corregido de paso:** `security_logs.encrypted_timestamp` era `DATETIME` pero el código guarda ahí texto cifrado. En MySQL/MariaDB en modo estricto (el predeterminado) **cada evento de auditoría de `auth.controller` se perdía en silencio** (`Incorrect datetime value`; en una prueba con el servidor real se perdieron 26 eventos en unos minutos). La migración 003 lo pasa a `LONGTEXT`.

### Qué hace una rotación

```bash
npm run rotate-keys -- rotate --confirm
```

| # | Paso | Detalle |
|---|------|---------|
| 1 | **Cierre** | Lock de mantenimiento: todos los procesos del servidor responden `503` (incluido `/health`) y dejan de ejecutar tareas que escriben. Lock en la BD (`GET_LOCK`) contra rotaciones concurrentes. Todas las sesiones se expiran. Espera `--drain` s (10) a las peticiones en curso |
| 2 | **Backup previo** | Snapshot de **toda** la BD → comprimido → cifrado con la **clave anterior** → releído y verificado antes de seguir |
| 3 | **Backups viejos** | Los backups de meses anteriores se re-cifran con la **clave nueva** (sin descomprimirlos) |
| 4 | **Re-cifrado** | Todas las columnas de `encrypted-columns.js`, en **una transacción**: se descifra con la clave antigua y se cifra con la nueva **en memoria**; se verifica cada valor |
| 5 | **Confirmación en dos fases** | Lo que debe cambiar de sitio (backups, keyring, `.env`) se prepara en temporales **antes** del `COMMIT` y se renombra **después**. Un journal registra la fase |
| 6 | **Barrido y reapertura** | Un último pase re-cifra cualquier valor que un proceso rezagado escribiera con la clave antigua; el nuevo `.env` queda activo, se recargan las claves y se quita el lock |

El servidor (si está corriendo) se reabre solo: cada 5 s comprueba el lock y compara la huella de su clave en memoria con la de `crypto_meta`; si no coinciden recarga el `.env`, y si aun así no coinciden **se niega a atender** (`503 KEYS_OUT_OF_SYNC`) en lugar de escribir datos con una clave equivocada. En una prueba con el servidor real, durante una rotación de 12 s hubo `503` desde el cierre hasta ~3 s después de terminar el CLI, **0 respuestas 5xx**, y tras ella el mismo login, las notas anteriores y las nuevas funcionaron.

### Decisiones de diseño (y por qué no es exactamente lo que se describió)

**Sobre "cerrar la red y el PC".** Se implementan dos capas: el **modo mantenimiento** de la aplicación (503 a todo) y, opcionalmente, un **bloqueo de red** con `--lockdown-firewall`, que descarta las conexiones *entrantes nuevas* salvo loopback, conexiones ya establecidas y tus IPs de administración (`MAINTENANCE_ADMIN_IPS`). No se apaga ni se bloquea la máquina: sin acceso del administrador no se podría vigilar, completar ni deshacer la migración. El script se niega a aplicarse sin IPs de administración, y las reglas se quitan solas pasados `--firewall-ttl` minutos (120) aunque el proceso muera.

**Sobre "pasar a datos no cifrados y borrar los registros no cifrados".** El texto plano **nunca se escribe en disco ni en logs**: se descifra y se vuelve a cifrar en memoria, valor a valor. No hay nada que borrar después, que es más seguro que borrarlo: en SSD, sistemas de archivos con journaling o copias de seguridad del hosting, "borrar" un archivo no destruye su contenido. (Node no puede garantizar poner a cero los strings en memoria; el proceso es corto y no vuelca nada.) Además se retiraron de los logs valores que se imprimían en claro: fragmentos de la URL de la BD, contraseñas de email y tokens (`credential-builder`/`database`), y nombres de usuario (`auth.controller`, `secure-auth.service`).

**Sobre el backup "comprimido al máximo".** Se comprime con **brotli (calidad 11)** y **gzip (nivel 9)** y se guarda el que menos ocupe. No se usa ZIP ni RAR: ZIP/deflate comprime peor que brotli y RAR es un formato propietario sin soporte en Node. Dos detalles importantes:
- **Se comprime antes de cifrar**, porque el texto cifrado no se comprime (parece aleatorio).
- **No se usa `tripleEncryptor` para el archivo**: devuelve texto hex y cada nivel vuelve a pasar a hex la salida del anterior, así que la salida llega a ocupar ~8 veces la entrada. El archivo usa **una capa AES-256-GCM binaria** (28 bytes de sobrecarga) con la cabecera autenticada: cambiar un solo byte hace que falle el descifrado. En las pruebas, 2 000 filas repetitivas ocupan menos de la quinta parte comprimidas y cifradas, y la BD de ejemplo pasa de 10,4 KB a 1,4 KB.

**El backup guarda las columnas cifradas ya descifradas** (el archivo completo sí va comprimido y cifrado). Si dentro hubiera texto cifrado con la clave antigua, cada backup necesitaría esa clave para siempre, y "re-cifrarlo con la clave nueva" solo cambiaría la capa de fuera. Así, una sola clave abre cualquier backup.

### La cadena mensual de backups

El backup de cada mes se cifra con la clave que acaba de dejar de ser la vigente ("copia de esas claves"), y **al mes siguiente se re-cifra con la nueva**. Para poder hacerlo, la clave anterior se guarda en `backups/keyring.json`, **envuelta con la clave actual**:

| Tras la rotación de… | Backup de ene | Backup de feb | Backup de mar | Keyring (guarda…) |
|----------------------|---------------|---------------|---------------|-------------------|
| **Enero** (K0→K1) | clave **K0** | | | K0, envuelta con K1 |
| **Febrero** (K1→K2) | clave **K2** | clave **K1** | | K1, envuelta con K2 |
| **Marzo** (K2→K3) | clave **K3** | clave **K3** | clave **K2** | K2, envuelta con K3 |

Con **solo la clave actual** (más el keyring) se abre cualquier backup, y no queda ninguna clave antigua suelta en disco. Si rotas porque la clave anterior **se ha comprometido**, usa `--backup-key new`: el backup de este mes también se cifra con la clave nueva (de lo contrario seguiría abierto para quien tenga la antigua hasta el mes siguiente).

### Uso

```bash
npm run rotate-keys -- status                   # modo de claves, lock, journal, backups
npm run rotate-keys -- analyze                  # ensayo: ¿se puede descifrar todo? (no cambia nada)
npm run rotate-keys -- rotate --confirm         # rotación completa
npm run rotate-keys -- rotate --confirm --lockdown-firewall   # + bloqueo de red (root y MAINTENANCE_ADMIN_IPS)
npm run rotate-keys -- backups                  # lista de backups (tamaño, algoritmo, época, filas)
npm run rotate-keys -- verify backups/<archivo>.sbk
npm run rotate-keys -- restore backups/<archivo>.sbk --confirm RESTORE [--tables users,user_notes]
```

Opciones de `rotate`: `--no-write-env`, `--backup-key old|new`, `--drain N`, `--legacy-scan-days N`, `--keep-backups N` (por defecto se conservan **todos**; los backups crecen cada mes), `--firewall-ttl N`, `--no-notify`, `--env-file ruta`. La cabecera de `scripts/rotateKeys.js` las documenta.

**Rotación mensual automática:** con `AUTO_ROTATION_ENABLED=true` el servidor rota el día 1 de cada mes a las 02:00 (México) dentro de su propio proceso (se pone en mantenimiento, rota, recarga las claves en memoria y se reabre; `BACKUP_RETENTION=N` limita los backups). Requiere un `.env` escribible y **una sola instancia** con esa variable activa. Alternativa más conservadora: déjala en `false` y programa `npm run rotate-keys -- rotate --confirm` con cron/systemd.

**Claves en el panel del hosting (sin `.env` escribible):** usa `--no-write-env`. La rotación re-cifra los datos pero no toca el `.env`: deja las variables nuevas en `data/rotation/new-env-*.txt` (permisos 600) y **el servidor sigue cerrado**. Aplica `ENCRYPTION_SEED`, `JWT_SEED` y `KEY_EPOCH` en el panel, reinicia, ejecuta `npm run rotate-keys -- finish` (comprueba que coinciden con la BD antes de reabrir) y borra ese archivo.

`/api/system/rotate-keys` ya **no** lanza la rotación por HTTP (responde `501`): una operación que bloquea el servidor y reescribe el `.env` no debe depender de una petición web. `GET /api/system/rotation` (admin) muestra el estado y los backups, sin claves ni datos.

### Si algo falla

| Dónde falló | Estado | Qué ocurre |
|-------------|--------|------------|
| Antes del `COMMIT` (dato ilegible, disco lleno, error de BD…) | La BD **no cambió** | Rollback, se borran los temporales, se quita el lock y el servidor se reabre con las claves anteriores. El backup ya creado se conserva |
| `COMMIT` ambiguo (se pierde la respuesta) | Puede que la BD sí confirmara | **No** se deshace a ciegas: se pregunta a la BD por la huella; si confirmó, se trata como confirmado |
| Después del `COMMIT` | La BD ya usa las claves nuevas | Sigue **cerrado**; `npm run rotate-keys -- recover` termina de colocar los archivos y reabre |
| El proceso muere | Lock y journal quedan en `data/rotation/` | Sigue cerrado (el lock **no caduca solo**); `recover` decide según la huella de la BD si termina o deshace |

Mantener el servidor cerrado ante la duda es deliberado: reabrirlo a medias de una migración corrompería datos.

### Restaurar un backup

`restore` sustituye el contenido de las tablas por el del backup (en una transacción), re-cifrando con la clave **actual**, aunque el backup sea de otra época. Bloquea el servidor mientras dura y cierra las sesiones. Omite `crypto_meta` y `user_sessions`. Usa `--tables` para restaurar solo algunas. Pruébalo con `verify` antes de necesitarlo de verdad.

### Si añades tablas o columnas cifradas

**Registra cada columna que guarde datos cifrados con `tripleEncryptor` en `src/crypto/encrypted-columns.js`.** La rotación solo re-cifra lo registrado: lo que falte quedaría cifrado con una clave que ya no existe (irrecuperable). `npm run test:rotation` falla si `database/schema.sql` tiene una columna de texto con "encrypted" en el nombre que no esté registrada. Esto está también en la guía "Cómo crear una API nueva".

### Límites y qué está probado

**Probado** (`npm run test:rotation`: 46 tests; se omiten si no hay BD, y entonces las suites salen "verdes" con pruebas omitidas: comprueba que `skipped` sea 0):
- Contra **MariaDB 10.11 y MySQL 8.0.46 reales** (las tres suites: 82/82 en cada motor, 0 omitidas): rotaciones encadenadas, backups por mes, fallos antes/durante/después del commit, `COMMIT` ambiguo, `recover`, migración legacy, restauración, guardián y CLI. Los tests se verificaron con mutaciones deliberadas.
- **`kill -9` en 44 instantes aleatorios** de la rotación (incluido justo tras el commit y durante la liberación del lock): en todos, tras `recover`, los datos íntegros y legibles, huella coherente, lock liberado y sin temporales sueltos.
- **Escrituras concurrentes**: con el servidor real y 8 escritores durante la rotación (≈63 000 peticiones), 0 escrituras confirmadas perdidas o corruptas y 0 respuestas 5xx.
- **El job mensual real** (`executeMonthlyRotation`) y el servidor real (login, notas, endpoints de administrador).

**Rendimiento medido** (no estimado): una BD de **83 MB** (30 000 filas, 70 000 valores cifrados) tardó **75 s** en rotar, con el servidor cerrado todo ese tiempo, y el proceso llegó a **593 MB de RAM** (≈7 veces el tamaño de la BD, porque el snapshot y su compresión van en memoria). Extrapolando de forma lineal, 1 GB de datos serían ≈15 min de cierre y ≈7 GB de RAM: **este diseño sirve para bases de datos de decenas o pocos cientos de MB**, no para bases grandes. Con carga concurrente el tiempo se multiplica (58 s en lugar de 5 s en una BD pequeña).

**No probado:**
- Bases de datos grandes (>100 MB), y varias máquinas reales compartiendo la BD (solo se probó el mecanismo con el lock de la BD, no un despliegue multi-host).
- Que el firewall de mantenimiento bloquee tráfico externo real (se verificó que las reglas se aplican, son idempotentes y se retiran en un entorno de red aislado).
- La ejecución automática del día 1 con el reloj real (sí se ejecutó el job y se comprobó que el planificador se registra con la próxima fecha).
- El flujo `--no-write-env` con un panel de hosting real (se probó con las variables aplicadas a mano en el test).

**Cosas a tener en cuenta:**
- **Ningún proceso con un `.env` distinto debe escribir en la misma BD** (un script lanzado con otras claves, o con claves legacy): deja datos que la rotación no puede descifrar. La rotación aborta sin cambiar nada y el mensaje indica el registro; si es regenerable (`server_integrity`) se puede borrar, si no, hay que restaurarlo.
- **Varias máquinas**: el guardián ve también el lock de la BD (`GET_LOCK`), así que todas se cierran durante la rotación; las que no tengan las claves nuevas después se quedan en `503 KEYS_OUT_OF_SYNC`. Aun así, lo recomendable es una sola instancia con `AUTO_ROTATION_ENABLED=true`.
- `recover` se niega si hay una rotación en curso (comprueba que el pid del lock siga vivo en esa máquina) y no toca locks de otro host sin `--force`.
- Si la BD no soporta SSL en `production`, `database.js` cae silenciosamente a una conexión **sin SSL** (`rejectUnauthorized: false` + *fallback*). Es comportamiento previo, pero conviene revisarlo.
- El límite de 10 peticiones/min **por IP** en login/registro (y en las operaciones de `highSecurity`) es **un único contador compartido**: varios usuarios detrás de la misma IP (una oficina, un NAT) se bloquean entre sí, y un atacante puede dejar sin login a toda esa IP. Es comportamiento previo.

---

## 🚀 Instrucciones Finales de Despliegue

### 1. Preparación para Producción
```bash
# 1. Clonar/crear el proyecto
git init
git add .
git commit -m "Initial commit: Ultra Secure Server"

# 2. Instalar dependencias
npm install

# 3. Crear base de datos
# Ejecutar el esquema SQL en tu base de datos MySQL

# 4. Configurar variables de entorno en tu hosting
# Ver sección "Variables de Entorno Seguras"

# 5. Ejecutar tests
npm run test

# 6. Iniciar en modo desarrollo (local)
npm run dev

# 7. Iniciar en producción
npm start
```

### 2. Comandos Útiles
```bash
# Verificar estado del sistema
npm run check-system

# Rotar claves (con migración de datos y backup; ver la sección de rotación)
npm run rotate-keys -- status
npm run rotate-keys -- rotate --confirm

# Descifrar mensaje recibido
npm run decrypt-message -- --text "mensaje_camuflado"

# Crear backup de emergencia
npm run emergency-backup

# Auditoría de seguridad
npm run security-audit

# Dar rol de administrador a un usuario
npm run set-role -- --user-id 1 --role admin

# Tests de la capa de APIs (sin MySQL)
npm run test:api

# Defensa ICMP: tests, firewall (dry-run) y monitor
npm run test:icmp
npm run icmp-firewall
sudo npm run icmp-monitor
```

### 3. Monitoreo Post-Despliegue
- Revisa los logs en tiempo real
- Verifica que lleguen las notificaciones de prueba
- Confirma que la rotación automática esté programada
- Realiza tests de penetración básicos

---

## 🔐 Características de Seguridad Implementadas

✅ **Cifrado multicapa** (AES-256-CBC + AES-256-GCM + ChaCha20-Poly1305)  
✅ **Rotación automática de claves** (programada mensualmente)  
✅ **Detección de anomalías en tiempo real**  
✅ **Bloqueo automático de IPs maliciosas**  
✅ **Verificación de integridad del servidor**  
✅ **Comunicaciones seguras multi-canal**  
✅ **Camuflaje de mensajes críticos**  
✅ **Rate limiting dinámico**  
✅ **Autenticación con análisis de riesgo**  
✅ **Logs de seguridad cifrados**  
✅ **Scripts de recuperación de emergencia**  
✅ **Monitoreo de sesiones sospechosas**  
✅ **APIs extensibles**: cada `*.routes.js` se monta solo, con JWT, validación, roles, cifrado y auditoría  
✅ **Control de acceso por roles** (`user` / `admin`)  
✅ **Rotación de claves con migración de datos**: modo mantenimiento, backup mensual comprimido y cifrado, re-cifrado transaccional y recuperación ante fallos  
✅ **Defensa contra exfiltración por ICMP** (`ping -p`): firewall, detector de patrones y verificación de postura de red  

---

¡Tu sistema ultra seguro está listo para proteger los datos más críticos! 🛡️🔐