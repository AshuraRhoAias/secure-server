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