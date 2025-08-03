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
            /(\.\.\/){3,}/i,
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