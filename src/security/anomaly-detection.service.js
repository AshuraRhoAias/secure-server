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
        const requestRate = this.getRequestRate(fingerprint.ip, fingerprint);
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

    getRequestRate(ip, fingerprint) {
        const now = Date.now();
        const timeWindow = 60 * 1000; // 1 minuto

        if (!this.requestHistory.has(ip)) {
            this.requestHistory.set(ip, []);
        }

        const requests = this.requestHistory.get(ip);

        // Filtrar requests del último minuto
        const recentRequests = requests.filter(req =>
            now - (req.timestamp || req) < timeWindow
        );

        // Agregar request actual con información completa
        recentRequests.push({
            timestamp: now,
            path: fingerprint.path,
            method: fingerprint.method,
            userAgent: fingerprint.userAgent,
            browser: fingerprint.browser,
            os: fingerprint.os
        });

        // Actualizar historial
        this.requestHistory.set(ip, recentRequests);

        return recentRequests.length;
    }

    getNavigationPattern(ip) {
        if (!this.requestHistory.has(ip)) {
            return { paths: [], timestamps: [], requestCount: 0 };
        }

        const requests = this.requestHistory.get(ip);
        const now = Date.now();
        const timeWindow = 10 * 60 * 1000; // 10 minutos

        // Obtener requests recientes con sus rutas
        const recentRequests = requests.filter(req => {
            const timestamp = req.timestamp || req;
            return now - timestamp < timeWindow;
        });

        return {
            paths: recentRequests.map(req => req.path || '/'),
            timestamps: recentRequests.map(req => req.timestamp || req),
            requestCount: recentRequests.length,
            methods: recentRequests.map(req => req.method || 'GET')
        };
    }

    isNavigationAnomalous(navigationPattern) {
        if (!navigationPattern.paths || navigationPattern.paths.length === 0) {
            return false;
        }

        const uniquePaths = new Set(navigationPattern.paths);
        const pathVariety = uniquePaths.size;
        const totalRequests = navigationPattern.paths.length;

        // Anomalías posibles:
        // 1. Demasiada variedad de rutas en poco tiempo
        if (pathVariety > 20 && totalRequests > 50) {
            return true;
        }

        // 2. Acceso repetitivo a la misma ruta (posible bot)
        const pathCounts = {};
        navigationPattern.paths.forEach(path => {
            pathCounts[path] = (pathCounts[path] || 0) + 1;
        });

        const maxRepeats = Math.max(...Object.values(pathCounts));
        if (maxRepeats > 30) { // Más de 30 requests a la misma ruta
            return true;
        }

        // 3. Secuencia de rutas sospechosa (crawling/scanning)
        const suspiciousPatterns = [
            /\/admin/i,
            /\/wp-admin/i,
            /\/wp-content/i,
            /\/config/i,
            /\/backup/i,
            /\/db/i,
            /\.env/i,
            /\.git/i,
            /\/api\/.*\/.*\/.*\//i, // Muchos niveles de API
            /\/phpmyadmin/i,
            /\/cpanel/i,
            /\/cgi-bin/i
        ];

        const suspiciousRequests = navigationPattern.paths.filter(path =>
            suspiciousPatterns.some(pattern => pattern.test(path))
        );

        if (suspiciousRequests.length > 5) {
            return true;
        }

        // 4. Velocidad de navegación anómala (demasiado rápida para ser humana)
        if (navigationPattern.timestamps.length > 1) {
            const timeDiffs = [];
            for (let i = 1; i < navigationPattern.timestamps.length; i++) {
                timeDiffs.push(navigationPattern.timestamps[i] - navigationPattern.timestamps[i - 1]);
            }

            const avgTimeBetweenRequests = timeDiffs.reduce((a, b) => a + b, 0) / timeDiffs.length;

            // Si el promedio es menos de 100ms entre requests, es sospechoso
            if (avgTimeBetweenRequests < 100 && totalRequests > 10) {
                return true;
            }
        }

        return false;
    }

    detectGeographicAnomaly(fingerprint) {
        const ip = fingerprint.ip;

        if (!this.deviceFingerprints.has(ip)) {
            // Primer acceso desde esta IP
            this.deviceFingerprints.set(ip, {
                locations: [{
                    country: fingerprint.country,
                    city: fingerprint.city,
                    timestamp: fingerprint.timestamp,
                    browser: fingerprint.browser,
                    os: fingerprint.os
                }],
                lastSeen: fingerprint.timestamp
            });
            return { isAnomalous: false };
        }

        const history = this.deviceFingerprints.get(ip);
        const lastLocation = history.locations[history.locations.length - 1];
        const timeDiff = fingerprint.timestamp - lastLocation.timestamp;

        // Agregar nueva ubicación
        history.locations.push({
            country: fingerprint.country,
            city: fingerprint.city,
            timestamp: fingerprint.timestamp,
            browser: fingerprint.browser,
            os: fingerprint.os
        });
        history.lastSeen = fingerprint.timestamp;

        // Mantener solo los últimos 10 registros de ubicación
        if (history.locations.length > 10) {
            history.locations = history.locations.slice(-10);
        }

        // Detectar cambio geográfico imposible
        // Si el país cambió en menos de 1 hora, es sospechoso
        if (lastLocation.country !== fingerprint.country &&
            lastLocation.country !== 'Unknown' &&
            fingerprint.country !== 'Unknown' &&
            timeDiff < 60 * 60 * 1000) {

            return {
                isAnomalous: true,
                previousLocation: `${lastLocation.city}, ${lastLocation.country}`,
                currentLocation: `${fingerprint.city}, ${fingerprint.country}`,
                timeDifference: timeDiff,
                timeDifferenceHours: Math.round(timeDiff / (60 * 60 * 1000) * 100) / 100,
                reason: 'IMPOSSIBLE_TRAVEL_TIME'
            };
        }

        // Detectar múltiples países en poco tiempo
        const recentLocations = history.locations.filter(loc =>
            fingerprint.timestamp - loc.timestamp < 24 * 60 * 60 * 1000 // Últimas 24 horas
        );

        const uniqueCountries = new Set(recentLocations.map(loc => loc.country));
        if (uniqueCountries.size > 3) { // Más de 3 países en 24 horas
            return {
                isAnomalous: true,
                reason: 'MULTIPLE_COUNTRIES_24H',
                countries: Array.from(uniqueCountries),
                timeWindow: '24 hours'
            };
        }

        return { isAnomalous: false };
    }

    detectDeviceChange(fingerprint) {
        const ip = fingerprint.ip;

        if (!this.deviceFingerprints.has(ip)) {
            return { isAnomalous: false };
        }

        const history = this.deviceFingerprints.get(ip);

        // Obtener el último dispositivo conocido
        const lastDevice = history.locations.length > 1 ?
            history.locations[history.locations.length - 2] : null;

        if (!lastDevice) {
            return { isAnomalous: false };
        }

        // Comparar características del dispositivo
        const browserChanged = fingerprint.browser !== lastDevice.browser;
        const osChanged = fingerprint.os !== lastDevice.os;
        const deviceChanged = browserChanged || osChanged;

        if (deviceChanged) {
            const timeDiff = fingerprint.timestamp - lastDevice.timestamp;

            // Si el dispositivo cambió en menos de 30 minutos, es sospechoso
            if (timeDiff < 30 * 60 * 1000) {
                return {
                    isAnomalous: true,
                    previousDevice: {
                        browser: lastDevice.browser,
                        os: lastDevice.os
                    },
                    currentDevice: {
                        browser: fingerprint.browser,
                        os: fingerprint.os
                    },
                    timeDifference: timeDiff,
                    timeDifferenceMinutes: Math.round(timeDiff / (60 * 1000)),
                    reason: 'RAPID_DEVICE_CHANGE',
                    changedFields: {
                        browser: browserChanged,
                        os: osChanged
                    }
                };
            }
        }

        return { isAnomalous: false };
    }

    detectMaliciousPayload(req) {
        const maliciousPatterns = [
            // SQL Injection
            {
                pattern: /(\bUNION\b.*\bSELECT\b|\bDROP\b.*\bTABLE\b|\bINSERT\b.*\bINTO\b)/i,
                type: 'SQL_INJECTION'
            },
            {
                pattern: /(\bOR\b.*\b1\s*=\s*1\b|\bAND\b.*\b1\s*=\s*1\b)/i,
                type: 'SQL_INJECTION'
            },
            {
                pattern: /(\bSELECT\b.*\bFROM\b.*\bWHERE\b)/i,
                type: 'SQL_INJECTION'
            },

            // XSS
            {
                pattern: /<script.*?>.*?<\/script>/i,
                type: 'XSS'
            },
            {
                pattern: /javascript:/i,
                type: 'XSS'
            },
            {
                pattern: /on\w+\s*=/i,
                type: 'XSS'
            },
            {
                pattern: /<iframe.*?>/i,
                type: 'XSS'
            },

            // Path Traversal
            {
                pattern: /(\.\.\/){3,}/i,
                type: 'PATH_TRAVERSAL'
            },
            {
                pattern: /etc\/passwd/i,
                type: 'PATH_TRAVERSAL'
            },
            {
                pattern: /\.\.\\.*\.\.\\.*\.\.\\/i,
                type: 'PATH_TRAVERSAL'
            },

            // Code Injection
            {
                pattern: /eval\s*\(/i,
                type: 'CODE_INJECTION'
            },
            {
                pattern: /exec\s*\(/i,
                type: 'CODE_INJECTION'
            },
            {
                pattern: /cmd\s*=/i,
                type: 'CODE_INJECTION'
            },
            {
                pattern: /system\s*\(/i,
                type: 'CODE_INJECTION'
            },

            // NoSQL Injection
            {
                pattern: /\$where/i,
                type: 'NOSQL_INJECTION'
            },
            {
                pattern: /\$ne/i,
                type: 'NOSQL_INJECTION'
            },
            {
                pattern: /\$gt/i,
                type: 'NOSQL_INJECTION'
            },
            {
                pattern: /\$lt/i,
                type: 'NOSQL_INJECTION'
            }
        ];

        const payloadString = JSON.stringify({
            body: req.body,
            query: req.query,
            params: req.params,
            url: req.url,
            headers: req.headers
        });

        for (const patternObj of maliciousPatterns) {
            if (patternObj.pattern.test(payloadString)) {
                return {
                    detected: true,
                    pattern: patternObj.pattern.toString(),
                    payload: payloadString.substring(0, 500),
                    type: patternObj.type,
                    location: this.findPatternLocation(patternObj.pattern, req)
                };
            }
        }

        return { detected: false };
    }

    findPatternLocation(pattern, req) {
        const locations = [];

        if (req.body && pattern.test(JSON.stringify(req.body))) {
            locations.push('body');
        }
        if (req.query && pattern.test(JSON.stringify(req.query))) {
            locations.push('query');
        }
        if (req.params && pattern.test(JSON.stringify(req.params))) {
            locations.push('params');
        }
        if (req.url && pattern.test(req.url)) {
            locations.push('url');
        }
        if (req.headers && pattern.test(JSON.stringify(req.headers))) {
            locations.push('headers');
        }

        return locations;
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
        try {
            const db = require('../config/database');
            const tripleEncryptor = require('../crypto/tripleEncryptor');

            for (const anomaly of anomalies) {
                // Log de la anomalía
                const logData = {
                    anomaly,
                    fingerprint,
                    timestamp: new Date().toISOString(),
                    riskScore: this.calculateRiskScore(anomaly)
                };

                const encryptedDetails = tripleEncryptor.encrypt(JSON.stringify(logData));

                await db.query(
                    `INSERT INTO security_logs (event_type, encrypted_details, ip_address, severity, risk_score) 
                     VALUES (?, ?, ?, ?, ?)`,
                    [anomaly.type, encryptedDetails, fingerprint.ip, anomaly.severity, logData.riskScore]
                );

                // Auto-bloquear para amenazas críticas
                if (anomaly.severity === 'critical') {
                    await this.blockIP(fingerprint.ip, anomaly.type);
                }

                console.log(`🚨 Anomalía detectada: ${anomaly.type} - Severidad: ${anomaly.severity} - IP: ${fingerprint.ip}`);
            }
        } catch (error) {
            console.error('❌ Error manejando anomalías:', error);
        }
    }

    async blockIP(ip, reason) {
        try {
            const db = require('../config/database');
            const blockDuration = 24 * 60 * 60 * 1000; // 24 horas
            const blockedUntil = new Date(Date.now() + blockDuration);

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

        try {
            const db = require('../config/database');
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
            const recentRequests = requests.filter(req => {
                const timestamp = req.timestamp || req;
                return now - timestamp < maxAge;
            });

            if (recentRequests.length === 0) {
                this.requestHistory.delete(ip);
            } else {
                this.requestHistory.set(ip, recentRequests);
            }
        }

        // Limpiar device fingerprints antiguos
        for (const [ip, data] of this.deviceFingerprints.entries()) {
            if (now - data.lastSeen > maxAge) {
                this.deviceFingerprints.delete(ip);
            }
        }

        console.log('🧹 Limpieza de datos de anomalías completada');
    }

    // Método para obtener estadísticas
    getStats() {
        return {
            activeIPs: this.requestHistory.size,
            blockedIPs: this.blockedIPs.size,
            trackedDevices: this.deviceFingerprints.size,
            uptime: process.uptime()
        };
    }

    // Método para desbloquear IP manualmente
    async unblockIP(ip) {
        try {
            const db = require('../config/database');
            await db.query('DELETE FROM blocked_ips WHERE ip_address = ?', [ip]);
            this.blockedIPs.delete(ip);
            console.log(`✅ IP ${ip} desbloqueada manualmente`);
            return true;
        } catch (error) {
            console.error('❌ Error desbloqueando IP:', error);
            return false;
        }
    }
}

module.exports = new AnomalyDetection();