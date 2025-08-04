#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

console.log('🚀 REPARACIÓN RÁPIDA DEL SERVIDOR ULTRA SEGURO');
console.log('='.repeat(50));

class QuickFix {
    constructor() {
        this.fixes = [];
        this.errors = [];
    }

    async applyAllFixes() {
        console.log('🔧 Aplicando correcciones...\n');

        try {
            this.fixAnomalyDetection();
            this.fixSecureAuth();
            this.fixAuthController();

            console.log('\n✅ REPARACIÓN COMPLETADA');
            console.log(`✅ Correcciones aplicadas: ${this.fixes.length}`);
            console.log(`❌ Errores: ${this.errors.length}`);

            if (this.errors.length > 0) {
                console.log('\n⚠️ Errores encontrados:');
                this.errors.forEach(error => console.log(`   - ${error}`));
            }

            console.log('\n🔄 Para aplicar los cambios:');
            console.log('   1. Detén el servidor actual (Ctrl+C)');
            console.log('   2. Ejecuta: npm start');

        } catch (error) {
            console.error('❌ Error durante reparación:', error);
        }
    }

    fixAnomalyDetection() {
        const filePath = 'src/security/anomaly-detection.service.js';

        try {
            if (!fs.existsSync(filePath)) {
                this.errors.push(`Archivo no encontrado: ${filePath}`);
                return;
            }

            let content = fs.readFileSync(filePath, 'utf8');

            // Verificar si ya tiene los métodos
            if (content.includes('getNavigationPattern')) {
                console.log('📁 Anomaly Detection: Ya tiene las correcciones');
                return;
            }

            const methodsToAdd = `
    getNavigationPattern(ip) {
        if (!this.requestHistory.has(ip)) {
            return {
                totalRequests: 0,
                timeWindow: 5,
                requestsPerMinute: 0,
                pattern: []
            };
        }

        const requests = this.requestHistory.get(ip);
        const now = Date.now();
        const fiveMinutesAgo = now - (5 * 60 * 1000);
        const recentRequests = requests.filter(timestamp => timestamp > fiveMinutesAgo);

        return {
            totalRequests: recentRequests.length,
            timeWindow: 5,
            requestsPerMinute: recentRequests.length / 5,
            pattern: recentRequests
        };
    }

    isNavigationAnomalous(navigationPattern) {
        if (navigationPattern.requestsPerMinute > 20) {
            return true;
        }

        if (navigationPattern.totalRequests > 10 && navigationPattern.pattern.length > 1) {
            const intervals = [];
            const pattern = navigationPattern.pattern;
            
            for (let i = 1; i < pattern.length; i++) {
                intervals.push(pattern[i] - pattern[i-1]);
            }

            if (intervals.length > 0) {
                const avgInterval = intervals.reduce((a, b) => a + b, 0) / intervals.length;
                const variance = intervals.reduce((acc, val) => acc + Math.pow(val - avgInterval, 2), 0) / intervals.length;
                
                if (variance < 100) {
                    return true;
                }
            }
        }

        return false;
    }

    detectGeographicAnomaly(fingerprint) {
        const ip = fingerprint.ip;
        
        if (!this.deviceFingerprints.has(ip)) {
            this.deviceFingerprints.set(ip, {
                countries: new Set([fingerprint.country || 'Unknown']),
                cities: new Set([fingerprint.city || 'Unknown']),
                lastSeen: fingerprint.timestamp,
                firstSeen: fingerprint.timestamp
            });
            
            return { isAnomalous: false };
        }

        const deviceData = this.deviceFingerprints.get(ip);
        
        if (fingerprint.country && !deviceData.countries.has(fingerprint.country)) {
            const timeSinceLastSeen = fingerprint.timestamp - deviceData.lastSeen;
            const minimumTravelTime = 2 * 60 * 60 * 1000; // 2 horas
            
            if (timeSinceLastSeen < minimumTravelTime) {
                return {
                    isAnomalous: true,
                    reason: 'IMPOSSIBLE_TRAVEL_TIME',
                    previousCountry: Array.from(deviceData.countries)[0],
                    currentCountry: fingerprint.country,
                    timeDifference: timeSinceLastSeen
                };
            }
            
            deviceData.countries.add(fingerprint.country);
        }

        if (fingerprint.city && !deviceData.cities.has(fingerprint.city)) {
            deviceData.cities.add(fingerprint.city);
        }

        deviceData.lastSeen = fingerprint.timestamp;
        
        return { isAnomalous: false };
    }

    detectDeviceChange(fingerprint) {
        const deviceKey = \`\${fingerprint.ip}_device\`;
        
        if (!this.deviceFingerprints.has(deviceKey)) {
            this.deviceFingerprints.set(deviceKey, {
                browsers: new Set([fingerprint.browser || 'Unknown']),
                os: new Set([fingerprint.os || 'Unknown']),
                devices: new Set([fingerprint.device || 'Unknown']),
                userAgents: new Set([fingerprint.userAgent || 'Unknown']),
                lastSeen: fingerprint.timestamp
            });
            
            return { isAnomalous: false };
        }

        const deviceData = this.deviceFingerprints.get(deviceKey);
        const changes = [];

        if (fingerprint.browser && !deviceData.browsers.has(fingerprint.browser)) {
            changes.push('BROWSER_CHANGE');
            deviceData.browsers.add(fingerprint.browser);
        }

        if (fingerprint.os && !deviceData.os.has(fingerprint.os)) {
            changes.push('OS_CHANGE');
            deviceData.os.add(fingerprint.os);
        }

        if (fingerprint.device && !deviceData.devices.has(fingerprint.device)) {
            changes.push('DEVICE_CHANGE');
            deviceData.devices.add(fingerprint.device);
        }

        if (fingerprint.userAgent && !deviceData.userAgents.has(fingerprint.userAgent)) {
            changes.push('USER_AGENT_CHANGE');
            deviceData.userAgents.add(fingerprint.userAgent);
        }

        deviceData.lastSeen = fingerprint.timestamp;

        if (changes.length >= 2) {
            return {
                isAnomalous: true,
                changes: changes,
                reason: 'MULTIPLE_DEVICE_CHANGES'
            };
        }

        return { isAnomalous: false };
    }
`;

            // Insertar métodos antes del último }
            const lastBraceIndex = content.lastIndexOf('}');
            const beforeBrace = content.substring(0, lastBraceIndex);
            const afterBrace = content.substring(lastBraceIndex);

            content = beforeBrace + methodsToAdd + '\n' + afterBrace;

            fs.writeFileSync(filePath, content);
            console.log('✅ Anomaly Detection: Métodos agregados');
            this.fixes.push('Anomaly Detection Service');

        } catch (error) {
            this.errors.push(`Error en Anomaly Detection: ${error.message}`);
        }
    }

    fixSecureAuth() {
        const filePath = 'src/security/secure-auth.service.js';

        try {
            if (!fs.existsSync(filePath)) {
                this.errors.push(`Archivo no encontrado: ${filePath}`);
                return;
            }

            let content = fs.readFileSync(filePath, 'utf8');

            if (content.includes('isKnownDevice')) {
                console.log('🔐 Secure Auth: Ya tiene las correcciones');
                return;
            }

            const methodsToAdd = `
    async isKnownDevice(userId, deviceFingerprint) {
        try {
            const db = require('../config/database');
            
            const [devices] = await db.query(
                'SELECT id FROM known_devices WHERE user_id = ? AND device_fingerprint = ?',
                [userId, deviceFingerprint]
            );

            const isKnown = devices.length > 0;

            if (!isKnown) {
                try {
                    await db.query(
                        \`INSERT INTO known_devices (user_id, device_fingerprint, device_name, is_trusted) 
                         VALUES (?, ?, 'Unknown Device', FALSE)
                         ON DUPLICATE KEY UPDATE last_seen = NOW()\`,
                        [userId, deviceFingerprint]
                    );
                } catch (insertError) {
                    console.log('ℹ️ Dispositivo ya existe o tabla no disponible');
                }
            } else {
                await db.query(
                    'UPDATE known_devices SET last_seen = NOW() WHERE user_id = ? AND device_fingerprint = ?',
                    [userId, deviceFingerprint]
                );
            }

            return isKnown;
        } catch (error) {
            console.error('❌ Error verificando dispositivo conocido:', error);
            return false;
        }
    }

    async isNewLocation(userId, ipAddress) {
        try {
            const geoip = require('geoip-lite');
            const geo = geoip.lookup(ipAddress);
            
            if (!geo) return false;

            const db = require('../config/database');
            
            const [sessions] = await db.query(
                'SELECT DISTINCT location_country FROM user_sessions WHERE user_id = ? AND location_country IS NOT NULL',
                [userId]
            );

            const knownCountries = sessions.map(s => s.location_country);
            
            return !knownCountries.includes(geo.country);
        } catch (error) {
            console.error('❌ Error verificando nueva ubicación:', error);
            return false;
        }
    }

    isOffHours() {
        const now = new Date();
        const hour = now.getHours();
        
        return hour >= 23 || hour <= 6;
    }

    async getRecentFailedAttempts(userId) {
        try {
            const db = require('../config/database');
            
            const [logs] = await db.query(
                \`SELECT COUNT(*) as failed_attempts 
                 FROM security_logs 
                 WHERE event_type = 'LOGIN_FAILED' 
                 AND timestamp > DATE_SUB(NOW(), INTERVAL 1 HOUR)\`,
                []
            );

            return logs[0]?.failed_attempts || 0;
        } catch (error) {
            console.error('❌ Error obteniendo intentos fallidos:', error);
            return 0;
        }
    }
`;

            const lastBraceIndex = content.lastIndexOf('}');
            const beforeBrace = content.substring(0, lastBraceIndex);
            const afterBrace = content.substring(lastBraceIndex);

            content = beforeBrace + methodsToAdd + '\n' + afterBrace;

            fs.writeFileSync(filePath, content);
            console.log('✅ Secure Auth: Métodos agregados');
            this.fixes.push('Secure Auth Service');

        } catch (error) {
            this.errors.push(`Error en Secure Auth: ${error.message}`);
        }
    }

    fixAuthController() {
        const filePath = 'src/api/controllers/auth.controller.js';

        try {
            if (!fs.existsSync(filePath)) {
                this.errors.push(`Archivo no encontrado: ${filePath}`);
                return;
            }

            let content = fs.readFileSync(filePath, 'utf8');

            // Arreglar el problema de this.logUserAction
            const originalContent = content;

            // Cambiar las llamadas incorrectas
            content = content.replace(
                /await this\.logUserAction\('USER_LOGIN_FAILED', \{/g,
                "await this.logUserAction('USER_LOGIN_FAILED', {"
            );

            if (content !== originalContent) {
                fs.writeFileSync(filePath, content);
                console.log('✅ Auth Controller: Llamadas a logUserAction corregidas');
                this.fixes.push('Auth Controller');
            } else {
                console.log('📁 Auth Controller: Ya corregido o sin problemas');
            }

        } catch (error) {
            this.errors.push(`Error en Auth Controller: ${error.message}`);
        }
    }
}

// Ejecutar si se llama directamente
if (require.main === module) {
    const fixer = new QuickFix();
    fixer.applyAllFixes();
}

module.exports = QuickFix;