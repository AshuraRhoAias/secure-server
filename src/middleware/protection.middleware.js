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

    getProtectionStats() {
        const now = Date.now();
        let activeWindows = 0;
        for (const data of this.rateLimits.values()) {
            if (now <= data.window) activeWindows++;
        }

        return {
            activeRateLimitWindows: activeWindows,
            trackedRateLimitEntries: this.rateLimits.size
        };
    }

    setupCleanup() {
        // Limpiar rate limits antiguos cada 5 minutos
        const timer = setInterval(() => {
            const now = Date.now();

            for (const [key, data] of this.rateLimits.entries()) {
                if (now > data.window) {
                    this.rateLimits.delete(key);
                }
            }
        }, 5 * 60 * 1000);

        // La limpieza no debe impedir que el proceso termine (tests, scripts)
        timer.unref();
    }
}

module.exports = new ProtectionMiddleware();