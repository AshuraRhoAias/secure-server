// Cargar variables de entorno PRIMERO y validar
const path = require('path');
const fs = require('fs');

// Verificar que el archivo .env existe
// ENV_FILE permite usar otro archivo (la rotación de claves y los tests lo usan)
const envPath = process.env.ENV_FILE ? path.resolve(process.env.ENV_FILE) : path.join(__dirname, '../.env');
if (!fs.existsSync(envPath)) {
    console.error('❌ ARCHIVO .env NO ENCONTRADO');
    console.error(`   Ubicación esperada: ${envPath}`);
    console.error('   Por favor, asegúrate de que el archivo .env esté en la raíz del proyecto');
    process.exit(1);
}

// Cargar dotenv con configuración explícita
const dotenvResult = require('dotenv').config({ 
    path: envPath,
    debug: process.env.DEBUG_DOTENV === 'true'
});

// Verificar si hubo errores cargando dotenv
if (dotenvResult.error) {
    console.error('❌ ERROR CARGANDO ARCHIVO .env:', dotenvResult.error.message);
    process.exit(1);
}

// Validar variables críticas inmediatamente
const criticalVars = [
    'BASE_SEED',
    'DB_FRAGMENT_1',
    'DB_FRAGMENT_2',
    'DB_FRAGMENT_3',
    'NODE_ENV'
];

const missingVars = criticalVars.filter(varName => !process.env[varName]);

if (missingVars.length > 0) {
    console.error('❌ VARIABLES DE ENTORNO CRÍTICAS FALTANTES:');
    missingVars.forEach(varName => {
        console.error(`   - ${varName}`);
    });
    console.error('\n🔧 Soluciones posibles:');
    console.error('   1. Verifica que el archivo .env esté en la raíz del proyecto');
    console.error('   2. Verifica que no haya espacios extra en las líneas del .env');
    console.error('   3. Ejecuta: npm run debug-env para más información');
    process.exit(1);
}

console.log('✅ Variables de entorno cargadas correctamente');

// Ahora continuar con el resto de imports
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
const { sanitizeInput } = require('./middleware/sanitize.middleware');
const serverCheck = require('./middleware/serverCheck.middleware');
const { guard: maintenanceGuard } = require('./maintenance');
const { createErrorHandler } = require('./middleware/error.middleware');

// Importar cargador de rutas (monta cada src/api/routes/*.routes.js en /api/<nombre>)
const { registerRoutes } = require('./api/routes');

// Importar servicios
const secureCommunications = require('./services/secure-communications.service');

// Importar tareas programadas
const scheduleKeyRotation = require('./tasks/scheduleKeyRotation');
const housekeeping = require('./tasks/securityHousekeeping');
const alertsService = require('./security/alerts.service');
const leader = require('./tasks/leader');
const tracing = require('./observability/tracing');
const metrics = require('./observability/metrics');

class SecureServer {
    constructor() {
        this.app = express();
        this.port = process.env.PORT || 3000;
        this.shuttingDown = false;
        this.readiness = { at: 0, ok: false };
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

            // Estado de mantenimiento y huella de claves, ANTES de cualquier escritura cifrada
            const guardState = await maintenanceGuard.start();
            if (guardState.maintenance) console.log('🔒 Hay una rotación/migración en curso: el servidor arranca en MANTENIMIENTO');
            if (guardState.outOfSync) console.log(`⚠️ Claves desincronizadas con la base de datos: ${guardState.detail}`);

            // Verificar sistemas
            await this.performInitialChecks();

            // Iniciar servidor
            this.startServer();

        } catch (error) {
            console.error('❌ Error iniciando servidor:', error);
            
            // Información adicional de debug
            console.error('\n🔧 Información de debug:');
            console.error(`   NODE_ENV: ${process.env.NODE_ENV || 'no definido'}`);
            console.error(`   BASE_SEED definido: ${!!process.env.BASE_SEED}`);
            console.error(`   DB_FRAGMENT_1 definido: ${!!process.env.DB_FRAGMENT_1}`);
            
            process.exit(1);
        }
    }

    async validateConfiguration() {
        try {
            console.log('🔍 Validando configuración...');

            // Mostrar información de entorno
            console.log(`   Entorno: ${process.env.NODE_ENV || 'development'}`);
            console.log(`   Puerto: ${this.port}`);

            // Validar credenciales con mejor manejo de errores
            try {
                credentialBuilder.validateCredentials();
                console.log('✅ Validación de credenciales exitosa');
            } catch (credError) {
                console.error('❌ Error en validación de credenciales:', credError.message);
                throw credError;
            }

            // Verificar conexión a base de datos con reintentos
            let dbConnected = false;
            let attempts = 0;
            const maxAttempts = 3;

            while (!dbConnected && attempts < maxAttempts) {
                attempts++;
                console.log(`   Intento de conexión DB ${attempts}/${maxAttempts}...`);
                
                try {
                    dbConnected = await database.testConnection();
                    if (dbConnected) {
                        console.log('✅ Conexión a base de datos exitosa');
                    } else {
                        console.log(`   ⏳ Intento ${attempts} falló, reintentando...`);
                        if (attempts < maxAttempts) {
                            await new Promise(resolve => setTimeout(resolve, 2000)); // Esperar 2 segundos
                        }
                    }
                } catch (dbError) {
                    console.error(`   ❌ Error en intento ${attempts}:`, dbError.message);
                    if (attempts === maxAttempts) {
                        throw new Error(`No se pudo conectar a la base de datos después de ${maxAttempts} intentos`);
                    }
                    await new Promise(resolve => setTimeout(resolve, 2000));
                }
            }

            if (!dbConnected) {
                throw new Error('No se pudo establecer conexión con la base de datos');
            }

            console.log('✅ Configuración validada');
        } catch (error) {
            console.error('❌ Error en validación de configuración:', error);
            throw error;
        }
    }

    // TRUST_PROXY indica cuántos proxies (balanceador, nginx...) hay delante, para que req.ip sea la
    // IP REAL del cliente y no la del proxy:  1 | 2 | loopback | 10.0.0.0/8 | true
    // Sin él, detrás de un proxy todos los usuarios comparten IP y el límite/bloqueo los afecta a todos.
    // Con un valor que no corresponde a tu infraestructura, un cliente podría falsear X-Forwarded-For.
    configureTrustProxy() {
        const raw = process.env.TRUST_PROXY;
        if (!raw) {
            if (process.env.NODE_ENV === 'production') {
                console.warn('⚠️ TRUST_PROXY sin definir: si hay un proxy delante, todas las peticiones parecerán venir de su IP');
            }
            return;
        }
        const value = raw === 'true' ? true : /^\d+$/.test(raw) ? Number(raw) : raw;
        this.app.set('trust proxy', value);
    }

    allowedOrigins() {
        if (process.env.ALLOWED_ORIGINS) return process.env.ALLOWED_ORIGINS.split(',').map(o => o.trim()).filter(Boolean);
        // En producción, sin orígenes declarados no se permite ninguno (antes había IPs privadas fijas en el código)
        return process.env.NODE_ENV === 'production' ? false : ['http://localhost:3000'];
    }

    setupMiddlewares() {
        console.log('⚙️ Configurando middlewares de seguridad...');

        this.configureTrustProxy();
        this.app.disable('x-powered-by');

        // Durante el cierre ordenado cada respuesta cierra su conexión: el cliente (o el balanceador) se reconecta a otra instancia
        this.app.use((req, res, next) => { if (this.shuttingDown) res.set('Connection', 'close'); next(); });

        // Observabilidad primero, para que mida y correlacione TODO (incluidos los rechazos de las capas siguientes)
        this.app.use(tracing.middleware());
        this.app.use(metrics.httpMiddleware());

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
            origin: this.allowedOrigins(),
            credentials: true,
            methods: ['GET', 'HEAD', 'POST', 'PUT', 'DELETE'],
            allowedHeaders: ['Content-Type', 'Authorization', 'Range'],
            exposedHeaders: ['Content-Range', 'Accept-Ranges', 'Content-Disposition', 'Retry-After', 'X-Request-Id']
        }));

        // Modo mantenimiento / claves desincronizadas: 503 a todo (ver src/maintenance/guard.js)
        this.app.use(maintenanceGuard.middleware());

        this.app.use(compression());
        // Registro de accesos. Cada línea es una escritura SÍNCRONA a stdout (en Linux, con pipes y archivos): a miles de peticiones por
        // segundo cuesta. ACCESS_LOG=combined (por defecto) | errors (solo respuestas ≥ 400) | off
        const accessLog = process.env.ACCESS_LOG || 'combined';
        if (accessLog !== 'off') {
            this.app.use(morgan('combined', accessLog === 'errors' ? { skip: (req, res) => res.statusCode < 400 } : {}));
        }
        // Los JSON de esta API son pequeños (la subida de archivos va por multipart, con sus propios límites)
        const bodyLimit = process.env.JSON_BODY_LIMIT || '1mb';
        this.app.use(express.json({ limit: bodyLimit }));
        this.app.use(express.urlencoded({ extended: false, limit: bodyLimit }));

        // Protección (estado en MySQL) y después validación estructural de la entrada
        this.app.use(protectionMiddleware.autoProtect());
        this.app.use(sanitizeInput());

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
                    version: '1.0.0',
                    environment: process.env.NODE_ENV || 'development',
                    envVarsLoaded: !!process.env.BASE_SEED
                };

                res.json(healthStatus);
            } catch (error) {
                res.status(500).json({
                    status: 'unhealthy',
                    error: error.message
                });
            }
        });

        // Preparación (readiness) para balanceadores/orquestadores: 200 solo si esta instancia puede atender de verdad (BD alcanzable,
        // no en mantenimiento —eso ya lo corta el guardián con 503— y no cerrándose). /health sigue siendo "el proceso vive".
        this.app.get('/health/ready', async (req, res) => {
            res.set('Cache-Control', 'no-store');
            if (this.shuttingDown) return res.status(503).json({ status: 'not_ready', reason: 'shutting_down' });
            if (!(await this.databaseReachable())) return res.status(503).json({ status: 'not_ready', reason: 'database' });
            res.json({ status: 'ready', leader: leader.isLeader(), pid: process.pid, uptime: Math.round(process.uptime()) });
        });

        // Ruta de diagnóstico de variables de entorno (solo para desarrollo)
        if (process.env.NODE_ENV === 'development') {
            this.app.get('/debug/env', (req, res) => {
                const criticalVars = [
                    'BASE_SEED',
                    'DB_FRAGMENT_1',
                    'DB_FRAGMENT_2',
                    'DB_FRAGMENT_3',
                    'PRIMARY_EMAIL_USER',
                    'EMAIL_DOMAIN_1',
                    'NODE_ENV'
                ];

                const envStatus = {};
                criticalVars.forEach(varName => {
                    envStatus[varName] = {
                        defined: !!process.env[varName],
                        length: process.env[varName] ? process.env[varName].length : 0
                    };
                });

                res.json({
                    envVarsStatus: envStatus,
                    dotenvLoaded: dotenvResult.parsed ? Object.keys(dotenvResult.parsed).length : 0
                });
            });
        }

        // APIs: /api/auth, /api/system, /api/notes y cualquier *.routes.js que se añada
        const mounted = registerRoutes(this.app);
        mounted.forEach(({ path: mountPath, access }) => {
            console.log(`   ↳ ${mountPath} (${access})`);
        });

        // Ruta 404
        this.app.use((req, res) => {
            res.status(404).json({
                success: false,
                message: 'Ruta no encontrada'
            });
        });

        console.log('✅ Rutas configuradas');
    }

    // Una comprobación de BD cada 2 s como mucho, aunque el balanceador pregunte cien veces por segundo
    async databaseReachable() {
        const now = Date.now();
        if (now - this.readiness.at < 2000) return this.readiness.ok;
        let ok = true;
        try { await database.query('SELECT 1'); } catch { ok = false; }
        this.readiness = { at: now, ok };
        return ok;
    }

    // Solo UNA instancia avisa del arranque/cierre (en cluster, el hueco 0; sin cluster, siempre)
    isNotifier() {
        return process.env.CLUSTER_WORKER_INDEX === undefined || process.env.CLUSTER_WORKER_INDEX === '0';
    }

    setupErrorHandling() {
        console.log('🛡️ Configurando manejo de errores...');

        // Manejo de errores generales (ver src/middleware/error.middleware.js)
        this.app.use(createErrorHandler({ logError: (error, req) => this.logError(error, req) }));

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
            // Verificar integridad del servidor (escribe datos cifrados: solo con claves en regla)
            if (maintenanceGuard.isOpen()) {
                await serverCheck.performAsyncCheck();
            } else {
                console.log('⏸️ Verificación de integridad omitida: servidor en mantenimiento o con claves desincronizadas');
            }

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
            console.log('✅ Variables críticas cargadas correctamente');
            console.log('========================================\n');

            // Tareas periódicas: las ejecuta solo la instancia LÍDER (src/tasks/leader.js)
            leader.start([
                { name: 'limpieza', start: () => housekeeping.start(), stop: () => housekeeping.stop() },
                { name: 'alertas', start: () => alertsService.start(), stop: () => alertsService.stop() },
                { name: 'rotación programada', start: () => scheduleKeyRotation.start(), stop: () => scheduleKeyRotation.stop() }
            ]).catch((error) => console.error('❌ Elección de líder:', error.message));

            // Enviar notificación de inicio (si hay canales configurados)
            if (this.isNotifier()) this.sendStartupNotification();
        });

        // Límites de conexión: cabeceras rápidas (contra slowloris) y tiempo total holgado para subidas grandes.
        // keepAliveTimeout MAYOR que el de inactividad de los balanceadores (ALB/nginx suelen usar 60 s): si el servidor cerrara antes,
        // el balanceador reutilizaría una conexión ya cerrada y devolvería 502 de forma intermitente.
        this.server.keepAliveTimeout = Number(process.env.KEEP_ALIVE_TIMEOUT_MS) || 65 * 1000;
        this.server.headersTimeout = Math.max(30 * 1000, this.server.keepAliveTimeout + 1000);
        this.server.requestTimeout = Number(process.env.REQUEST_TIMEOUT_MS) || 10 * 60 * 1000;

        // Manejo graceful de cierre
        process.on('SIGTERM', () => this.gracefulShutdown());
        process.on('SIGINT', () => this.gracefulShutdown());
        // Con cluster: si el proceso principal desaparece, el worker no se queda huérfano
        process.on('disconnect', () => this.gracefulShutdown());
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

    // Cierre ordenado: deja de ser "ready", no acepta conexiones nuevas, deja terminar las peticiones en curso (cerrando las
    // conexiones keep-alive ociosas), suelta el liderazgo y cierra el pool de la BD. Pasado el plazo, corta lo que quede.
    async gracefulShutdown() {
        if (this.shuttingDown) return;
        this.shuttingDown = true;
        console.log('\n🛑 Iniciando cierre graceful del servidor...');
        const deadlineMs = Number(process.env.SHUTDOWN_TIMEOUT_MS) || 10000;

        const force = setTimeout(() => {
            console.log('⚠️ Forzando cierre del servidor');
            this.server?.closeAllConnections?.();
            process.exit(1);
        }, deadlineMs + 2000);
        force.unref();

        try {
            if (this.isNotifier()) {
                const commStats = secureCommunications.getStats();
                if (commStats.availableChannels > 0) {
                    await Promise.race([
                        secureCommunications.sendSecureAlert({
                            type: 'SYSTEM_SHUTDOWN', severity: 'info',
                            details: 'Servidor iniciando proceso de cierre', timestamp: new Date().toISOString()
                        }, 'normal'),
                        new Promise(resolve => setTimeout(resolve, 2000))
                    ]).catch(() => {});
                }
            }

            const closed = new Promise(resolve => this.server ? this.server.close(resolve) : resolve());
            // Las conexiones ociosas NO se cierran de inmediato: una recién aceptada cuya petición todavía viaja por la red también
            // parece "ociosa", y cerrarla da un reset al cliente. Se espera un momento (los clientes que llegaron ya recibirán su
            // respuesta con Connection: close) y después se barren las que sigan ociosas.
            const drainMs = Math.min(Number(process.env.SHUTDOWN_DRAIN_MS) || 1500, deadlineMs);
            let sweep;
            const startSweep = setTimeout(() => { sweep = setInterval(() => this.server?.closeIdleConnections?.(), 250); }, drainMs);
            const cut = setTimeout(() => this.server?.closeAllConnections?.(), deadlineMs);
            await closed;
            clearTimeout(startSweep);
            if (sweep) clearInterval(sweep);
            clearTimeout(cut);

            await leader.stop().catch(() => {});
            await database.close().catch(() => {});
            console.log('✅ Servidor cerrado correctamente');
            process.exit(0);
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