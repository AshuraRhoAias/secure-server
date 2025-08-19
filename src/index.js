// Cargar variables de entorno PRIMERO y validar
const path = require('path');
const fs = require('fs');

// Verificar que el archivo .env existe
const envPath = path.join(__dirname, '../.env');
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
            origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000', 'http://192.168.100.58:3000'],
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
                            platform: process.platform,
                            environment: process.env.NODE_ENV || 'development'
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
        this.app.use((req, res) => {
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
            console.log('✅ Variables críticas cargadas correctamente');
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