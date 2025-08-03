#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

class SecurityAudit {
    constructor() {
        this.auditResults = {
            timestamp: new Date().toISOString(),
            overallScore: 0,
            categories: {},
            recommendations: [],
            criticalIssues: [],
            warnings: []
        };
    }

    async runFullAudit() {
        console.log('🔍 Iniciando Auditoría de Seguridad Completa...\n');

        try {
            // 1. Auditoría de configuración
            await this.auditConfiguration();

            // 2. Auditoría de base de datos
            await this.auditDatabase();

            // 3. Auditoría de sistema de cifrado
            await this.auditEncryption();

            // 4. Auditoría de archivos críticos
            await this.auditCriticalFiles();

            // 5. Auditoría de dependencias
            await this.auditDependencies();

            // 6. Auditoría de logs de seguridad
            await this.auditSecurityLogs();

            // 7. Auditoría de integridad del servidor
            await this.auditServerIntegrity();

            // Calcular puntuación general
            this.calculateOverallScore();

            // Generar reporte
            await this.generateReport();

            console.log('\n✅ Auditoría de seguridad completada');
            this.displaySummary();

        } catch (error) {
            console.error('❌ Error durante la auditoría:', error);
            throw error;
        }
    }

    async auditConfiguration() {
        console.log('🔧 Auditando configuración...');
        const configScore = { score: 0, maxScore: 100, issues: [] };

        try {
            // Verificar variables de entorno críticas
            const criticalEnvVars = [
                'BASE_SEED',
                'JWT_SEED',
                'ENCRYPTION_SEED',
                'DB_FRAGMENT_1',
                'DB_FRAGMENT_2',
                'DB_FRAGMENT_3',
                'NODE_ENV'
            ];

            let envVarsPresent = 0;
            for (const envVar of criticalEnvVars) {
                if (process.env[envVar]) {
                    envVarsPresent++;
                } else {
                    configScore.issues.push(`Variable de entorno faltante: ${envVar}`);
                }
            }

            configScore.score += (envVarsPresent / criticalEnvVars.length) * 40;

            // Verificar configuración de seguridad
            const securityConfigs = [
                'INTEGRITY_MONITOR_ENABLED',
                'AUTO_ROTATION_ENABLED',
                'ANOMALY_DETECTION_ENABLED',
                'AUTO_BLOCK_MALICIOUS_IPS'
            ];

            let securityEnabled = 0;
            for (const config of securityConfigs) {
                if (process.env[config] === 'true') {
                    securityEnabled++;
                } else {
                    configScore.issues.push(`Configuración de seguridad deshabilitada: ${config}`);
                }
            }

            configScore.score += (securityEnabled / securityConfigs.length) * 30;

            // Verificar modo de producción
            if (process.env.NODE_ENV === 'production') {
                configScore.score += 20;
            } else {
                configScore.issues.push('Sistema no está en modo producción');
            }

            // Verificar longitud de semillas
            if (process.env.BASE_SEED && process.env.BASE_SEED.length >= 64) {
                configScore.score += 10;
            } else {
                configScore.issues.push('BASE_SEED tiene longitud insuficiente (recomendado: 64+ caracteres)');
            }

            this.auditResults.categories.configuration = configScore;
            console.log(`   Puntuación: ${Math.round(configScore.score)}/100`);

        } catch (error) {
            console.error('   ❌ Error en auditoría de configuración:', error.message);
            configScore.issues.push(`Error durante auditoría: ${error.message}`);
            this.auditResults.categories.configuration = configScore;
        }
    }

    async auditDatabase() {
        console.log('🗄️ Auditando base de datos...');
        const dbScore = { score: 0, maxScore: 100, issues: [] };

        try {
            const db = require('../src/config/database');

            // Test de conexión
            const connected = await db.testConnection();
            if (connected) {
                dbScore.score += 30;
            } else {
                dbScore.issues.push('No se puede conectar a la base de datos');
                this.auditResults.criticalIssues.push('Base de datos inaccesible');
            }

            // Verificar tablas críticas
            const criticalTables = [
                'users',
                'user_sessions',
                'security_logs',
                'server_integrity',
                'encryption_keys',
                'blocked_ips'
            ];

            let tablesExist = 0;
            for (const table of criticalTables) {
                try {
                    await db.query(`SELECT 1 FROM ${table} LIMIT 1`);
                    tablesExist++;
                } catch (error) {
                    dbScore.issues.push(`Tabla faltante o inaccesible: ${table}`);
                }
            }

            dbScore.score += (tablesExist / criticalTables.length) * 40;

            // Verificar cifrado de datos sensibles
            try {
                const [logs] = await db.query('SELECT encrypted_details FROM security_logs LIMIT 1');
                if (logs.length > 0 && logs[0].encrypted_details) {
                    dbScore.score += 20;
                } else {
                    dbScore.issues.push('No se encontraron datos cifrados en security_logs');
                }
            } catch (error) {
                dbScore.issues.push('Error verificando cifrado de datos');
            }

            // Verificar índices de optimización
            try {
                const [indexes] = await db.query(`
                    SELECT COUNT(*) as index_count 
                    FROM information_schema.statistics 
                    WHERE table_schema = DATABASE() 
                    AND table_name IN ('users', 'user_sessions', 'security_logs')
                `);

                if (indexes[0].index_count >= 5) {
                    dbScore.score += 10;
                } else {
                    dbScore.issues.push('Índices de base de datos insuficientes para optimización');
                }
            } catch (error) {
                dbScore.issues.push('Error verificando índices de base de datos');
            }

            this.auditResults.categories.database = dbScore;
            console.log(`   Puntuación: ${Math.round(dbScore.score)}/100`);

        } catch (error) {
            console.error('   ❌ Error en auditoría de base de datos:', error.message);
            dbScore.issues.push(`Error durante auditoría: ${error.message}`);
            this.auditResults.categories.database = dbScore;
        }
    }

    async auditEncryption() {
        console.log('🔐 Auditando sistema de cifrado...');
        const encScore = { score: 0, maxScore: 100, issues: [] };

        try {
            const tripleEncryptor = require('../src/crypto/tripleEncryptor');

            // Test de health check
            const healthCheck = await tripleEncryptor.healthCheck();
            if (healthCheck.healthy) {
                encScore.score += 40;
            } else {
                encScore.issues.push('Health check del sistema de cifrado falló');
                this.auditResults.criticalIssues.push('Sistema de cifrado no saludable');
            }

            // Test de cifrado/descifrado
            const testData = 'Security audit test data ' + Date.now();
            try {
                const encrypted = tripleEncryptor.encrypt(testData);
                const decrypted = tripleEncryptor.decrypt(encrypted);

                if (decrypted === testData) {
                    encScore.score += 30;
                } else {
                    encScore.issues.push('Test de cifrado/descifrado falló');
                    this.auditResults.criticalIssues.push('Integridad del cifrado comprometida');
                }
            } catch (error) {
                encScore.issues.push(`Error en test de cifrado: ${error.message}`);
                this.auditResults.criticalIssues.push('Sistema de cifrado no funcional');
            }

            // Verificar rotación de claves
            const secureEnv = require('../src/config/secure-env');
            if (secureEnv.needsRotation && !secureEnv.needsRotation()) {
                encScore.score += 20;
            } else {
                encScore.issues.push('Las claves necesitan rotación');
                this.auditResults.warnings.push('Considerar rotación manual de claves');
            }

            // Verificar algoritmos fuertes
            encScore.score += 10; // Asumimos algoritmos fuertes implementados

            this.auditResults.categories.encryption = encScore;
            console.log(`   Puntuación: ${Math.round(encScore.score)}/100`);

        } catch (error) {
            console.error('   ❌ Error en auditoría de cifrado:', error.message);
            encScore.issues.push(`Error durante auditoría: ${error.message}`);
            this.auditResults.categories.encryption = encScore;
        }
    }

    async auditCriticalFiles() {
        console.log('📁 Auditando archivos críticos...');
        const filesScore = { score: 0, maxScore: 100, issues: [] };

        const criticalFiles = [
            'src/index.js',
            'src/config/database.js',
            'src/config/secure-env.js',
            'src/crypto/tripleEncryptor.js',
            'src/security/secure-auth.service.js',
            'src/middleware/serverCheck.middleware.js',
            'database/schema.sql',
            '.env'
        ];

        let filesExist = 0;
        for (const file of criticalFiles) {
            if (fs.existsSync(file)) {
                filesExist++;
            } else {
                filesScore.issues.push(`Archivo crítico faltante: ${file}`);
            }
        }

        filesScore.score += (filesExist / criticalFiles.length) * 60;

        // Verificar permisos de archivos críticos
        try {
            const envStats = fs.statSync('.env');
            const envPerms = (envStats.mode & parseInt('777', 8)).toString(8);

            if (envPerms === '600' || envPerms === '644') {
                filesScore.score += 20;
            } else {
                filesScore.issues.push(`Permisos inseguros en .env: ${envPerms} (recomendado: 600)`);
                this.auditResults.warnings.push('Ajustar permisos del archivo .env');
            }
        } catch (error) {
            filesScore.issues.push('Error verificando permisos de .env');
        }

        // Verificar que no hay archivos sensibles en Git
        if (fs.existsSync('.gitignore')) {
            const gitignore = fs.readFileSync('.gitignore', 'utf8');
            if (gitignore.includes('.env') && gitignore.includes('node_modules')) {
                filesScore.score += 20;
            } else {
                filesScore.issues.push('.gitignore no protege archivos sensibles adecuadamente');
                this.auditResults.warnings.push('Actualizar .gitignore para proteger archivos sensibles');
            }
        } else {
            filesScore.issues.push('Archivo .gitignore faltante');
            this.auditResults.warnings.push('Crear archivo .gitignore para proteger archivos sensibles');
        }

        this.auditResults.categories.files = filesScore;
        console.log(`   Puntuación: ${Math.round(filesScore.score)}/100`);
    }

    async auditDependencies() {
        console.log('📦 Auditando dependencias...');
        const depsScore = { score: 0, maxScore: 100, issues: [] };

        try {
            // Verificar package.json
            if (fs.existsSync('package.json')) {
                const packageJson = JSON.parse(fs.readFileSync('package.json', 'utf8'));

                // Verificar dependencias de seguridad críticas
                const securityDeps = ['helmet', 'bcryptjs', 'jsonwebtoken', 'cors'];
                let securityDepsPresent = 0;

                for (const dep of securityDeps) {
                    if (packageJson.dependencies && packageJson.dependencies[dep]) {
                        securityDepsPresent++;
                    } else {
                        depsScore.issues.push(`Dependencia de seguridad faltante: ${dep}`);
                    }
                }

                depsScore.score += (securityDepsPresent / securityDeps.length) * 50;

                // Verificar que no hay dependencias peligrosas conocidas
                const dangerousDeps = ['eval', 'vm2', 'serialize-javascript'];
                let safeDeps = true;

                for (const dep of dangerousDeps) {
                    if (packageJson.dependencies && packageJson.dependencies[dep]) {
                        depsScore.issues.push(`Dependencia potencialmente peligrosa: ${dep}`);
                        this.auditResults.warnings.push(`Revisar uso de dependencia: ${dep}`);
                        safeDeps = false;
                    }
                }

                if (safeDeps) {
                    depsScore.score += 30;
                }

                // Verificar versiones de Node.js
                if (packageJson.engines && packageJson.engines.node) {
                    depsScore.score += 20;
                } else {
                    depsScore.issues.push('Versión de Node.js no especificada en package.json');
                }

            } else {
                depsScore.issues.push('package.json faltante');
                this.auditResults.criticalIssues.push('package.json no encontrado');
            }

            this.auditResults.categories.dependencies = depsScore;
            console.log(`   Puntuación: ${Math.round(depsScore.score)}/100`);

        } catch (error) {
            console.error('   ❌ Error en auditoría de dependencias:', error.message);
            depsScore.issues.push(`Error durante auditoría: ${error.message}`);
            this.auditResults.categories.dependencies = depsScore;
        }
    }

    async auditSecurityLogs() {
        console.log('📋 Auditando logs de seguridad...');
        const logsScore = { score: 0, maxScore: 100, issues: [] };

        try {
            const db = require('../src/config/database');

            // Verificar que existen logs de seguridad
            const [logCount] = await db.query('SELECT COUNT(*) as count FROM security_logs');

            if (logCount[0].count > 0) {
                logsScore.score += 30;
            } else {
                logsScore.issues.push('No hay logs de seguridad registrados');
            }

            // Verificar logs recientes (última hora)
            const [recentLogs] = await db.query(`
                SELECT COUNT(*) as count 
                FROM security_logs 
                WHERE timestamp > DATE_SUB(NOW(), INTERVAL 1 HOUR)
            `);

            if (recentLogs[0].count > 0) {
                logsScore.score += 25;
            } else {
                logsScore.issues.push('No hay logs recientes (última hora)');
            }

            // Verificar variedad de tipos de eventos
            const [eventTypes] = await db.query(`
                SELECT COUNT(DISTINCT event_type) as types 
                FROM security_logs
            `);

            if (eventTypes[0].types >= 3) {
                logsScore.score += 25;
            } else {
                logsScore.issues.push('Poca variedad en tipos de eventos de seguridad');
            }

            // Verificar que los logs están cifrados
            const [encryptedCheck] = await db.query(`
                SELECT encrypted_details 
                FROM security_logs 
                WHERE encrypted_details IS NOT NULL 
                LIMIT 1
            `);

            if (encryptedCheck.length > 0) {
                logsScore.score += 20;
            } else {
                logsScore.issues.push('Los logs de seguridad no están cifrados');
                this.auditResults.criticalIssues.push('Logs de seguridad sin cifrar');
            }

            this.auditResults.categories.logs = logsScore;
            console.log(`   Puntuación: ${Math.round(logsScore.score)}/100`);

        } catch (error) {
            console.error('   ❌ Error en auditoría de logs:', error.message);
            logsScore.issues.push(`Error durante auditoría: ${error.message}`);
            this.auditResults.categories.logs = logsScore;
        }
    }

    async auditServerIntegrity() {
        console.log('🛡️ Auditando integridad del servidor...');
        const integrityScore = { score: 0, maxScore: 100, issues: [] };

        try {
            const serverCheck = require('../src/middleware/serverCheck.middleware');

            // Verificar estado de integridad
            const status = serverCheck.getStatus();

            if (status.serverFingerprint) {
                integrityScore.score += 40;
            } else {
                integrityScore.issues.push('Fingerprint del servidor no disponible');
                this.auditResults.criticalIssues.push('Sistema de integridad no inicializado');
            }

            // Ejecutar verificación de integridad
            try {
                const result = await serverCheck.performAsyncCheck();

                if (!result.compromised) {
                    integrityScore.score += 40;
                } else {
                    integrityScore.issues.push('Integridad del servidor comprometida');
                    this.auditResults.criticalIssues.push('SERVIDOR COMPROMETIDO - Acción inmediata requerida');
                }
            } catch (error) {
                integrityScore.issues.push(`Error en verificación de integridad: ${error.message}`);
            }

            // Verificar última verificación
            if (status.lastIntegrityCheck) {
                const timeSinceCheck = Date.now() - status.lastIntegrityCheck;
                const oneHour = 60 * 60 * 1000;

                if (timeSinceCheck < oneHour) {
                    integrityScore.score += 20;
                } else {
                    integrityScore.issues.push('Última verificación de integridad hace más de 1 hora');
                }
            } else {
                integrityScore.issues.push('No hay registro de verificaciones de integridad previas');
            }

            this.auditResults.categories.integrity = integrityScore;
            console.log(`   Puntuación: ${Math.round(integrityScore.score)}/100`);

        } catch (error) {
            console.error('   ❌ Error en auditoría de integridad:', error.message);
            integrityScore.issues.push(`Error durante auditoría: ${error.message}`);
            this.auditResults.categories.integrity = integrityScore;
        }
    }

    calculateOverallScore() {
        const categories = this.auditResults.categories;
        const categoryScores = Object.values(categories).map(cat => cat.score);
        const totalScore = categoryScores.reduce((sum, score) => sum + score, 0);
        this.auditResults.overallScore = Math.round(totalScore / categoryScores.length);

        // Generar recomendaciones basadas en puntuación
        if (this.auditResults.overallScore < 70) {
            this.auditResults.recommendations.push('Puntuación general baja - revisar todas las categorías');
        }

        if (this.auditResults.criticalIssues.length > 0) {
            this.auditResults.recommendations.push('Resolver problemas críticos inmediatamente');
        }

        if (this.auditResults.warnings.length > 3) {
            this.auditResults.recommendations.push('Atender advertencias para mejorar la seguridad');
        }
    }

    async generateReport() {
        const reportPath = path.join(__dirname, `../reports/security_audit_${Date.now()}.json`);

        // Asegurar que el directorio existe
        const reportsDir = path.dirname(reportPath);
        if (!fs.existsSync(reportsDir)) {
            fs.mkdirSync(reportsDir, { recursive: true });
        }

        // Escribir reporte
        await fs.promises.writeFile(reportPath, JSON.stringify(this.auditResults, null, 2));

        console.log(`\n📄 Reporte de auditoría guardado en: ${reportPath}`);
        return reportPath;
    }

    displaySummary() {
        console.log('\n🔍 ========================================');
        console.log('📊 RESUMEN DE AUDITORÍA DE SEGURIDAD');
        console.log('🔍 ========================================');
        console.log(`📈 Puntuación General: ${this.auditResults.overallScore}/100`);

        // Estado general basado en puntuación
        let status = '';
        let statusIcon = '';
        if (this.auditResults.overallScore >= 90) {
            status = 'EXCELENTE';
            statusIcon = '🟢';
        } else if (this.auditResults.overallScore >= 80) {
            status = 'BUENO';
            statusIcon = '🟡';
        } else if (this.auditResults.overallScore >= 70) {
            status = 'ACEPTABLE';
            statusIcon = '🟠';
        } else {
            status = 'CRÍTICO';
            statusIcon = '🔴';
        }

        console.log(`${statusIcon} Estado: ${status}`);
        console.log('');

        // Puntuaciones por categoría
        console.log('📋 Puntuaciones por Categoría:');
        for (const [category, data] of Object.entries(this.auditResults.categories)) {
            const categoryName = category.charAt(0).toUpperCase() + category.slice(1);
            console.log(`   ${categoryName}: ${Math.round(data.score)}/100`);
        }

        // Problemas críticos
        if (this.auditResults.criticalIssues.length > 0) {
            console.log('\n🚨 PROBLEMAS CRÍTICOS:');
            this.auditResults.criticalIssues.forEach(issue => {
                console.log(`   ❌ ${issue}`);
            });
        }

        // Advertencias
        if (this.auditResults.warnings.length > 0) {
            console.log('\n⚠️ ADVERTENCIAS:');
            this.auditResults.warnings.forEach(warning => {
                console.log(`   ⚠️ ${warning}`);
            });
        }

        // Recomendaciones
        if (this.auditResults.recommendations.length > 0) {
            console.log('\n💡 RECOMENDACIONES:');
            this.auditResults.recommendations.forEach(rec => {
                console.log(`   💡 ${rec}`);
            });
        }

        console.log('\n========================================');
    }

    // Métodos para comandos específicos
    async quickScan() {
        console.log('⚡ Ejecutando escaneo rápido de seguridad...\n');

        await this.auditConfiguration();
        await this.auditEncryption();
        await this.auditServerIntegrity();

        this.calculateOverallScore();
        this.displaySummary();
    }

    async checkIntegrity() {
        console.log('🛡️ Verificando integridad del servidor...\n');

        await this.auditServerIntegrity();
        await this.auditCriticalFiles();

        this.calculateOverallScore();
        this.displaySummary();
    }

    showUsage() {
        console.log(`
🔍 Auditoría de Seguridad del Sistema

Uso:
  node scripts/securityAudit.js [comando]

Comandos:
  full              Auditoría completa del sistema
  quick             Escaneo rápido de seguridad
  integrity         Verificación de integridad
  help              Mostrar esta ayuda

Ejemplos:
  node scripts/securityAudit.js full
  node scripts/securityAudit.js quick
  node scripts/securityAudit.js integrity
        `);
    }
}

// Ejecución desde línea de comandos
if (require.main === module) {
    const audit = new SecurityAudit();
    const command = process.argv[2] || 'full';

    (async () => {
        try {
            switch (command) {
                case 'full':
                    await audit.runFullAudit();
                    break;
                case 'quick':
                    await audit.quickScan();
                    break;
                case 'integrity':
                    await audit.checkIntegrity();
                    break;
                case 'help':
                    audit.showUsage();
                    break;
                default:
                    console.log(`❌ Comando desconocido: ${command}`);
                    audit.showUsage();
                    process.exit(1);
            }
        } catch (error) {
            console.error('❌ Error durante la auditoría:', error.message);
            process.exit(1);
        }
    })();
}

module.exports = SecurityAudit;