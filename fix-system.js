#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

class SystemFixer {
    constructor() {
        this.issues = [];
        this.fixes = [];
    }

    async fixAll() {
        console.log('🔧 Iniciando reparación automática del sistema...\n');

        try {
            await this.fixEnvFile();
            await this.fixPermissions();
            await this.fixPackageJson();
            await this.validateFixes();

            console.log('\n✅ ========================================');
            console.log('🎉 REPARACIÓN COMPLETADA');
            console.log('✅ ========================================');
            console.log(`📋 Problemas encontrados: ${this.issues.length}`);
            console.log(`🔧 Reparaciones aplicadas: ${this.fixes.length}`);

            if (this.fixes.length > 0) {
                console.log('\n📝 Reparaciones aplicadas:');
                this.fixes.forEach((fix, index) => {
                    console.log(`   ${index + 1}. ${fix}`);
                });
            }

            console.log('\n🚀 Siguientes pasos:');
            console.log('   1. Ejecuta: npm run debug-env');
            console.log('   2. Si todo está bien, ejecuta: npm start');
            console.log('   3. Verifica el estado con: npm run security-audit');

        } catch (error) {
            console.error('❌ Error durante la reparación:', error.message);
            process.exit(1);
        }
    }

    async fixEnvFile() {
        console.log('🔍 Verificando archivo .env...');

        const envPath = '.env';

        if (!fs.existsSync(envPath)) {
            this.issues.push('Archivo .env no encontrado');

            // Copiar desde .env.example si existe
            if (fs.existsSync('.env.example')) {
                fs.copyFileSync('.env.example', envPath);
                this.fixes.push('Archivo .env creado desde .env.example');
                console.log('✅ Archivo .env creado desde plantilla');
            } else {
                throw new Error('No se encontró .env ni .env.example');
            }
        }

        // Leer y validar contenido
        const envContent = fs.readFileSync(envPath, 'utf8');
        const lines = envContent.split('\n');

        // Variables que deben existir
        const requiredVars = {
            'NODE_ENV': 'development',
            'PORT': '3000',
            'BASE_SEED': '9a1f3b8e2d4c7f1a9b2d3e4f5678123456789abcdef1234567890abcdef123456',
            'JWT_SEED': 'e2f1c3a9b4d5f6789abc1234567890abcdef1234567890abcdef1234567890ab',
            'ENCRYPTION_SEED': '7c9e1a2b3d4f567890abcdef1234567890abcdef1234567890abcdef12345678',
            'EMAIL_SEED': 'b8f1234567890abcdef1234567890abcdef1234567890abcdef1234567890abc',
            'DB_FRAGMENT_1': 'mysql://root:@',
            'DB_FRAGMENT_2': 'localhost:',
            'DB_FRAGMENT_3': '3306/secure_platform',
            'PRIMARY_EMAIL_USER': 'mendezperezraul580',
            'EMAIL_DOMAIN_1': 'gmail.com',
            'DISABLE_EMAIL_NOTIFICATIONS': 'true'
        };

        let envChanged = false;
        const existingVars = {};

        // Parsear variables existentes
        lines.forEach(line => {
            if (line.includes('=') && !line.trim().startsWith('#')) {
                const [key, ...valueParts] = line.split('=');
                existingVars[key.trim()] = valueParts.join('=');
            }
        });

        // Verificar y agregar variables faltantes
        for (const [varName, defaultValue] of Object.entries(requiredVars)) {
            if (!existingVars[varName]) {
                this.issues.push(`Variable ${varName} faltante`);
                lines.push(`${varName}=${defaultValue}`);
                envChanged = true;
                this.fixes.push(`Variable ${varName} agregada con valor por defecto`);
            }
        }

        // Guardar cambios si es necesario
        if (envChanged) {
            fs.writeFileSync(envPath, lines.join('\n'));
            console.log('✅ Variables faltantes agregadas al archivo .env');
        } else {
            console.log('✅ Archivo .env contiene todas las variables requeridas');
        }
    }

    async fixPermissions() {
        console.log('🔒 Verificando permisos del archivo .env...');

        if (process.platform === 'win32') {
            console.log('ℹ️ Windows detectado - permisos de archivo no aplicables');
            return;
        }

        try {
            const envPath = '.env';
            const stats = fs.statSync(envPath);
            const perms = (stats.mode & parseInt('777', 8)).toString(8);

            if (perms !== '600') {
                this.issues.push(`Permisos inseguros en .env: ${perms}`);
                fs.chmodSync(envPath, 0o600);
                this.fixes.push('Permisos de .env ajustados a 600');
                console.log('✅ Permisos del archivo .env corregidos');
            } else {
                console.log('✅ Permisos del archivo .env son correctos');
            }
        } catch (error) {
            console.log('⚠️ No se pudieron verificar/corregir permisos:', error.message);
        }
    }

    async fixPackageJson() {
        console.log('📦 Verificando package.json...');

        const packagePath = 'package.json';

        if (!fs.existsSync(packagePath)) {
            throw new Error('package.json no encontrado');
        }

        const packageJson = JSON.parse(fs.readFileSync(packagePath, 'utf8'));
        let packageChanged = false;

        // Agregar engines si no existe
        if (!packageJson.engines) {
            this.issues.push('Versión de Node.js no especificada');
            packageJson.engines = {
                "node": ">=18.0.0",
                "npm": ">=8.0.0"
            };
            this.fixes.push('Versiones de Node.js y npm especificadas en package.json');
            packageChanged = true;
        }

        // Agregar script debug-env si no existe
        if (!packageJson.scripts['debug-env']) {
            packageJson.scripts['debug-env'] = 'node debug-env.js';
            this.fixes.push('Script debug-env agregado');
            packageChanged = true;
        }

        // Agregar script fix-permissions si no existe
        if (!packageJson.scripts['fix-permissions']) {
            packageJson.scripts['fix-permissions'] = 'chmod 600 .env || echo "Permisos ajustados"';
            this.fixes.push('Script fix-permissions agregado');
            packageChanged = true;
        }

        // Actualizar autor si está vacío
        if (!packageJson.author || packageJson.author === '') {
            packageJson.author = 'Security Team';
            this.fixes.push('Autor del proyecto actualizado');
            packageChanged = true;
        }

        // Guardar cambios
        if (packageChanged) {
            fs.writeFileSync(packagePath, JSON.stringify(packageJson, null, 2));
            console.log('✅ package.json actualizado');
        } else {
            console.log('✅ package.json está correcto');
        }
    }

    async validateFixes() {
        console.log('🧪 Validando reparaciones...');

        // Intentar cargar dotenv
        try {
            const dotenv = require('dotenv');
            const result = dotenv.config();

            if (result.error) {
                throw new Error(`Error cargando .env: ${result.error.message}`);
            }

            console.log('✅ Archivo .env se carga correctamente');

            // Verificar variables críticas
            const criticalVars = [
                'BASE_SEED',
                'DB_FRAGMENT_1',
                'DB_FRAGMENT_2',
                'DB_FRAGMENT_3',
                'NODE_ENV'
            ];

            const missingVars = criticalVars.filter(varName => !process.env[varName]);

            if (missingVars.length > 0) {
                throw new Error(`Variables aún faltantes: ${missingVars.join(', ')}`);
            }

            console.log('✅ Todas las variables críticas están presentes');

        } catch (error) {
            throw new Error(`Validación falló: ${error.message}`);
        }

        // Intentar validar credenciales
        try {
            const credentialBuilder = require('./src/config/credential-builder');
            credentialBuilder.validateCredentials();
            console.log('✅ Validación de credenciales exitosa');
        } catch (error) {
            console.log(`⚠️ Advertencia en credenciales: ${error.message}`);
        }
    }

    showUsage() {
        console.log(`
🔧 Script de Reparación del Sistema

Uso:
  node fix-system.js

Este script automáticamente:
  ✅ Verifica y crea el archivo .env si falta
  ✅ Agrega variables de entorno faltantes
  ✅ Corrige permisos del archivo .env (Unix/Linux)
  ✅ Actualiza package.json con configuraciones faltantes
  ✅ Valida que las reparaciones funcionen

Después de ejecutar este script:
  1. Ejecuta: npm run debug-env
  2. Inicia el servidor: npm start
  3. Ejecuta auditoría: npm run security-audit
        `);
    }
}

// Ejecución desde línea de comandos
if (require.main === module) {
    const fixer = new SystemFixer();
    const args = process.argv.slice(2);

    if (args.includes('--help') || args.includes('-h')) {
        fixer.showUsage();
        process.exit(0);
    }

    fixer.fixAll().catch(error => {
        console.error('\n❌ Error en reparación:', error.message);
        console.log('\n💡 Soluciones manuales:');
        console.log('   1. Verifica que todos los archivos estén en su lugar');
        console.log('   2. Revisa los permisos de archivos');
        console.log('   3. Ejecuta: npm run debug-env para más información');
        process.exit(1);
    });
}

module.exports = SystemFixer;