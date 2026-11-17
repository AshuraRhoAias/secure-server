// debug-env.js - Script para diagnosticar problemas con variables de entorno

const fs = require('fs');
const path = require('path');

console.log('🔍 Diagnosticando problemas con variables de entorno...\n');

// 1. Verificar archivo .env
const envPath = path.join(__dirname, '..', '.env');
console.log(`📍 Buscando archivo .env en: ${envPath}`);

if (fs.existsSync(envPath)) {
    console.log('✅ Archivo .env encontrado');

    // Verificar permisos
    try {
        const stats = fs.statSync(envPath);
        const perms = (stats.mode & parseInt('777', 8)).toString(8);
        console.log(`📋 Permisos actuales: ${perms}`);

        if (perms !== '600') {
            console.log('⚠️ Permisos inseguros detectados');

            // Corregir permisos automáticamente (solo en sistemas Unix)
            if (process.platform !== 'win32') {
                fs.chmodSync(envPath, 0o600);
                console.log('✅ Permisos corregidos a 600');
            } else {
                console.log('ℹ️ En Windows, ajusta manualmente los permisos del archivo');
            }
        }
    } catch (error) {
        console.log('❌ Error verificando permisos:', error.message);
    }

    // Leer contenido del archivo
    try {
        const envContent = fs.readFileSync(envPath, 'utf8');
        const lines = envContent.split('\n').filter(line =>
            line.trim() && !line.trim().startsWith('#')
        );

        console.log(`📊 Variables definidas en .env: ${lines.length}`);

        // Mostrar variables críticas
        const criticalVars = [
            'BASE_SEED',
            'DB_FRAGMENT_1',
            'DB_FRAGMENT_2',
            'DB_FRAGMENT_3',
            'PRIMARY_EMAIL_USER',
            'EMAIL_DOMAIN_1',
            'NODE_ENV'
        ];

        console.log('\n🔑 Variables críticas en archivo:');
        criticalVars.forEach(varName => {
            const found = lines.find(line => line.startsWith(`${varName}=`));
            console.log(`   ${varName}: ${found ? '✅' : '❌'}`);
        });

    } catch (error) {
        console.log('❌ Error leyendo archivo .env:', error.message);
    }

} else {
    console.log('❌ Archivo .env NO encontrado');
}

// 2. Intentar cargar dotenv
console.log('\n🔄 Intentando cargar dotenv...');
try {
    const result = require('dotenv').config();

    if (result.error) {
        console.log('❌ Error cargando dotenv:', result.error.message);
    } else {
        console.log('✅ Dotenv cargado exitosamente');
        console.log(`📊 Variables cargadas: ${Object.keys(result.parsed || {}).length}`);
    }
} catch (error) {
    console.log('❌ Error requiriendo dotenv:', error.message);
}

// 3. Verificar variables en process.env
console.log('\n🧪 Verificando variables en process.env:');
const criticalVars = [
    'BASE_SEED',
    'DB_FRAGMENT_1',
    'DB_FRAGMENT_2',
    'DB_FRAGMENT_3',
    'PRIMARY_EMAIL_USER',
    'EMAIL_DOMAIN_1',
    'NODE_ENV'
];

criticalVars.forEach(varName => {
    const value = process.env[varName];
    console.log(`   ${varName}: ${value ? '✅ (longitud: ' + value.length + ')' : '❌ NO ENCONTRADA'}`);
});

// 4. Información del entorno
console.log('\n📋 Información del entorno:');
console.log(`   Node.js: ${process.version}`);
console.log(`   Plataforma: ${process.platform}`);
console.log(`   Directorio actual: ${process.cwd()}`);
console.log(`   Archivo ejecutado desde: ${__dirname}`);

// 5. Recomendaciones
console.log('\n💡 Recomendaciones:');
console.log('   1. Asegúrate de que el archivo .env esté en la raíz del proyecto');
console.log('   2. Verifica que no haya espacios extra en las líneas del .env');
console.log('   3. Asegúrate de que dotenv se cargue ANTES de cualquier otro require');
console.log('   4. En Windows, verifica que no haya problemas de encoding');
console.log('   5. Intenta reiniciar el proceso Node.js completamente');