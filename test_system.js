const crypto = require('crypto');
require('dotenv').config();


async function testSystem() {
    console.log('🧪 Iniciando tests del sistema ultra seguro...\n');

    let passedTests = 0;
    let totalTests = 0;

    // Test 1: Cifrado Triple
    totalTests++;
    try {
        console.log('🔐 Test 1: Sistema de cifrado triple');
        const tripleEncryptor = require('./src/crypto/tripleEncryptor');

        const testData = 'Test de cifrado ultra seguro ' + Date.now();
        const encrypted = tripleEncryptor.encrypt(testData);
        const decrypted = tripleEncryptor.decrypt(encrypted);

        if (decrypted === testData) {
            console.log('✅ Cifrado triple: PASS');
            passedTests++;
        } else {
            console.log('❌ Cifrado triple: FAIL');
        }
    } catch (error) {
        console.log('❌ Cifrado triple: ERROR -', error.message);
    }

    // Test 2: Base de datos
    totalTests++;
    try {
        console.log('🗄️ Test 2: Conexión a base de datos');
        const database = require('./src/config/database');

        const connected = await database.testConnection();

        if (connected) {
            console.log('✅ Base de datos: PASS');
            passedTests++;
        } else {
            console.log('❌ Base de datos: FAIL');
        }
    } catch (error) {
        console.log('❌ Base de datos: ERROR -', error.message);
    }

    // Test 3: Generación de credenciales
    totalTests++;
    try {
        console.log('🔑 Test 3: Generación de credenciales');
        const credentialBuilder = require('./src/config/credential-builder');

        const jwtSecret = credentialBuilder.generateJWTSecret();

        if (jwtSecret && jwtSecret.length > 0) {
            console.log('✅ Credenciales: PASS');
            passedTests++;
        } else {
            console.log('❌ Credenciales: FAIL');
        }
    } catch (error) {
        console.log('❌ Credenciales: ERROR -', error.message);
    }

    // Test 4: Sistema de camuflaje
    totalTests++;
    try {
        console.log('🎭 Test 4: Sistema de camuflaje de mensajes');
        const disguiser = require('./src/crypto/disguiser');

        const testKeys = {
            key1: 'test_key_1',
            key2: 'test_key_2',
            key3: 'test_key_3'
        };

        const camouflageMessage = disguiser.generateCamouflageMessage(testKeys);

        if (camouflageMessage && camouflageMessage.body && camouflageMessage.subject) {
            console.log('✅ Camuflaje: PASS');
            passedTests++;
        } else {
            console.log('❌ Camuflaje: FAIL');
        }
    } catch (error) {
        console.log('❌ Camuflaje: ERROR -', error.message);
    }

    // Test 5: Verificación de integridad
    totalTests++;
    try {
        console.log('🛡️ Test 5: Verificación de integridad');
        const serverCheck = require('./src/middleware/serverCheck.middleware');

        const status = serverCheck.getStatus();

        if (status && status.serverFingerprint) {
            console.log('✅ Integridad: PASS');
            passedTests++;
        } else {
            console.log('❌ Integridad: FAIL');
        }
    } catch (error) {
        console.log('❌ Integridad: ERROR -', error.message);
    }

    // Resumen
    console.log('\n📊 RESUMEN DE TESTS:');
    console.log('='.repeat(30));
    console.log(`✅ Tests pasados: ${passedTests}/${totalTests}`);
    console.log(`❌ Tests fallidos: ${totalTests - passedTests}/${totalTests}`);
    console.log(`📈 Porcentaje de éxito: ${Math.round((passedTests / totalTests) * 100)}%`);

    if (passedTests === totalTests) {
        console.log('\n🎉 ¡TODOS LOS TESTS PASARON! Sistema listo para producción.');
    } else {
        console.log('\n⚠️ Algunos tests fallaron. Revisa la configuración antes de continuar.');
    }
}

// Ejecutar tests
testSystem().catch(error => {
    console.error('❌ Error ejecutando tests:', error);
    process.exit(1);
});