// test-mysql-nodejs.js
const mysql = require('mysql2/promise');

// Configuración para RemoteMySQL.com (ejemplo)
// Cambia estos datos por los que obtengas al registrarte
const dbConfig = {
    host: 'sistemagym.xo.je',
    user: 'if0_39743949',
    password: 'bbP5q08WZw9Zx', // Cambia esto por tu contraseña
    database: 'if0_39743949_sistemagym',
    port: 3306,
    connectTimeout: 60000
};

async function testConnection() {
    console.log('🔄 Conectando a MySQL remoto...');
    console.log(`Host: ${dbConfig.host}`);
    console.log(`Usuario: ${dbConfig.user}`);
    console.log(`Base de datos: ${dbConfig.database}`);
    
    try {
        // Crear conexión
        const connection = await mysql.createConnection(dbConfig);
        console.log('✅ ¡Conexión exitosa!');
        
        // Test 1: Información del servidor
        const [serverInfo] = await connection.execute(
            'SELECT NOW() as fecha_actual, VERSION() as version_mysql, USER() as usuario_actual'
        );
        
        console.log('\n📊 Información del servidor:');
        console.log(`- Fecha: ${serverInfo[0].fecha_actual}`);
        console.log(`- Versión MySQL: ${serverInfo[0].version_mysql}`);
        console.log(`- Usuario: ${serverInfo[0].usuario_actual}`);
        
        // Test 2: Crear tabla de prueba
        console.log('\n🔧 Creando tabla de prueba...');
        await connection.execute(`
            CREATE TABLE IF NOT EXISTS usuarios_test (
                id INT AUTO_INCREMENT PRIMARY KEY,
                nombre VARCHAR(100),
                email VARCHAR(100),
                fecha_registro TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        console.log('✅ Tabla creada');
        
        // Test 3: Insertar datos
        console.log('\n📝 Insertando datos de prueba...');
        const [insertResult] = await connection.execute(
            'INSERT INTO usuarios_test (nombre, email) VALUES (?, ?)',
            ['Juan Pérez', 'juan@example.com']
        );
        console.log(`✅ Usuario insertado con ID: ${insertResult.insertId}`);
        
        // Test 4: Consultar datos
        console.log('\n📋 Consultando datos...');
        const [rows] = await connection.execute('SELECT * FROM usuarios_test ORDER BY id DESC LIMIT 5');
        
        if (rows.length > 0) {
            console.log('✅ Datos encontrados:');
            rows.forEach((row, index) => {
                console.log(`${index + 1}. ID: ${row.id}, Nombre: ${row.nombre}, Email: ${row.email}`);
            });
        } else {
            console.log('⚠️ No hay datos en la tabla');
        }
        
        // Test 5: Contar registros
        const [countResult] = await connection.execute('SELECT COUNT(*) as total FROM usuarios_test');
        console.log(`\n📊 Total de registros: ${countResult[0].total}`);
        
        // Cerrar conexión
        await connection.end();
        console.log('\n🔒 Conexión cerrada exitosamente');
        
    } catch (error) {
        console.error('❌ Error:', error.message);
        
        // Diagnóstico del error
        if (error.code === 'ENOTFOUND') {
            console.log('💡 El host no se pudo resolver. Verifica:');
            console.log('   - Que el hostname sea correcto');
            console.log('   - Que tengas conexión a internet');
        } else if (error.code === 'ER_ACCESS_DENIED_ERROR') {
            console.log('💡 Acceso denegado. Verifica:');
            console.log('   - Usuario y contraseña correctos');
            console.log('   - Que el usuario tenga permisos');
        } else if (error.code === 'ETIMEDOUT') {
            console.log('💡 Timeout de conexión. Puede ser:');
            console.log('   - Firewall bloqueando el puerto 3306');
            console.log('   - Servidor MySQL no disponible');
        }
    }
}

// Ejecutar test
testConnection();

// Función auxiliar para uso en aplicaciones
async function ejecutarConsulta(sql, params = []) {
    let connection;
    try {
        connection = await mysql.createConnection(dbConfig);
        const [results] = await connection.execute(sql, params);
        return results;
    } catch (error) {
        console.error('Error en consulta:', error.message);
        throw error;
    } finally {
        if (connection) {
            await connection.end();
        }
    }
}

// Ejemplo de uso de la función auxiliar
/*
(async () => {
    try {
        const usuarios = await ejecutarConsulta('SELECT * FROM usuarios_test LIMIT 3');
        console.log('Usuarios:', usuarios);
    } catch (error) {
        console.error('Error:', error.message);
    }
})();
*/