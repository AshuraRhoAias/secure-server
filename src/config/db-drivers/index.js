// Adaptador de base de datos: elige el driver según DB_CLIENT (ver docs/BASES-DE-DATOS.md).
//
//   DB_CLIENT=mysql      (por defecto) MariaDB y MySQL, con mysql2
//   DB_CLIENT=mariadb    alias de mysql
//   DB_CLIENT=postgres   PostgreSQL y Supabase (alias: postgresql, supabase) — fase 2, todavía NO disponible
//
// CONTRATO de un driver (lo que usa src/config/database.js y los módulos que retienen una conexión, como el líder de tareas y
// la rotación de claves). Es el subconjunto de mysql2/promise que el proyecto usa, para que los ~230 llamantes no cambien:
//   driver.name                           'mysql' | 'postgres' (métricas y trazas: db.system)
//   driver.createPool(options) → pool     options = { uri, connectionLimit, queueLimit, ssl, connectTimeout, ... }
//   pool.getConnection() → conn
//   pool.end()
//   conn.execute(sql, params) → [rows]                 SELECT: array de filas (objetos)
//                             → [{ affectedRows, insertId }]   INSERT/UPDATE/DELETE
//   conn.query(sql, params)   → igual (sin preparar; solo para lo que no admite sentencia preparada)
//   conn.beginTransaction() · conn.commit() · conn.rollback() · conn.release()
//   conn.destroy() · conn.on('error', fn)   (conexión retenida del líder: cerrarla libera su cerrojo en el servidor)
//   driver.isTlsUnsupported(error) → true si el servidor no admite TLS (mensaje claro en testConnection)
// Las consultas siguen escritas con marcadores `?`: un driver que use otros ($1, $2…) los traduce él.

const CLIENTS = Object.freeze({
    mysql: 'mysql',
    mariadb: 'mysql',
    postgres: 'postgres',
    postgresql: 'postgres',
    supabase: 'postgres'
});

// Motor configurado (normalizado). Lanza con un mensaje claro si DB_CLIENT no es válido: mejor no arrancar que adivinar.
function resolveClient(value = process.env.DB_CLIENT) {
    const key = String(value || 'mysql').trim().toLowerCase();
    if (!Object.hasOwn(CLIENTS, key)) {
        throw new Error(`DB_CLIENT no válido: "${value}". Usa mysql (MariaDB/MySQL) o postgres (PostgreSQL/Supabase).`);
    }
    return CLIENTS[key];
}

function loadDriver(client = resolveClient()) {
    if (client === 'mysql') return require('./mysql');
    // PostgreSQL necesita antes el SQL portable módulo a módulo y su job de CI (docs/BASES-DE-DATOS.md §3): sin eso no se ofrece
    throw new Error('DB_CLIENT=postgres todavía no está disponible: el soporte de PostgreSQL/Supabase está en desarrollo (docs/BASES-DE-DATOS.md).');
}

module.exports = { resolveClient, loadDriver, CLIENTS };
