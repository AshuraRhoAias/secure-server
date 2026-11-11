// Driver MariaDB / MySQL (mysql2). El pool de mysql2 ya cumple el contrato del adaptador (ver ./index.js) tal cual:
// este archivo es el ÚNICO del código de la aplicación que importa mysql2.
const mysql = require('mysql2/promise');

module.exports = {
    name: 'mysql',
    createPool: (options) => mysql.createPool(options),
    isTlsUnsupported: (error) => error?.code === 'HANDSHAKE_NO_SSL_SUPPORT'
};
