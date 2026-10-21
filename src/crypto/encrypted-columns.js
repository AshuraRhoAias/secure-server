// REGISTRO DE COLUMNAS CIFRADAS.
//
// La rotación de claves re-cifra únicamente las columnas listadas aquí. Si creas una tabla o
// columna nueva con datos cifrados con tripleEncryptor y NO la añades a este registro, tras la
// próxima rotación esos datos quedarán cifrados con una clave que ya no existe (irrecuperables).
// test_rotation.js lo vigila: falla si database/schema.sql tiene una columna de texto cuyo
// nombre contiene "encrypted" y que no esté aquí ni en IGNORED.

const ENCRYPTED_COLUMNS = {
    users: {
        primaryKey: 'id',
        columns: [
            'email_encrypted',
            'personal_data_encrypted',
            'metadata_encrypted',
            'username_encrypted',
            'risk_level_encrypted',
            'encrypted_metadata'
        ]
    },
    security_logs: { primaryKey: 'id', columns: ['encrypted_details', 'encrypted_timestamp'] },
    // regenerable: son registros que el servidor vuelve a crear solo; si uno queda ilegible se puede borrar
    server_integrity: { primaryKey: 'id', columns: ['system_data_encrypted'], regenerable: true },
    encryption_keys: { primaryKey: 'id', columns: ['encrypted_key_data'] },
    user_notes: { primaryKey: 'id', columns: ['title_encrypted', 'content_encrypted'] },
    // Metadatos de /api/files. key_encrypted es la clave de CADA archivo envuelta con la clave maestra:
    // al rotar solo se re-envuelven estas claves, los bytes de los archivos no se tocan.
    user_files: { primaryKey: 'id', columns: ['filename_encrypted', 'key_encrypted'] }
};

// Columnas con "encrypted" en el nombre que NO guardan texto cifrado con tripleEncryptor
// (hoy ninguna; añade aquí `tabla.columna: 'motivo'` si alguna vez hace falta)
const IGNORED = {};

module.exports = { ENCRYPTED_COLUMNS, IGNORED };
