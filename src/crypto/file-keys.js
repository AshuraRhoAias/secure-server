// Punto único para proteger y recuperar la clave de cada archivo: clave maestra (v4:) o KMS (kms1:, KMS_DATA_KEYS=true).
// Se lee siempre según lo que HAYA guardado, así que se puede cambiar de modo sin romper los archivos existentes.

const tripleEncryptor = require('./tripleEncryptor');
const dataKeys = require('./kms-data-keys');

const protect = async (storageName, key) => dataKeys.enabled()
    ? dataKeys.wrapDataKey(storageName, key)
    : tripleEncryptor.encrypt(key.toString('hex'));

const recover = async (storageName, stored) => dataKeys.isKmsKey(stored)
    ? dataKeys.unwrapDataKey(storageName, stored)
    : Buffer.from(tripleEncryptor.decrypt(stored), 'hex');

module.exports = { protect, recover };
