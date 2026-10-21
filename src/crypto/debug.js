// Logging de depuración del subsistema de cifrado.
//
// El cifrado es el camino caliente del servidor (se ejecuta en CADA lectura y
// escritura de datos). Volcar varias líneas por operación con console.log tenía
// un coste enorme: en las pruebas, /api/notes pasaba de ~8 req/s a mucho más al
// silenciarlo. Por eso TODO el log por operación del cifrado pasa por aquí y
// está APAGADO por defecto; se enciende sólo cuando se depura.
//
//   CRYPTO_DEBUG=true   -> vuelve a mostrar el log detallado por operación.
//
// Los errores reales (console.error) NO pasan por aquí: se siguen mostrando.

const ENABLED = process.env.CRYPTO_DEBUG === 'true';

function clog(...args) {
    if (ENABLED) console.log(...args);
}

module.exports = { clog, CRYPTO_DEBUG: ENABLED };
