// Manejador de errores global de Express.
//
// Los errores del CLIENTE (JSON malformado, payload demasiado grande...) llevan un `status` 4xx:
// se responden con ese código y NO se registran como errores del servidor. Si se registraran,
// cualquiera, sin autenticarse, podría llenar la tabla de auditoría con filas SERVER_ERROR de
// severidad alta enviando JSON roto. Solo los errores reales (5xx) se registran y se ocultan
// detrás de un mensaje genérico.
function createErrorHandler({ logError }) {
    // Express reconoce un manejador de errores por tener exactamente 4 parámetros
    return (error, req, res, next) => {
        const status = error.status >= 400 && error.status < 500 ? error.status : 500;

        if (status === 500) {
            console.error('❌ Error no manejado:', error);
            logError(error, req);
        }

        res.status(status).json({
            success: false,
            message: status === 500 ? 'Error interno del servidor' : 'Solicitud inválida',
            ...(process.env.NODE_ENV === 'development' && { error: error.message })
        });
    };
}

module.exports = { createErrorHandler };
