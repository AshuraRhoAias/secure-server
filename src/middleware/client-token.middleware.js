const clientTokenService = require('../security/client-token.service');

// Exige el token web diario (X-Client-Token) en cada petición protegida.
//
// Se monta DESPUÉS de verifyJWT, porque necesita saber qué usuario es
// (req.user.id) para validar que el token corresponde a ESE usuario y a HOY.
// Sin un token válido no se recibe la petición: responde 403.
function requireClientToken(req, res, next) {
    // Si no hay usuario, el JWT no se validó: deja que el flujo normal lo maneje.
    if (!req.user || req.user.id === undefined || req.user.id === null) {
        return res.status(401).json({
            success: false,
            message: 'Autenticación requerida',
            code: 'MISSING_TOKEN'
        });
    }

    const provided = req.headers[clientTokenService.HEADER_NAME];

    if (!provided) {
        return res.status(403).json({
            success: false,
            message: 'Falta el token de cliente diario (cabecera X-Client-Token)',
            code: 'CLIENT_TOKEN_REQUIRED'
        });
    }

    if (!clientTokenService.verify(req.user.id, provided)) {
        return res.status(403).json({
            success: false,
            message: 'Token de cliente inválido o caducado; vuelve a iniciar sesión para obtener el del día',
            code: 'INVALID_CLIENT_TOKEN'
        });
    }

    next();
}

module.exports = { requireClientToken };
