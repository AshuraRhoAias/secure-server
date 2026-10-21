const express = require('express');
const router = express.Router();
const authController = require('../controllers/auth.controller');
const authMiddleware = require('../../middleware/auth.middleware');
const protectionMiddleware = require('../../middleware/protection.middleware');
const validate = require('../utils/validate');

// La protección global (autoProtect) ya está en src/index.js: aquí NO se repite. Montarla dos veces
// contaba cada petición doble en los contadores de la base de datos.

// Rutas públicas (sin autenticación)
router.post('/register',
    protectionMiddleware.highSecurity(),
    validate.body({
        username: { type: 'string', required: true, min: 3, max: 64 },
        email: { type: 'email', required: true, max: 254 },
        password: { type: 'string', required: true, min: 10, max: 128, trim: false },
        deviceInfo: { type: 'object' }
    }),
    authController.register
);

router.post('/login',
    protectionMiddleware.highSecurity(),
    validate.body({
        username: { type: 'string', required: true, min: 1, max: 64 },
        password: { type: 'string', required: true, min: 1, max: 128, trim: false },
        deviceInfo: { type: 'object' }
    }),
    authController.login
);

// Rutas protegidas (requieren autenticación)
router.use(authMiddleware.verifyJWT);

router.post('/logout', authController.logout);
router.get('/profile', authController.getProfile);

// Mezcla rutas públicas (register/login) y protegidas (logout/profile): gestiona su propia protección
router.access = 'custom';

module.exports = router;
