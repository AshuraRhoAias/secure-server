const express = require('express');
const router = express.Router();
const authController = require('../controllers/auth.controller');
const authMiddleware = require('../../middleware/auth.middleware');
const protectionMiddleware = require('../../middleware/protection.middleware');

// Aplicar protección automática a todas las rutas
router.use(protectionMiddleware.autoProtect());

// Rutas públicas (sin autenticación)
router.post('/register',
    protectionMiddleware.highSecurity(),
    authController.register
);

router.post('/login',
    protectionMiddleware.highSecurity(),
    authController.login
);

// Rutas protegidas (requieren autenticación)
router.use(authMiddleware.verifyJWT);

router.post('/logout', authController.logout);
router.get('/profile', authController.getProfile);
// Renueva el token de cliente diario sin volver a iniciar sesión.
router.get('/client-token', authController.getClientToken);

// Mezcla rutas públicas (register/login) y protegidas (logout/profile): gestiona su propia protección
router.access = 'custom';

module.exports = router;