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

module.exports = router;