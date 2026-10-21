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

// Segundo paso del login cuando la cuenta tiene MFA
router.post('/login/mfa',
    protectionMiddleware.highSecurity(),
    validate.body({
        mfaToken: { type: 'string', required: true, max: 2000 },
        otp: { type: 'string', pattern: /^\d{6}$/ },
        recoveryCode: { type: 'string', max: 32, pattern: /^[A-Za-z2-7-]{16,23}$/ },
        deviceInfo: { type: 'object' }
    }),
    authController.loginMfa
);

// Rutas protegidas (requieren autenticación)
router.use(authMiddleware.verifyJWT);

// Autenticación en dos pasos (TOTP)
const reauth = {
    password: { type: 'string', required: true, min: 1, max: 128, trim: false },
    otp: { type: 'string', pattern: /^\d{6}$/ },
    recoveryCode: { type: 'string', max: 32, pattern: /^[A-Za-z2-7-]{16,23}$/ }
};
router.get('/mfa', authController.mfaStatus);
router.post('/mfa/setup', protectionMiddleware.highSecurity(), authController.mfaSetup);
router.post('/mfa/enable', protectionMiddleware.highSecurity(), validate.body({ otp: { type: 'string', required: true, pattern: /^\d{6}$/ } }), authController.mfaEnable);
router.post('/mfa/disable', protectionMiddleware.highSecurity(), validate.body(reauth), authController.mfaDisable);
router.post('/mfa/recovery-codes', protectionMiddleware.highSecurity(), validate.body(reauth), authController.mfaRegenerateCodes);

router.post('/logout', authController.logout);
router.get('/profile', authController.getProfile);

// Mezcla rutas públicas (register/login) y protegidas (logout/profile): gestiona su propia protección
router.access = 'custom';

module.exports = router;
