const express = require('express');
const router = express.Router();
const ssoController = require('../controllers/sso.controller');
const protectionMiddleware = require('../../middleware/protection.middleware');

// SSO por OpenID Connect (ver src/sso/oidc.service.js). Públicas: son la puerta de entrada.
// Sin SSO_ISSUER / SSO_CLIENT_ID / SSO_REDIRECT_URI responden 404 SSO_NOT_CONFIGURED.

router.get('/status', ssoController.status);
router.get('/login', protectionMiddleware.highSecurity(), ssoController.login);
router.get('/callback', protectionMiddleware.highSecurity(), ssoController.callback);

router.access = 'public';
module.exports = router;
