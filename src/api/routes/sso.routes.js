const express = require('express');
const router = express.Router();
const ssoController = require('../controllers/sso.controller');
const protectionMiddleware = require('../../middleware/protection.middleware');

// SSO por OpenID Connect (ver src/sso/oidc.service.js). Públicas: son la puerta de entrada.
// Sin SSO_ISSUER / SSO_CLIENT_ID / SSO_REDIRECT_URI responden 404 SSO_NOT_CONFIGURED.

const validate = require('../utils/validate');
const loginQuery = validate.query({
    format: { type: 'enum', values: ['json'] },
    handoff: { type: 'string', pattern: /^[A-Za-z0-9_-]{43}$/ }
});

router.get('/status', ssoController.status);
router.get('/login', protectionMiddleware.highSecurity(), loginQuery, ssoController.login);
router.get('/callback', protectionMiddleware.highSecurity(), ssoController.callback);
// Canje del código de entrega a la interfaz web (OIDC y SAML): lo llama el BFF, servidor a servidor. Ver src/sso/handoff.service.js
router.post('/exchange',
    protectionMiddleware.highSecurity(),
    validate.body({
        code: { type: 'string', required: true, pattern: /^[A-Za-z0-9_-]{43}$/ },
        verifier: { type: 'string', required: true, pattern: /^[A-Za-z0-9_-]{43,128}$/ }
    }),
    ssoController.exchange
);

router.access = 'public';
module.exports = router;
