const express = require('express');
const router = express.Router();
const samlController = require('../controllers/saml.controller');
const protectionMiddleware = require('../../middleware/protection.middleware');

// SSO por SAML 2.0 (ver src/sso/saml.service.js). Públicas: son la puerta de entrada.
// Sin SAML_IDP_SSO_URL / SAML_IDP_ENTITY_ID / SAML_IDP_CERT / SAML_CALLBACK_URL responden 404 SAML_NOT_CONFIGURED.
//
//   GET  /api/saml/status     ¿activado?
//   GET  /api/saml/metadata   metadatos del SP para registrarlo en el IdP
//   GET  /api/saml/login      inicia el login (302 al IdP, o JSON con ?format=json)
//   POST /api/saml/acs        recibe la respuesta firmada del IdP (application/x-www-form-urlencoded)

router.get('/status', samlController.status);
router.get('/metadata', samlController.metadata);
router.get('/login',
    protectionMiddleware.highSecurity(),
    require('../utils/validate').query({
        format: { type: 'enum', values: ['json'] },
        handoff: { type: 'string', pattern: /^[A-Za-z0-9_-]{43}$/ }
    }),
    samlController.login
);
router.post('/acs', protectionMiddleware.highSecurity(), samlController.acs);

router.access = 'public';
module.exports = router;
