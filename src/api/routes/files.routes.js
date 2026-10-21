const express = require('express');
const router = express.Router();
const filesController = require('../controllers/files.controller');
const protectionMiddleware = require('../../middleware/protection.middleware');
const validate = require('../utils/validate');
const { CATEGORIES } = require('../../files/file-types');

// Montada automáticamente en /api/files (ver routes/index.js): el cargador ya exige JWT y la
// protección global ya está activa. Los archivos van cifrados en disco (src/files/file-cipher.js).

const perUser = (req) => `u:${req.user.id}`;
const idParam = validate.params({ id: { type: 'integer', required: true, min: 1 } });

// Subida: multipart/form-data con UN archivo en el campo "file"
router.post('/',
    protectionMiddleware.limit({
        scope: 'upload', limit: () => Number(process.env.UPLOAD_RATE_PER_MIN) || 20, key: perUser,
        code: 'UPLOAD_RATE_LIMITED', message: 'Demasiadas subidas, espera un momento'
    }),
    filesController.upload
);

router.get('/quota', filesController.quota);

router.get('/',
    validate.query({
        limit: { type: 'integer', min: 1, max: 100, default: 20 },
        before: { type: 'integer', min: 1 },
        category: { type: 'enum', values: CATEGORIES }
    }),
    filesController.list
);

router.get('/:id', idParam, filesController.getOne);

router.get('/:id/download',
    protectionMiddleware.limit({
        scope: 'download', limit: () => Number(process.env.DOWNLOAD_RATE_PER_MIN) || 600, key: perUser,
        code: 'DOWNLOAD_RATE_LIMITED', message: 'Demasiadas descargas, espera un momento'
    }),
    idParam,
    validate.query({ inline: { type: 'boolean' } }),
    filesController.download
);

router.delete('/:id', idParam, filesController.remove);

module.exports = router;
