const express = require('express');
const router = express.Router();
const notesController = require('../controllers/notes.controller');
const validate = require('../utils/validate');

// Montada automáticamente en /api/notes (ver routes/index.js).
// El cargador ya exige JWT (verifyJWT) y la protección global ya está activa: aquí solo va la lógica del recurso.

const idParam = validate.params({ id: { type: 'integer', required: true, min: 1 } });

router.post('/',
    validate.body({
        title: { type: 'string', required: true, min: 1, max: 200 },
        content: { type: 'string', max: 10000 }
    }),
    notesController.create
);

router.get('/',
    validate.query({
        page: { type: 'integer', min: 1, default: 1 },
        limit: { type: 'integer', min: 1, max: 100, default: 20 }
    }),
    notesController.list
);

router.get('/:id', idParam, notesController.getOne);

router.put('/:id',
    idParam,
    validate.body({
        title: { type: 'string', min: 1, max: 200 },
        content: { type: 'string', max: 10000 }
    }),
    notesController.update
);

router.delete('/:id', idParam, notesController.remove);

module.exports = router;
