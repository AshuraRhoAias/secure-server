const fs = require('fs');
const path = require('path');
const authMiddleware = require('../../middleware/auth.middleware');
const { requireClientToken } = require('../../middleware/client-token.middleware');

// Cargador automático de APIs.
//
// Cada archivo `<nombre>.routes.js` de esta carpeta se monta en `/api/<nombre>`.
// Para crear una API nueva basta con añadir el archivo: NO hay que tocar src/index.js.
//
// Seguridad por defecto: protectionMiddleware.autoProtect() ya es global (src/index.js) y el
// cargador antepone authMiddleware.verifyJWT. Un router puede cambiar eso con `router.access`:
//
//   'protected' (por defecto)  JWT + token de cliente diario (X-Client-Token) obligatorios
//   'public'                   sin login (solo la protección global)
//   'custom'                   el router gestiona su propia autenticación (p. ej. /api/auth)
//
// En las rutas 'protected' se añade requireClientToken DESPUÉS de verifyJWT: sin
// el token web diario único por usuario no se recibe la petición (403).

const ROUTE_SUFFIX = '.routes.js';

function registerRoutes(app) {
    const mounted = [];

    const files = fs.readdirSync(__dirname)
        .filter(file => file.endsWith(ROUTE_SUFFIX))
        .sort();

    for (const file of files) {
        const name = file.slice(0, -ROUTE_SUFFIX.length);
        const router = require(path.join(__dirname, file));
        const access = router.access || 'protected';
        const mountPath = `/api/${name}`;

        if (typeof router !== 'function' || !['protected', 'public', 'custom'].includes(access)) {
            throw new Error(`${file}: debe exportar un express.Router() y router.access debe ser protected | public | custom`);
        }

        const middlewares = access === 'protected'
            ? [authMiddleware.verifyJWT, requireClientToken]
            : [];

        app.use(mountPath, ...middlewares, router);
        mounted.push({ path: mountPath, access });
    }

    return mounted;
}

module.exports = { registerRoutes };
