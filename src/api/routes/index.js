const fs = require('fs');
const path = require('path');
const authMiddleware = require('../../middleware/auth.middleware');

// Cargador automático de APIs.
//
// Cada archivo `<nombre>.routes.js` de esta carpeta se monta en `/api/<nombre>`.
// Para crear una API nueva basta con añadir el archivo: NO hay que tocar src/index.js.
//
// Seguridad por defecto: protectionMiddleware.autoProtect() ya es global (src/index.js) y el
// cargador antepone authMiddleware.verifyJWT. Un router puede cambiar eso con `router.access`:
//
//   'protected' (por defecto)  JWT obligatorio
//   'public'                   sin login (solo la protección global)
//   'custom'                   el router gestiona su propia autenticación (p. ej. /api/auth)

const ROUTE_SUFFIX = '.routes.js';

function registerRoutes(app) {
    const mounted = [];

    const files = fs.readdirSync(__dirname)
        .filter(file => file.endsWith(ROUTE_SUFFIX))
        .sort();

    for (const file of files) {
        const name = file.slice(0, -ROUTE_SUFFIX.length);
        // eslint-disable-next-line security/detect-non-literal-require -- `file` sale de leer ESTA carpeta del servidor (solo *.routes.js), no de la entrada del usuario
        const router = require(path.join(__dirname, file));
        const access = router.access || 'protected';
        const mountPath = `/api/${name}`;

        if (typeof router !== 'function' || !['protected', 'public', 'custom'].includes(access)) {
            throw new Error(`${file}: debe exportar un express.Router() y router.access debe ser protected | public | custom`);
        }

        const middlewares = access === 'protected' ? [authMiddleware.verifyJWT] : [];

        app.use(mountPath, ...middlewares, router);
        mounted.push({ path: mountPath, access });
    }

    return mounted;
}

module.exports = { registerRoutes };
