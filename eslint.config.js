// Análisis estático de seguridad (npm run lint:security): eslint-plugin-security sobre src/ y scripts/.
// No hace falta red ni servicios. Se ejecuta en CI y debe quedar a CERO avisos.
//
// Dos reglas heurísticas están desactivadas porque generan ruido sin aportar señal en este código:
//   - detect-object-injection: marca cualquier `obj[variable]` (más de 100 avisos, todos con claves controladas).
//   - detect-non-literal-fs-filename: marca cualquier ruta que no sea un literal. Las rutas de este proyecto salen de
//     constantes de configuración o de UUID generados por el servidor (src/files/storage.js valida el UUID); el
//     recorrido de directorios se prueba de forma explícita en test_files.js, que es donde se defiende.
// El resto (eval, child_process, expresiones regulares peligrosas, require dinámico, temporización, caracteres bidi…)
// se mantiene como error. Los falsos positivos se justifican en línea con `eslint-disable-next-line` y el motivo.
const security = require('eslint-plugin-security');
const globals = require('globals');

module.exports = [
    security.configs.recommended,
    {
        files: ['src/**/*.js', 'scripts/**/*.js'],
        languageOptions: { ecmaVersion: 2023, sourceType: 'commonjs', globals: { ...globals.node } },
        rules: {
            'security/detect-object-injection': 'off',
            'security/detect-non-literal-fs-filename': 'off',
            'no-eval': 'error',
            'no-implied-eval': 'error',
            'no-new-func': 'error'
        }
    }
];
