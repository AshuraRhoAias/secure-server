const { POLLUTION_KEYS } = require('../security/injection-detector');

// Rechaza estructuras de entrada que ninguna API legítima envía, ANTES de que lleguen a un controlador:
//
//   - claves __proto__ / constructor / prototype (contaminación de prototipos)
//   - bytes NUL (truncan cadenas en librerías nativas y en rutas de archivo)
//   - anidamiento excesivo o un número desmesurado de claves/elementos (consumo de CPU/memoria)
//
// No modifica los datos: o los deja pasar tal cual o responde 400.

const MAX_DEPTH = 10;
const MAX_NODES = 5000;
const MAX_STRING = 1_000_000;

function inspect(value, state, depth = 0) {
    if (++state.nodes > MAX_NODES) return 'DEMASIADOS_ELEMENTOS';
    if (depth > MAX_DEPTH) return 'ANIDAMIENTO_EXCESIVO';

    if (typeof value === 'string') {
        if (value.length > MAX_STRING) return 'TEXTO_DEMASIADO_LARGO';
        return value.includes('\u0000') ? 'BYTE_NULO' : null;
    }
    if (Array.isArray(value)) {
        for (const item of value) {
            const problem = inspect(item, state, depth + 1);
            if (problem) return problem;
        }
        return null;
    }
    if (value && typeof value === 'object') {
        for (const key of Object.keys(value)) {
            if (POLLUTION_KEYS.has(key)) return 'CLAVE_PROHIBIDA';
            if (key.includes('\u0000')) return 'BYTE_NULO';
            const problem = inspect(value[key], state, depth + 1);
            if (problem) return problem;
        }
    }
    return null;
}

function sanitizeInput() {
    return (req, res, next) => {
        const state = { nodes: 0 };
        for (const source of ['body', 'query', 'params']) {
            const problem = req[source] && typeof req[source] === 'object' ? inspect(req[source], state) : null;
            if (problem) {
                // El evento lo registra la capa de protección (hereda el hallazgo del detector);
                // aquí solo se corta la petición.
                return res.status(400).json({
                    success: false,
                    message: 'Entrada inválida',
                    code: 'INVALID_INPUT',
                    reason: problem
                });
            }
        }
        next();
    };
}

module.exports = { sanitizeInput, inspect };
