// Validador mínimo para req.body / req.query / req.params (sin dependencias extra).
//
// Uso:
//   router.post('/', validate.body({
//       title:   { type: 'string', required: true, min: 1, max: 200 },
//       content: { type: 'string', max: 10000 }
//   }), controller.create);
//
// Tipos soportados: string, number, integer, boolean, email, enum (con `values`).
// Los campos que no estén en el esquema se descartan (req.body queda "limpio").

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function checkField(name, rule, raw) {
    const isText = rule.type === 'string' || rule.type === 'email';
    // Un string vacío cuenta como "ausente" salvo en campos de texto opcionales,
    // donde se valida contra min (así `title: ""` falla y `content: ""` borra el contenido).
    const missing = raw === undefined || raw === null || (raw === '' && (!isText || rule.required));

    if (missing) {
        if (rule.required) return { error: `${name} es requerido` };
        return { skip: true };
    }

    let value = raw;

    switch (rule.type) {
        case 'string':
        case 'email': {
            if (typeof value !== 'string') return { error: `${name} debe ser texto` };
            value = value.trim();
            if (rule.type === 'email' && !EMAIL_REGEX.test(value)) {
                return { error: `${name} no tiene formato de email válido` };
            }
            if (rule.min !== undefined && value.length < rule.min) {
                return { error: `${name} debe tener al menos ${rule.min} caracteres` };
            }
            if (rule.max !== undefined && value.length > rule.max) {
                return { error: `${name} no puede superar ${rule.max} caracteres` };
            }
            break;
        }
        case 'number':
        case 'integer': {
            // Los query params llegan como string
            if (typeof value === 'string' && value.trim() !== '') value = Number(value);
            if (typeof value !== 'number' || !Number.isFinite(value)) {
                return { error: `${name} debe ser numérico` };
            }
            if (rule.type === 'integer' && !Number.isInteger(value)) {
                return { error: `${name} debe ser un entero` };
            }
            if (rule.min !== undefined && value < rule.min) return { error: `${name} debe ser >= ${rule.min}` };
            if (rule.max !== undefined && value > rule.max) return { error: `${name} debe ser <= ${rule.max}` };
            break;
        }
        case 'boolean': {
            if (value === 'true') value = true;
            else if (value === 'false') value = false;
            if (typeof value !== 'boolean') return { error: `${name} debe ser booleano` };
            break;
        }
        case 'enum': {
            if (!Array.isArray(rule.values) || !rule.values.includes(value)) {
                return { error: `${name} debe ser uno de: ${(rule.values || []).join(', ')}` };
            }
            break;
        }
        default:
            return { error: `${name}: tipo de validación desconocido (${rule.type})` };
    }

    return { value };
}

function build(source, schema) {
    return (req, res, next) => {
        const input = req[source] ?? {};
        const clean = {};
        const errors = [];

        for (const [name, rule] of Object.entries(schema)) {
            const result = checkField(name, rule, input[name]);
            if (result.error) errors.push(result.error);
            else if (!result.skip) clean[name] = result.value;
            else if (rule.default !== undefined) clean[name] = rule.default;
        }

        if (errors.length > 0) {
            return res.status(400).json({
                success: false,
                message: 'Datos inválidos',
                code: 'VALIDATION_ERROR',
                errors
            });
        }

        // req.query es de solo lectura en Express 5, por eso se guarda en req.validated
        req.validated = { ...(req.validated || {}), [source]: clean };
        if (source === 'body') req.body = clean;
        next();
    };
}

module.exports = {
    body: (schema) => build('body', schema),
    query: (schema) => build('query', schema),
    params: (schema) => build('params', schema)
};
