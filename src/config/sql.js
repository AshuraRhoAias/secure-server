// Ayudas para construir SQL SIN concatenar texto del usuario.
//
// La defensa contra inyección SQL de este proyecto es de tres capas:
//   1. TODA consulta usa parámetros (`?`): mysql2 `execute` las envía como sentencias preparadas
//      en el servidor, de modo que los valores nunca se interpretan como SQL.
//   2. Lo único que no admite parámetros (LIMIT/OFFSET, listas de `?`) pasa por estas funciones,
//      que o devuelven un entero seguro o lanzan una excepción.
//   3. test_security.js recorre el código fuente y FALLA si encuentra SQL con `${...}` que no sea
//      una de estas ayudas (ver "no hay SQL con interpolación").

// Entero seguro para LIMIT/OFFSET: lanza si no es un entero no negativo.
function sqlInt(value, { min = 0, max = Number.MAX_SAFE_INTEGER } = {}) {
    const n = typeof value === 'string' && /^\d{1,15}$/.test(value) ? Number(value) : value;
    if (!Number.isSafeInteger(n) || n < min || n > max) {
        throw new RangeError('Entero SQL fuera de rango');
    }
    return String(n);
}

// "?, ?, ?" para un IN (...) con `count` valores
function sqlPlaceholders(count) {
    const n = Number(sqlInt(count, { min: 1, max: 1000 }));
    return Array(n).fill('?').join(', ');
}

module.exports = { sqlInt, sqlPlaceholders };
