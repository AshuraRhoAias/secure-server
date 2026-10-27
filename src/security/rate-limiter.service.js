const db = require('../config/database');
const { sqlInt } = require('../config/sql');

// Limitador de peticiones con estado en MySQL (tabla rate_limit_counters), no en memoria.
//
// - Es ATÓMICO entre procesos y servidores: dos instancias contando a la vez suman en la misma fila
//   (INSERT ... ON DUPLICATE KEY UPDATE hits = hits + 1).
// - Sobrevive a reinicios.
// - Ventana deslizante aproximada: se pondera la ventana anterior según lo que falta de la actual.
//   Así no se puede duplicar el límite disparando una ráfaga justo en el cambio de ventana.
//
// Coste: UNA sentencia por comprobación (sobre la clave primaria). Truco: `hits = LAST_INSERT_ID(hits + 1)` hace que MariaDB
// devuelva en `insertId` el contador ya incrementado de la ventana actual, sin una lectura aparte. La ventana ANTERIOR ya está
// cerrada y no cambia (salvo escrituras rezagadas de otra instancia con el reloj algo atrasado), así que se lee una vez por
// (sujeto, ventana) y se recuerda en memoria: es una caché de un valor casi inmutable, no estado de seguridad.

const PREVIOUS_CACHE_MAX = 50_000;
const previousCache = new Map(); // "scope\0subject\0windowStart" -> hits de esa ventana (ya cerrada)

function remember(key, hits) {
    if (previousCache.size >= PREVIOUS_CACHE_MAX) previousCache.clear(); // simple y acotado; se vuelve a llenar sola
    previousCache.set(key, hits);
}

class RateLimiter {
    async hit(scope, subject, windowSec) {
        const windowSeconds = Number(sqlInt(windowSec, { min: 1, max: 86400 }));
        const nowSec = Math.floor(Date.now() / 1000);
        const windowStart = nowSec - (nowSec % windowSeconds);
        const previousStart = windowStart - windowSeconds;
        const previousKey = `${scope}\0${subject}\0${previousStart}`;

        const [result] = await db.query(
            `INSERT INTO rate_limit_counters (scope, subject, window_start, hits) VALUES (?, ?, ?, 1)
             ON DUPLICATE KEY UPDATE hits = LAST_INSERT_ID(hits + 1)`,
            [scope, subject, windowStart]
        );
        const current = Number(result.insertId) > 0 ? Number(result.insertId) : 1; // 0 = fila nueva = primer golpe

        let previous = previousCache.get(previousKey);
        if (previous === undefined) {
            const [rows] = await db.query(
                'SELECT hits FROM rate_limit_counters WHERE scope = ? AND subject = ? AND window_start = ?',
                [scope, subject, previousStart]
            );
            previous = rows[0] ? Number(rows[0].hits) : 0;
            remember(previousKey, previous);
        }

        const elapsed = (nowSec - windowStart) / windowSeconds;
        const count = Math.ceil(current + previous * (1 - elapsed));

        return { count, current, windowStart, retryAfter: windowStart + windowSeconds - nowSec };
    }

    // Borra contadores de ventanas ya irrelevantes
    async purge(olderThanSec = 86400) {
        const cutoff = Math.floor(Date.now() / 1000) - Number(sqlInt(olderThanSec, { min: 60 }));
        const [result] = await db.query('DELETE FROM rate_limit_counters WHERE window_start < ? LIMIT 10000', [cutoff]);
        return result.affectedRows;
    }

    async stats() {
        const recent = Math.floor(Date.now() / 1000) - 120;
        const [[row]] = await db.query(
            'SELECT COUNT(*) AS tracked, SUM(window_start >= ?) AS active FROM rate_limit_counters', [recent]);
        return { trackedRateLimitEntries: Number(row.tracked) || 0, activeRateLimitWindows: Number(row.active) || 0 };
    }
}

module.exports = new RateLimiter();
