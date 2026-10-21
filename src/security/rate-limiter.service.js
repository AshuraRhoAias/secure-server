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
// Coste: dos sentencias por comprobación sobre una clave primaria (sin escaneos).

class RateLimiter {
    async hit(scope, subject, windowSec) {
        const windowSeconds = Number(sqlInt(windowSec, { min: 1, max: 86400 }));
        const nowSec = Math.floor(Date.now() / 1000);
        const windowStart = nowSec - (nowSec % windowSeconds);
        const previousStart = windowStart - windowSeconds;

        return db.withConnection(async (conn) => {
            await conn.query(
                `INSERT INTO rate_limit_counters (scope, subject, window_start, hits) VALUES (?, ?, ?, 1)
                 ON DUPLICATE KEY UPDATE hits = hits + 1`,
                [scope, subject, windowStart]
            );
            const [rows] = await conn.query(
                'SELECT window_start, hits FROM rate_limit_counters WHERE scope = ? AND subject = ? AND window_start IN (?, ?)',
                [scope, subject, windowStart, previousStart]
            );

            const current = rows.find(r => Number(r.window_start) === windowStart)?.hits || 0;
            const previous = rows.find(r => Number(r.window_start) === previousStart)?.hits || 0;
            const elapsed = (nowSec - windowStart) / windowSeconds;
            const count = Math.ceil(current + previous * (1 - elapsed));

            return { count, current, windowStart, retryAfter: windowStart + windowSeconds - nowSec };
        });
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
