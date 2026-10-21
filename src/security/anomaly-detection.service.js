const db = require('../config/database');
const rateLimiter = require('./rate-limiter.service');
const events = require('./security-events.service');
const { ipSubject, isNeverBlocked } = require('./ip');

// Bloqueo de IPs y reacción a comportamiento abusivo, con TODO el estado en MySQL
// (tablas blocked_ips, rate_limit_counters y security_events). Nada vive en memoria del proceso:
// un reinicio no libera a un atacante y varias instancias comparten el mismo veredicto.
//
// Esta versión sustituye a la anterior, que guardaba historiales por IP en Map/Set. Se eliminaron
// dos detectores que no tenían sentido por petición (cambio de país y de navegador "por IP": una
// misma IP no cambia de país). Sus equivalentes con sentido —nuevo país, nuevo dispositivo y viaje
// imposible POR USUARIO— están en el login (secure-auth.service.js) y también acaban en security_events.

const HOUR = 3600;

class AnomalyDetection {
    // ¿Está bloqueada? (IPv6 se agrupa por /64)
    async isIPBlocked(ip) {
        const [rows] = await db.query(
            'SELECT 1 AS blocked FROM blocked_ips WHERE ip_address = ? AND blocked_until > NOW() LIMIT 1',
            [ipSubject(ip)]
        );
        return rows.length > 0;
    }

    // Bloqueo PROGRESIVO: 1 h la primera vez, 2 h la segunda, 4 h... hasta 7 días.
    // Nunca se bloquea el loopback ni lo listado en PROTECTION_ALLOWLIST (un proxy mal configurado
    // haría que todas las peticiones parezcan de una IP y se bloquearía a todo el mundo).
    async blockIP(ip, reason, { baseSeconds = HOUR, maxSeconds = 7 * 24 * HOUR } = {}) {
        const subject = ipSubject(ip);
        if (subject === 'unknown' || isNeverBlocked(ip)) {
            await events.record({ type: 'BLOCK_SKIPPED', rule: String(reason).slice(0, 64), severity: 'info', ip });
            return false;
        }

        try {
            await db.query(
                `INSERT INTO blocked_ips (ip_address, reason, blocked_until, block_count)
                 VALUES (?, ?, DATE_ADD(NOW(), INTERVAL ? SECOND), 1)
                 ON DUPLICATE KEY UPDATE
                    reason = ?,
                    blocked_until = DATE_ADD(NOW(), INTERVAL LEAST(? * POW(2, LEAST(block_count, 10)), ?) SECOND),
                    block_count = block_count + 1`,
                [subject, String(reason).slice(0, 500), baseSeconds, String(reason).slice(0, 500), baseSeconds, maxSeconds]
            );

            await events.record({
                type: 'IP_BLOCKED', rule: String(reason).slice(0, 64), severity: 'high', riskScore: 80,
                action: 'blocked_ip', ip
            });
            return true;
        } catch (error) {
            console.error('❌ Error bloqueando IP:', error.code || error.message);
            return false;
        }
    }

    async unblockIP(ip) {
        try {
            await db.query('DELETE FROM blocked_ips WHERE ip_address = ?', [ipSubject(ip)]);
            return true;
        } catch (error) {
            console.error('❌ Error desbloqueando IP:', error.code || error.message);
            return false;
        }
    }

    // Un "strike" es un mal comportamiento puntual (inyección rechazada, ruta de escáner...).
    // Varios en 10 minutos desde el mismo origen → bloqueo automático.
    async strike(ip, kind, { threshold, windowSec = 600, blockSeconds = HOUR } = {}) {
        const subject = ipSubject(ip);
        const { count } = await rateLimiter.hit(`strike:${kind}`.slice(0, 24), subject, windowSec);
        if (count >= threshold) {
            const blocked = await this.blockIP(ip, kind, { baseSeconds: blockSeconds });
            return { count, blocked };
        }
        return { count, blocked: false };
    }

    async getStats() {
        const [[blocked]] = await db.query('SELECT COUNT(*) AS active FROM blocked_ips WHERE blocked_until > NOW()');
        const [[events24h]] = await db.query(
            "SELECT COUNT(*) AS total, SUM(severity IN ('high','critical')) AS serious FROM security_events WHERE created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)");
        return {
            storage: 'mysql',
            blockedIPs: Number(blocked.active) || 0,
            events24h: Number(events24h.total) || 0,
            seriousEvents24h: Number(events24h.serious) || 0,
            uptime: process.uptime()
        };
    }
}

module.exports = new AnomalyDetection();
