const rateLimiter = require('../security/rate-limiter.service');
const events = require('../security/security-events.service');

// Limpieza periódica de las tablas de seguridad y de los archivos temporales de subida.
//
// Es MANTENIMIENTO, no estado de seguridad: si el proceso se reinicia o hay varias instancias haciéndolo
// a la vez no pasa nada (todos los DELETE son idempotentes y están acotados por LIMIT), y lo que
// protege —bloqueos, contadores, eventos— está en la base de datos, no aquí.

const INTERVAL_MS = (Number(process.env.HOUSEKEEPING_INTERVAL_MINUTES) || 10) * 60 * 1000;

class SecurityHousekeeping {
    constructor() {
        this.timer = null;
        this.running = false;
    }

    async runOnce() {
        if (this.running) return null;
        this.running = true;

        const result = {};
        const step = async (name, fn) => {
            try { result[name] = await fn(); } catch (error) { result[name] = `error: ${error.code || error.message}`; }
        };

        try {
            await step('rateLimitCounters', () => rateLimiter.purge());
            await step('securityEvents', () => events.purge());
            await step('authData', () => require('../security/secure-auth.service').purgeOldData());
            await step('ssoStates', () => require('../sso/oidc.service').purgeExpired());
            await step('samlCache', () => require('../sso/saml.service').purgeExpired());
            await step('webauthnChallenges', () => require('../security/webauthn.service').purgeExpired());
            await step('tempUploads', () => require('../files/storage').purgeStaleTemp());
            return result;
        } finally {
            this.running = false;
        }
    }

    start() {
        if (this.timer) return;
        this.timer = setInterval(() => { this.runOnce().catch(() => {}); }, INTERVAL_MS);
        this.timer.unref(); // no debe impedir que el proceso termine
    }

    stop() {
        if (this.timer) clearInterval(this.timer);
        this.timer = null;
    }
}

module.exports = new SecurityHousekeeping();
