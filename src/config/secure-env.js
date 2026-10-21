const fs = require('fs');
const path = require('path');
const dotenv = require('dotenv');
const keyProvider = require('../crypto/key-provider');
const kms = require('../crypto/kms');

// Variables que definen el material de claves: son las que cambian en una rotación.
const KEY_VARIABLES = ['BASE_SEED', 'ENCRYPTION_SEED', 'JWT_SEED', 'KEY_EPOCH'];

class SecureEnvironment {
    constructor() {
        // Valores del entorno guardados cifrados por un KMS (kms:...): se descifran AQUÍ, antes de derivar
        // ninguna clave. Si el KMS no responde esto lanza y el servidor no arranca (falla cerrado).
        const unwrapped = kms.resolveProcessEnv();
        if (unwrapped > 0) console.log(`🔑 ${unwrapped} secretos descifrados con el KMS`);

        this.loadRotatingSecrets();
        this.setupAutoRotation();
    }

    loadRotatingSecrets() {
        const keys = keyProvider.deriveFromEnv(process.env);

        this.mode = keys.mode;
        this.epoch = keys.epoch;
        this.fingerprint = keys.fingerprint;
        this.secrets = {
            jwt: keys.jwt,
            encryption: keys.encryption,
            session: keys.session,
            email: keys.email
        };

        console.log(`🔐 Secretos cargados (modo ${keys.mode}, época ${keys.epoch})`);
    }

    // Modo legacy: recalcular cada 24 h (las claves dependen de la fecha). En modo estable las
    // claves solo cambian al rotar, así que no hace falta ningún temporizador.
    setupAutoRotation() {
        if (this.mode !== 'legacy') return;

        const timer = setInterval(() => {
            this.loadRotatingSecrets();
            console.log('🔄 Secretos internos rotados automáticamente');
        }, 24 * 60 * 60 * 1000);
        timer.unref(); // no debe impedir que el proceso termine
    }

    // Relee las variables de claves desde el archivo .env (tras una rotación) y recalcula
    // los secretos sin reiniciar el proceso. Devuelve true si el archivo tenía cambios.
    reload(envFile = process.env.ENV_FILE || path.join(__dirname, '../../.env')) {
        const parsed = dotenv.parse(fs.readFileSync(envFile));
        let changed = false;

        for (const name of KEY_VARIABLES) {
            // El archivo puede traer valores envueltos por el KMS (la rotación los escribe así)
            const value = parsed[name] === undefined ? undefined : kms.resolveValue(name, parsed[name]);
            if (value !== undefined && value !== process.env[name]) {
                process.env[name] = value;
                changed = true;
            }
        }

        const before = this.fingerprint;
        this.loadRotatingSecrets();
        return changed || before !== this.fingerprint;
    }

    getSecret(type) {
        return this.secrets[type] || require('crypto').scryptSync(`fallback_${type}`, 'dynamic_salt', 32).toString('hex');
    }

    getKeyInfo() {
        return { mode: this.mode, epoch: this.epoch, fingerprint: this.fingerprint };
    }

    // Verificar si los secretos necesitan renovación (solo tiene sentido en modo legacy)
    needsRotation() {
        const lastRotation = this.lastRotationTime || Date.now();
        return this.mode === 'legacy' && (Date.now() - lastRotation) > (24 * 60 * 60 * 1000);
    }
}

module.exports = new SecureEnvironment();
module.exports.KEY_VARIABLES = KEY_VARIABLES;
