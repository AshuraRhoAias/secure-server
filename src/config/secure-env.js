const crypto = require('crypto');

class SecureEnvironment {
    constructor() {
        this.loadRotatingSecrets();
        this.setupAutoRotation();
    }

    loadRotatingSecrets() {
        // Generar secretos basados en fecha + semilla
        const today = new Date().toISOString().split('T')[0]; // YYYY-MM-DD
        const baseSeed = process.env.BASE_SEED || 'default_seed_change_this';

        this.secrets = {
            jwt: this.generateTimeBasedSecret(baseSeed + '_jwt_' + today),
            encryption: this.generateTimeBasedSecret(baseSeed + '_enc_' + today),
            session: this.generateTimeBasedSecret(baseSeed + '_sess_' + today),
            email: this.generateTimeBasedSecret(baseSeed + '_email_' + today)
        };

        console.log('🔐 Secretos dinámicos cargados para:', today);
    }

    generateTimeBasedSecret(input) {
        return crypto.scryptSync(input, 'dynamic_salt', 32).toString('hex');
    }

    // Auto-rotación cada 24 horas
    setupAutoRotation() {
        setInterval(() => {
            this.loadRotatingSecrets();
            console.log('🔄 Secretos internos rotados automáticamente');
        }, 24 * 60 * 60 * 1000); // 24 horas
    }

    getSecret(type) {
        return this.secrets[type] || this.generateTimeBasedSecret(`fallback_${type}`);
    }

    // Verificar si los secretos necesitan renovación
    needsRotation() {
        const lastRotation = this.lastRotationTime || Date.now();
        const timeSinceRotation = Date.now() - lastRotation;
        return timeSinceRotation > (24 * 60 * 60 * 1000); // 24 horas
    }
}

module.exports = new SecureEnvironment();