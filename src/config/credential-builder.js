const crypto = require('crypto');

class CredentialBuilder {
    constructor() {
        this.secureEnv = require('./secure-env');
    }

    getEnvVariable(key) {
        const value = process.env[key];
        if (!value) {
            console.error(`❌ Variable de entorno faltante o vacía: ${key}`);
        } else {
            console.log(`✅ Variable de entorno encontrada: ${key} = ${value}`);
        }
        return value || null;
    }

    buildDatabaseURL() {
        try {
            // Extraer fragmentos uno a uno usando getEnvVariable
            const fragment1 = this.getEnvVariable('DB_FRAGMENT_1');
            const fragment2 = this.getEnvVariable('DB_FRAGMENT_2');
            const fragment3 = this.getEnvVariable('DB_FRAGMENT_3');

            if (!fragment1 || !fragment2 || !fragment3) {
                throw new Error('Fragmentos de DB incompletos');
            }

            return fragment1 + fragment2 + fragment3;
        } catch (error) {
            console.error('❌ Error construyendo URL de base de datos:', error);
            throw error;
        }
    }

    buildEmailCredentials(channel = 'primary') {
        try {
            const userEnvVar = channel === 'primary' ? 'PRIMARY_EMAIL_USER' : 'BACKUP_EMAIL_USER';
            const domainEnvVar = channel === 'primary' ? 'EMAIL_DOMAIN_1' : 'EMAIL_DOMAIN_2';
            const passwordEnvVar = channel === 'primary' ? 'PRIMARY_EMAIL_PASSWORD' : 'BACKUP_EMAIL_PASSWORD';

            const user = this.getEnvVariable(userEnvVar);
            const domain = this.getEnvVariable(domainEnvVar);
            const password = this.getEnvVariable(passwordEnvVar);

            if (!user || !domain) {
                throw new Error(`Credenciales de email ${channel} incompletas`);
            }

            return {
                user: `${user}@${domain}`,
                pass: password || this.generateEmailPassword(channel), // Usar contraseña real o generar una
                service: domain.includes('gmail') ? 'gmail' : 'smtp'
            };
        } catch (error) {
            console.error(`❌ Error construyendo credenciales de ${channel}:`, error);
            throw error;
        }
    }

    generateEmailPassword(channel) {
        const date = new Date();
        const seed = this.getEnvVariable('BASE_SEED') || 'default';
        const emailSeed = this.getEnvVariable('EMAIL_SEED') || 'email_default';
        const pattern = `${seed}_${emailSeed}_${channel}_${date.getMonth()}_${date.getFullYear()}`;

        return crypto.scryptSync(pattern, 'email_salt', 16).toString('hex');
    }

    buildTelegramCredentials() {
        return {
            botToken: this.getEnvVariable('TELEGRAM_BOT_TOKEN'),
            chatId: this.getEnvVariable('TELEGRAM_CHAT_ID')
        };
    }

    generateJWTSecret() {
        const jwtSeed = this.getEnvVariable('JWT_SEED') || 'jwt_default';
        const baseSeed = this.getEnvVariable('BASE_SEED') || 'default';
        const today = new Date().toISOString().split('T')[0];

        return crypto.scryptSync(`${baseSeed}_${jwtSeed}_${today}`, 'jwt_salt', 64).toString('hex');
    }

    validateCredentials() {
        const required = [
            'BASE_SEED',
            'DB_FRAGMENT_1',
            'DB_FRAGMENT_2',
            'DB_FRAGMENT_3'
        ];

        // Solo validar email si las variables están presentes
        const primaryEmailUser = this.getEnvVariable('PRIMARY_EMAIL_USER');
        const emailDomain = this.getEnvVariable('EMAIL_DOMAIN_1');

        if (primaryEmailUser && emailDomain) {
            required.push('PRIMARY_EMAIL_USER', 'EMAIL_DOMAIN_1');
        }

        const missing = [];

        required.forEach(key => {
            if (!process.env[key]) {
                missing.push(key);
            }
        });

        if (missing.length > 0) {
            throw new Error(`Variables de entorno faltantes: ${missing.join(', ')}`);
        }

        console.log('✅ Validación de credenciales completada');
        return true;
    }
}

module.exports = new CredentialBuilder();