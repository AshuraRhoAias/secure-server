// Fachada de compatibilidad. La rotación real vive en src/maintenance/rotation.service.js
// (re-cifrado transaccional, backup, modo mantenimiento). La versión anterior de este archivo
// generaba claves que nunca se usaban, no re-cifraba ningún dato y dejó de funcionar en Node 22
// (crypto.createCipher ya no existe).

class KeyRotator {
    constructor() {
        this.rotationInProgress = false;
    }

    // Rotación dentro del propio servidor (la usa el planificador mensual): el servidor se pone en
    // mantenimiento, rota, recarga las claves en memoria y se reabre. Requiere que las claves
    // vivan en un archivo .env escribible; si están en el panel del hosting, usa el CLI con
    // `--no-write-env` (npm run rotate-keys).
    async rotateKeys(options = {}) {
        if (this.rotationInProgress) {
            throw new Error('Ya hay una rotación de claves en progreso');
        }

        const { guard, getRotationService } = require('../maintenance');
        const secureEnv = require('../config/secure-env');

        try {
            this.rotationInProgress = true;
            return await getRotationService().run({
                trigger: 'in-process',
                writeEnv: true,
                keepBackups: Number(process.env.BACKUP_RETENTION) || 0,
                ...options,
                reloadInProcess: async () => { secureEnv.reload(); },
                hooks: { afterLock: () => guard.tick() }
            });
        } finally {
            this.rotationInProgress = false;
            await guard.tick().catch(() => {});
        }
    }
}

module.exports = new KeyRotator();
