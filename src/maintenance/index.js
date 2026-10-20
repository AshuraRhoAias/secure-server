// Puntos de acceso compartidos (singletons perezosos): el servidor, el planificador y los scripts
// usan el mismo guardián y el mismo servicio de rotación.

let guard = null;
let rotationService = null;

module.exports = {
    get guard() {
        if (!guard) {
            const { MaintenanceGuard } = require('./guard');
            guard = new MaintenanceGuard();
        }
        return guard;
    },

    getRotationService() {
        if (!rotationService) {
            const { RotationService } = require('./rotation.service');
            rotationService = new RotationService({
                db: require('../config/database'),
                encryptor: require('../crypto/tripleEncryptor')
            });
        }
        return rotationService;
    }
};
