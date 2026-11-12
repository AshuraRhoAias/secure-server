// Mantenimiento = sin entradas ni salidas. Las peticiones NUEVAS ya reciben 503 del guardián (guard.middleware()); esto corta lo
// que sigue abierto cuando el servidor pasa de abierto a cerrado:
//   - los streams en vivo (SSE), al momento: dejan de enviar datos y el navegador reconecta cuando se reabre;
//   - las conexiones inactivas (keep-alive), al momento;
//   - cualquier otra conexión (descargas o subidas largas), tras `cutMs`. Por defecto 4 s: menos que los 10 s de vaciado que
//     espera la rotación antes de copiar y re-cifrar, así que cuando empieza no queda nada leyendo ni escribiendo.
// Devuelve la función para desactivarlo.
function cutOffOnMaintenance({ guard, getServer, liveStream, cutMs = Number(process.env.MAINTENANCE_CUT_MS) || 4000, log = console }) {
    let timer = null;
    return guard.onStateChange((state, previous) => {
        const wasOpen = !previous.maintenance && !previous.outOfSync;
        if (!wasOpen || guard.isOpen()) return;
        log.log?.('🔒 Mantenimiento: se cierran los streams y las conexiones abiertas');
        liveStream?.closeAll('MAINTENANCE');
        getServer()?.closeIdleConnections?.();
        clearTimeout(timer);
        timer = setTimeout(() => {
            if (!guard.isOpen()) getServer()?.closeAllConnections?.();
        }, cutMs);
        timer.unref?.();
    });
}

module.exports = { cutOffOnMaintenance };
