// Detección de capacidad del equipo y presupuesto de "media máquina".
//
// Al arrancar, el servidor mira cuántos núcleos y cuánta RAM tiene el equipo y
// se reserva SÓLO LA MITAD. A partir de ese presupuesto se derivan los límites
// que el proceso puede controlar en caliente:
//
//   - connectionLimit del pool MySQL
//   - UV_THREADPOOL_SIZE (hilos de libuv para crypto/fs/DNS)
//   - trabajadores sugeridos para tareas en paralelo (lo usa la API de estrés)
//   - memoria recomendada para --max-old-space-size (la imprime; el flag se
//     aplica al lanzar node, p. ej. desde el instalador)
//
// Se puede forzar todo con CAPACITY_FRACTION (por defecto 0.5).

const os = require('os');

function clampInt(n, min, max) {
    return Math.max(min, Math.min(max, Math.floor(n)));
}

function compute() {
    const fraction = (() => {
        const f = parseFloat(process.env.CAPACITY_FRACTION);
        return Number.isFinite(f) && f > 0 && f <= 1 ? f : 0.5;
    })();

    const totalCores = os.cpus().length || 1;
    const totalMemBytes = os.totalmem();
    const totalMemMB = Math.floor(totalMemBytes / (1024 * 1024));

    // Núcleos a usar: la fracción pedida, mínimo 1.
    const cpuBudget = clampInt(totalCores * fraction, 1, totalCores);

    // Memoria a usar: la fracción pedida.
    const memBudgetMB = clampInt(totalMemMB * fraction, 64, totalMemMB);

    // Pool de BD: el trabajo de BD es de E/S, así que se permiten algo más de
    // conexiones que núcleos, pero acotado para no saturar el servidor MySQL.
    const dbPool = clampInt(cpuBudget * 4, 2, 50);

    // Hilos de libuv (crypto/fs): la mitad de los núcleos, acotado al rango válido.
    const threadPool = clampInt(cpuBudget, 1, 128);

    return {
        fraction,
        total: { cores: totalCores, memMB: totalMemMB },
        budget: { cores: cpuBudget, memMB: memBudgetMB },
        dbPool,
        threadPool,
        // Trabajadores para cargas en paralelo (CPU-bound).
        workers: cpuBudget,
        // Recomendación para el heap de V8 (no se puede fijar en caliente).
        recommendedMaxOldSpaceMB: memBudgetMB
    };
}

const capacity = compute();

// Fijar UV_THREADPOOL_SIZE lo antes posible (debe estar puesto ANTES del primer
// uso del threadpool de libuv). Si ya venía definido por el entorno, se respeta.
if (!process.env.UV_THREADPOOL_SIZE) {
    process.env.UV_THREADPOOL_SIZE = String(capacity.threadPool);
}

function summaryLines() {
    return [
        `🧮 Capacidad del equipo: ${capacity.total.cores} núcleos, ${capacity.total.memMB} MB RAM`,
        `⚖️  Presupuesto (${Math.round(capacity.fraction * 100)}% del equipo): ${capacity.budget.cores} núcleos, ${capacity.budget.memMB} MB RAM`,
        `   ↳ Pool MySQL: ${capacity.dbPool} · UV_THREADPOOL_SIZE: ${process.env.UV_THREADPOOL_SIZE} · trabajadores: ${capacity.workers}`,
        `   ↳ Heap V8 recomendado: node --max-old-space-size=${capacity.recommendedMaxOldSpaceMB}`
    ];
}

function logSummary() {
    summaryLines().forEach(line => console.log(line));
}

module.exports = { ...capacity, summaryLines, logSummary };
