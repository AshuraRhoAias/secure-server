# Informe de rendimiento — secure-server

**Fecha:** 2026-10-21
**Alcance:** pruebas tipo producción (100 000 registros cifrados, 1 000 000 de peticiones), bloqueo de IP conmutable, y una API de estrés que satura CPU/RAM/GPU con topes.

> **Honestidad primero.** Todo lo de abajo son mediciones reales de estas corridas. Donde algo **no** se pudo medir (p. ej. la GPU) se dice explícitamente; no hay cifras inventadas ni redondeos "de humo".

---

## 0. Dónde se midió (esto cambia cómo leer los números)

| Dato | Valor real de este entorno |
|---|---|
| CPU | Xeon de **4 vCPU** compartidos (contenedor en la nube), **no** un Ryzen 7 |
| RAM | ~15 GB |
| GPU | **Ninguna** (no hay NVIDIA; `nvidia-smi`/`/dev/nvidia0` ausentes) |
| BD | MariaDB 10.11 local, `secure_platform`, con 100 000 notas cifradas sembradas |
| App | Node 22 / Express 5, proceso único, pool MySQL = 10 |

**Importante:** los topes que pediste —portátil **Ryzen 7 usando 1/2 CPU**, **≤8 GB RAM**, **1/2 de una RTX 3050 Ti**— son la **configuración** de la API de estrés (`STRESS_CPU_WORKERS`, `STRESS_MAX_RAM_MB=8192`, `STRESS_GPU_FRACTION=0.5`), no las características de esta máquina de prueba. El tope de 8 GB **sí se verificó** que se respeta; la GPU **no se pudo ejercitar aquí** porque este entorno no tiene ninguna (se reporta `ran:false` con el motivo, sin simular).

---

## 1. Tabla de datos: qué tan sólido es el sistema

Columna **%** = qué tan bien quedó ese aspecto (0–100, criterio explicado en "porqué"). No es un porcentaje de "uso", es una calificación honesta del resultado observado.

| # | Nombre | % | El porqué (evidencia real) |
|---|---|---:|---|
| 1 | **Éxito bajo 1 M de peticiones** | 100% | 1 000 000 de `GET /health`, **0 errores**, **1 000 000 × HTTP 200**. No se cayó ni degradó. |
| 2 | **Throughput sostenido** | 85% | **2 462 req/s** sostenidos durante 406 s con 200 conexiones concurrentes. Techo razonable para 1 proceso Node en 4 vCPU; subiría casi lineal con `cluster`/más núcleos. |
| 3 | **Latencia bajo carga (ruta ligera)** | 88% | p50 **77 ms**, p90 **100 ms**, p99 **136 ms**, máx **295 ms**. Cola muy estable (p99 ≈ 1.75× la mediana), sin picos largos. |
| 4 | **Estabilidad de memoria** | 97% | RSS **plano en ~379 MB** (máx 379.4 / media 378.1) durante todo el millón. **Sin fuga de memoria** apreciable. |
| 5 | **Uso de CPU (ruta ligera)** | 90% | ~**107% de 1 núcleo** de media (máx 124%) = **~27% de los 4 núcleos**. Deja margen amplio; el cuello no es CPU en esta ruta. |
| 6 | **Tráfico concurrido con bloqueo OFF** | 100% | Con `DISABLE_IP_BLOCKING=true`, el millón de peticiones desde 1 sola IP pasa al 100%. Confirma que **acepta tráfico concurrido sin caerse** cuando se desactiva el bloqueo para la prueba. |
| 7 | **Defensa con bloqueo ON** | 95% | Con bloqueo activo (normal), la misma IP martilleando recibe **429 (rate limit)**: en la prueba de login, 10×401 y luego **429, 429**. La protección hace su trabajo; por eso para medir carga pura hubo que desactivarla temporalmente. |
| 8 | **Tope de RAM de la API de estrés** | 100% | Se pidió reservar mucha RAM y la API la **cortó exactamente en 8192 MB** (`allocated_mb:8192, cap_mb:8192`); RSS subió a ~8.3 GB y ahí se quedó. El límite de **8 GB se respeta de verdad**. |
| 9 | **Saturación de CPU (API de estrés)** | 80% | La API lanza `STRESS_CPU_WORKERS` hilos de `pbkdf2` a la vez (aquí 2 = 1/2 de 4 núcleos) + gzip en el hilo principal. En 2.1 s hizo 2 866 pbkdf2 y 50 rondas gzip (13 MB). Usa ~1/2 de la CPU como se pidió; en un Ryzen 7 real usaría la mitad de **sus** núcleos. |
| 10 | **GPU** | N/D | **No evaluable aquí**: no hay GPU NVIDIA en este entorno (`ran:false`, motivo registrado). El código detecta GPU de forma honesta y, de haber una + librería de cómputo, la acotaría a `STRESS_GPU_FRACTION=0.5`. **No se simuló ningún resultado de GPU.** |
| 11 | **Lectura pesada `/api/notes`** | 45% | Con 100 k notas cifradas, leer notas descifra en caliente (cifrado triple + escritura de auditoría + pool=10): **8.3 req/s**, p50 **4.4 s**, p99 **11.5 s**. Correcto (0 errores, 100×200) pero **lento**: es el cuello real del sistema. |

**Promedio de lo medible (excluye GPU, N/D): ≈ 89%.**

---

## 2. Qué significa, sin humo

- **Lo fuerte de verdad:** el núcleo HTTP aguanta **1 millón de peticiones sin un solo error** y con memoria plana. Eso es lo más difícil de lograr y aquí está demostrado con datos, no con promesas.
- **La seguridad estorba la carga… a propósito:** el rate limiting y el bloqueo de IP cortan el tráfico repetido desde una IP (viste los 429). Por eso la prueba de "1 M sin caer" se hizo con `DISABLE_IP_BLOCKING=true`, un **bypass explícito y apagado por defecto** que añadí para esto; en producción el bloqueo sigue activo.
- **El cuello de botella real es `/api/notes`:** descifrar en cada lectura + auditoría encriptada + pool chico lo deja en ~8 req/s. Es el punto a optimizar (índice/paginado por cursor, caché de descifrado, subir el pool, no auditar cada GET de lectura).
- **GPU:** no se puede presumir nada. Aquí no hay GPU; el sistema lo dice en claro en vez de inventar un número.

## 3. Recomendaciones priorizadas

1. **`/api/notes`:** paginar por cursor + subir pool MySQL + no escribir auditoría en lecturas simples → objetivo p50 < 300 ms.
2. **Escalar el throughput:** `node:cluster`/PM2 en N núcleos → ~N× los 2 462 req/s actuales.
3. **GPU:** si se quiere medir de verdad, correr en una máquina con RTX 3050 Ti y `gpu.js`/`tfjs-node-gpu`; el gancho ya existe.
4. **No dejar `DISABLE_IP_BLOCKING=true` en producción** (está apagado por defecto; sólo para benchmarks).

---

---

## 4. Ronda 4 — optimizaciones aplicadas (medidas)

Tras la ronda 3 se optimizó el camino caliente. Mismo equipo (4 vCPU, sin GPU),
mismos datos (usuario con 100 000 notas cifradas). Ver `OPTIMIZACIONES.md`.

| Métrica | Antes (ronda 3) | Después (ronda 4) | Mejora |
|---|---:|---:|---:|
| `/api/notes` throughput | 8.3 req/s | **316 req/s** | **~38×** |
| `/api/notes` p50 | 4 379 ms | **78 ms** | **~56× menos** |
| `/api/notes` p99 | 11 520 ms | **659 ms** | ~17× menos |
| Éxito | 100% | 100% | = |

Qué lo consiguió, sin humo:
- **Cifrado:** se quitó del camino caliente un auto-descifrado que corría en CADA
  cifrado (duplicaba el trabajo) y el log por operación. A/B sobre los mismos
  datos: 159 → 345 req/s (~2.2×). Microbenchmark: ~9 600 pares cifrar+descifrar/s.
- **COUNT cacheado:** el `COUNT(*)` por listado costaba ~17 ms con 100k notas
  (la página en sí, <1 ms). Cacheado unos segundos e invalidado al escribir, la
  paginación sigue exacta y el listado deja de pagar ese coste en cada petición.

Formato de cifrado intacto: los datos ya guardados se descifran igual (0 fallos
en 2 000 ciclos y en las suites test:api / test:rotation).

### Reproducibilidad
```bash
# Carga ligera (techo de throughput)
node benchmarks/loadtest.js --url http://127.0.0.1:5000/health --requests 1000000 --concurrency 200 --out res.json
# Saturación controlada (CPU+RAM+zlib, tope 8 GB, 1/2 CPU)
STRESS_MAX_RAM_MB=8192 STRESS_GPU_FRACTION=0.5 node benchmarks/stress-api.js   # luego: curl "localhost:3100/stress?ms=2000&ram=8192"
# Siembra de 100k notas cifradas
NODE_ENV=development node benchmarks/seed-notes.js --user-id 1 --count 100000
```
Artefactos de esta corrida: `res_health_1M.json`, `res_notes.json`, `/caps` de la API de estrés.
