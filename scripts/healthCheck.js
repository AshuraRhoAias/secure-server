#!/usr/bin/env node
// Comprobación de salud REAL (sustituye al antiguo `health-check`, que imprimía "Sistema funcionando" sin mirar nada).
//
//   npm run health-check                     → GET http://127.0.0.1:$PORT/health/ready
//   HEALTH_URL=https://api.ejemplo.com/health/ready npm run health-check
//
// Sale con 0 solo si la instancia responde 200 en /health/ready (BD alcanzable, no en mantenimiento ni cerrándose).
// Lo usa el HEALTHCHECK de la imagen Docker y sirve para sondas de systemd/cron. No lee el .env ni secretos.

const port = Number(process.env.PORT) || 3000;
const url = process.env.HEALTH_URL || `http://127.0.0.1:${port}/health/ready`;
const timeoutMs = Number(process.env.HEALTH_TIMEOUT_MS) || 3000;

async function main() {
    try {
        const res = await fetch(url, { signal: AbortSignal.timeout(timeoutMs), headers: { Accept: 'application/json' } });
        if (res.status === 200) {
            console.log(`✅ ${url} → 200`);
            return 0;
        }
        let code = '';
        try { code = (await res.json()).code || ''; } catch { /* cuerpo no JSON */ }
        console.error(`❌ ${url} → ${res.status}${code ? ` (${code})` : ''}`);
        return 1;
    } catch (error) {
        console.error(`❌ ${url} → sin respuesta (${error.name === 'TimeoutError' ? `más de ${timeoutMs} ms` : error.code || error.message})`);
        return 1;
    }
}

main().then(code => process.exit(code));
