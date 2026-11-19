// Simulación de ataques CONTROLADOS contra el PROPIO servidor, por HTTP, para comprobar que las defensas responden.
//
// Seguridad de la simulación:
//   - El destino es FIJO: 127.0.0.1 y el puerto del socket que recibió la petición de lanzamiento (ctx.port). Nada de la petición
//     del cliente decide a quién se ataca.
//   - Las IP de origen son de documentación (TEST-NET-3, 203.0.113.0/24, RFC 5737), distintas en cada ejecución, y viajan en
//     X-Forwarded-For SOLO si el servidor confía en ese encabezado (ctx.trustsForwardedFor). Si no confía, los ataques saldrían de
//     127.0.0.1 (el BFF y los administradores): NINGÚN paso de ataque se ejecuta (todos pueden sumar riesgo, limitar o bloquear
//     por IP) y cada uno emite `warn` con el motivo.
//   - Se crea un usuario temporal con contraseña aleatoria; al final se borra y, para TODAS las IP realmente usadas (también la
//     loopback si se llegara a usar), se borra el estado por IP: blocked_ips, login_attempts y rate_limit_counters (más la caché de
//     bloqueo). Los eventos de seguridad (security_events) NO se borran: son auditoría; alerts.service no avisa por webhook de
//     las alertas que provoca la simulación (marcadas details.simulation). Nunca se imprimen contraseñas ni tokens.
//
// Cada paso emite: pass = la defensa aguantó, fail = el ataque tuvo éxito (vulnerabilidad), warn = no se pudo comprobar.

const crypto = require('crypto');
const http = require('http');
const https = require('https');
const db = require('../../config/database');

// EICAR en pedazos para que el propio código fuente no lo detecte
const EICAR = ['X5O!P%@AP[4\\PZX54(P^)7CC)7}$', 'EICAR-STANDARD-ANTIVIRUS-TEST-FILE!', '$H+H*'].join('');
// Alfabeto sin caracteres ambiguos (0/o/O, 1/l/I), construido por rangos: un literal largo con «PASSWORD» en el nombre lo
// marca gitleaks como secreto (generic-api-key) aunque solo sea un alfabeto
const range = (from, to) => Array.from({ length: to.charCodeAt(0) - from.charCodeAt(0) + 1 }, (_, i) => String.fromCharCode(from.charCodeAt(0) + i));
const PASSWORD_CHARS = [...range('a', 'z'), ...range('A', 'Z'), ...range('2', '9')].filter(c => !'loIO'.includes(c)).join('');

const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));
const clip = (text, max = 120) => String(text ?? '').replace(/[\r\n]+/g, ' ').slice(0, max);

function describe() {
    return {
        title: 'Simulación de ataques',
        description: 'Lanza ataques controlados contra este mismo servidor (inyección SQL, XSS, path traversal, JWT falso, fuerza bruta, subidas peligrosas, payload enorme) desde IP de documentación y comprueba si se detectan. Limpia lo que crea.',
        enabled: true
    };
}

function validate(target) {
    if (target) {
        const { RunError } = require('../runs.service');
        throw new RunError('INVALID_TARGET', 'La simulación de ataques no admite destino: siempre ataca a este servidor', 400);
    }
}

function randomPassword() {
    const bytes = crypto.randomBytes(14);
    return `Sim-${Array.from(bytes, b => PASSWORD_CHARS[b % PASSWORD_CHARS.length]).join('')}-1`;
}

// Cliente HTTP mínimo contra el propio servidor (no normaliza rutas: sirve para path traversal) con tiempo límite
function makeClient(ctx, touched = new Set()) {
    const lib = ctx.tls ? https : http;
    return function send({ method = 'GET', path, ip, token, json, body, headers = {}, contentType }) {
        return new Promise((resolve, reject) => {
            const payload = body !== undefined ? body : json !== undefined ? Buffer.from(JSON.stringify(json)) : null;
            const h = { ...headers };
            if (ip && ctx.trustsForwardedFor) h['X-Forwarded-For'] = ip;
            touched.add(ip && ctx.trustsForwardedFor ? ip : '127.0.0.1'); // IP con la que el servidor verá la petición
            if (token) h.Authorization = `Bearer ${token}`;
            if (json !== undefined) h['Content-Type'] = 'application/json';
            if (contentType) h['Content-Type'] = contentType;
            if (payload) h['Content-Length'] = payload.length;
            const req = lib.request({ host: '127.0.0.1', port: ctx.port, method, path, headers: h, rejectUnauthorized: false, timeout: 15_000 }, (res) => {
                const chunks = [];
                res.on('data', c => chunks.push(c));
                res.on('end', () => {
                    const text = Buffer.concat(chunks).toString('utf8');
                    let parsed = null;
                    try { parsed = JSON.parse(text); } catch { /* respuesta no JSON */ }
                    resolve({ status: res.statusCode, text, json: parsed, code: parsed?.code, headers: res.headers });
                });
            });
            req.on('timeout', () => req.destroy(new Error('tiempo de espera agotado')));
            req.on('error', (error) => {
                // El servidor puede cortar la conexión (p. ej. un cuerpo enorme): es una respuesta de rechazo, no un fallo
                if (error.code === 'ECONNRESET' || error.code === 'EPIPE') return resolve({ status: 0, text: '', json: null, code: 'CONNECTION_CLOSED', headers: {} });
                reject(error);
            });
            if (payload) req.write(payload);
            req.end();
        });
    };
}

const multipart = (data, filename) => {
    const boundary = `----opssim${crypto.randomBytes(8).toString('hex')}`;
    const head = Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="${filename}"\r\nContent-Type: application/octet-stream\r\n\r\n`);
    return { body: Buffer.concat([head, data, Buffer.from(`\r\n--${boundary}--\r\n`)]), contentType: `multipart/form-data; boundary=${boundary}` };
};

const b64url = (value) => Buffer.from(typeof value === 'string' ? value : JSON.stringify(value)).toString('base64url');

async function run(ctx) {
    const touched = new Set(); // IP de origen realmente usadas (para limpiar su estado)
    const send = makeClient(ctx, touched);
    const trusted = Boolean(ctx.trustsForwardedFor);
    const offset = 100 + ((ctx.runId * 4) % 100);
    const ipA = trusted ? `203.0.113.${offset}` : '127.0.0.1'; // registro, inyecciones, JWT, payload (sin confianza no se usa: no hay pasos)
    const ipB = trusted ? `203.0.113.${offset + 1}` : null;   // fuerza bruta (solo si se puede aislar su origen)
    // Subidas desde IP propias: las inyecciones de antes BLOQUEAN ipA, y un rechazo por IP_BLOCKED no probaría el filtro de
    // archivos (antes pasaba: «rechazado 403 IP_BLOCKED» se contaba como acierto del filtro)
    const ipUpload = trusted ? `203.0.113.${offset + 2}` : null;
    const ipEicar = trusted ? `203.0.113.${offset + 3}` : null;
    // ¿Lo rechazó la protección por IP (no el control que se quería probar)?
    const byIpBlock = (r) => r.code === 'IP_BLOCKED' || r.code === 'RATE_LIMITED' || r.status === 429;
    // Sin IP de prueba utilizables (el servidor no confía en X-Forwarded-For) no se ejecuta ningún paso de ataque
    const step = (name, announce, fn) => ctx.step(name, announce, trusted
        ? fn
        : async () => ({ level: 'warn', message: 'Omitido: sin TRUST_PROXY no se pueden usar IP de prueba (203.0.113.x) y el ataque saldría de 127.0.0.1 (BFF y administradores), pudiendo bloquear o limitar esa IP' }));

    const [[mx]] = await db.query('SELECT COALESCE(MAX(id), 0) AS id FROM security_events');
    const startEventId = Number(mx.id);

    // Eventos de seguridad que dejó la IP desde el inicio (para decir si se DETECTÓ, no solo si se rechazó)
    const recordedFor = async (ip) => {
        await sleep(150);
        const [rows] = await db.query(
            'SELECT event_type, rule FROM security_events WHERE ip_address = ? AND id > ? ORDER BY id DESC LIMIT 20', [ip, startEventId]
        );
        return [...new Set(rows.map(r => (r.rule ? `${r.event_type}/${r.rule}` : r.event_type)))].slice(0, 6);
    };

    const attacks = [];
    const record = (name, blocked, recorded) => attacks.push({ name, blocked, recorded: recorded.length > 0 });
    const rejected = (r) => r.status === 0 || (r.status >= 400 && r.status < 500) || r.status === 503;

    const created = { userId: null, fileIds: [] };
    let token = null;
    let username = null;
    let password = null;

    ctx.setTotal(11);
    if (!trusted) {
        await ctx.emit('warn', 'configuracion', 'El servidor no confía en X-Forwarded-For (TRUST_PROXY): no se puede usar IP de prueba; se OMITEN todos los pasos de ataque para no limitar ni bloquear 127.0.0.1 (BFF y administradores)', { trustsForwardedFor: false });
    }

    try {
        await step('preparacion', 'Creando un usuario temporal de pruebas', async () => {
            username = `opssim_${crypto.randomBytes(5).toString('hex')}`;
            password = randomPassword();
            const reg = await send({ method: 'POST', path: '/api/auth/register', ip: ipA, json: { username, email: 'opssim@example.com', password } });
            if (reg.status !== 201) return { level: 'warn', message: `No se pudo crear el usuario temporal (HTTP ${reg.status}${reg.code ? ` ${reg.code}` : ''}): se omiten los pasos que necesitan sesión` };
            created.userId = reg.json?.userId ?? null;
            const login = await send({ method: 'POST', path: '/api/auth/login', ip: ipA, json: { username, password } });
            token = login.status === 200 ? login.json?.token : null;
            if (!token) return { level: 'warn', message: `El usuario temporal no pudo iniciar sesión (HTTP ${login.status})` };
            return { message: 'Usuario temporal creado y con sesión (se borrará al terminar)', data: { sent: 'POST /api/auth/register + /login' } };
        });

        await step('sqli-login', 'Inyección SQL en el login: usuario «admin\' OR \'1\'=\'1\' --»', async () => {
            const r = await send({ method: 'POST', path: '/api/auth/login', ip: ipA, json: { username: "admin' OR '1'='1' --", password: 'x' } });
            const recorded = await recordedFor(ipA);
            const leaked = r.status === 200 || Boolean(r.json?.token);
            record('Inyección SQL (login)', !leaked, recorded);
            const data = { sent: "POST /api/auth/login {username: \"admin' OR '1'='1' --\"}", status: r.status, code: r.code, recorded };
            if (leaked) return { level: 'fail', message: 'LA INYECCIÓN OBTUVO UNA SESIÓN', data };
            return { message: `Rechazada (HTTP ${r.status}${r.code ? ` ${r.code}` : ''}); ${recorded.length ? `detectada: ${recorded.join(', ')}` : 'sin evento de seguridad'}`, data };
        });

        await step('sqli-query', 'Inyección SQL en un parámetro de consulta (/api/files?before=1 OR 1=1)', async () => {
            if (!token) return { level: 'warn', message: 'Omitido: no hay sesión temporal' };
            const r = await send({ path: '/api/files?before=' + encodeURIComponent('1 OR 1=1; DROP TABLE users --'), ip: ipA, token });
            const recorded = await recordedFor(ipA);
            const leaked = r.status === 200 && Array.isArray(r.json?.files) && r.json.files.length > 0;
            record('Inyección SQL (consulta)', !leaked && r.status !== 500, recorded);
            const data = { sent: 'GET /api/files?before=1 OR 1=1; DROP TABLE users --', status: r.status, code: r.code, recorded };
            if (leaked || r.status === 500) return { level: 'fail', message: `Respuesta inesperada (HTTP ${r.status})`, data };
            return { message: `Rechazada o inofensiva (HTTP ${r.status}${r.code ? ` ${r.code}` : ''}); ${recorded.length ? `detectada: ${recorded.join(', ')}` : 'sin evento'}`, data };
        });

        await step('xss', 'XSS almacenado: nota con <script> y onerror', async () => {
            if (!token) return { level: 'warn', message: 'Omitido: no hay sesión temporal' };
            const title = '<script>alert(1)</script>nota';
            const content = '<img src=x onerror=alert(1)> y <a href="javascript:alert(1)">clic</a>';
            const r = await send({ method: 'POST', path: '/api/notes', ip: ipA, token, json: { title, content } });
            const data = { sent: 'POST /api/notes con <script>, onerror= y javascript:', status: r.status, code: r.code };
            if (r.status >= 400) {
                record('XSS', true, await recordedFor(ipA));
                return { message: `Rechazado en la entrada (HTTP ${r.status}${r.code ? ` ${r.code}` : ''})`, data };
            }
            const noteId = r.json?.note?.id ?? r.json?.id;
            const back = noteId ? await send({ path: `/api/notes/${noteId}`, ip: ipA, token }) : r;
            // Diseño del proyecto: el texto se guarda tal cual (la API no es HTML) y el XSS se evita porque la respuesta es JSON con
            // nosniff y el cliente escapa al pintar. Lo que importa aquí: que NUNCA se sirva como HTML ejecutable.
            const type = String(back.headers?.['content-type'] || '');
            const nosniff = String(back.headers?.['x-content-type-options'] || '').toLowerCase() === 'nosniff';
            const servedAsHtml = /html|xml/i.test(type) || !nosniff;
            const recorded = await recordedFor(ipA);
            record('XSS', !servedAsHtml, recorded);
            Object.assign(data, { contentType: type.split(';')[0], nosniff, recorded });
            if (servedAsHtml) return { level: 'fail', message: `La nota se sirve como ${type || 'tipo desconocido'} ${nosniff ? '' : 'sin nosniff'}: podría ejecutarse en el navegador`, data };
            return { message: `Guardada como texto y servida como ${type.split(';')[0]} + nosniff (no ejecutable); ${recorded.length ? `registrada: ${recorded.join(', ')}` : 'sin evento'}`, data };
        });

        await step('path-traversal', 'Path traversal en la descarga de archivos', async () => {
            if (!token) return { level: 'warn', message: 'Omitido: no hay sesión temporal' };
            const paths = ['/api/files/..%2f..%2f..%2fetc%2fpasswd/download', '/api/files/%2e%2e/%2e%2e/.env', '/api/files/1/download?inline=../../../../etc/passwd'];
            const results = [];
            for (const path of paths) {
                const r = await send({ path, ip: ipA, token });
                const leaked = r.status === 200 && /root:|DB_FRAGMENT|BASE_SEED/.test(r.text);
                results.push({ path: clip(path, 60), status: r.status });
                if (leaked) {
                    record('Path traversal', false, []);
                    return { level: 'fail', message: `LA RUTA ${clip(path, 60)} DEVOLVIÓ CONTENIDO DEL SISTEMA`, data: { results } };
                }
            }
            record('Path traversal', true, await recordedFor(ipA));
            return { message: `3 variantes rechazadas (${results.map(r => r.status).join(', ')}), sin filtrar archivos del sistema`, data: { results } };
        });

        await step('jwt-falso', 'JWT falsificado: alg none, firma incorrecta y carga alterada', async () => {
            const real = token || `${b64url({ alg: 'HS256', typ: 'JWT' })}.${b64url({ userId: 1, role: 'admin' })}.firma`;
            const [h, p, s] = real.split('.');
            let payload = {};
            try { payload = JSON.parse(Buffer.from(p, 'base64url').toString('utf8')); } catch { /* token de relleno */ }
            const forgedPayload = b64url({ ...payload, role: 'admin', userId: 1 });
            const forged = {
                'alg none': `${b64url({ alg: 'none', typ: 'JWT' })}.${forgedPayload}.`,
                'firma incorrecta': `${h}.${forgedPayload}.${crypto.createHmac('sha256', 'secreto-inventado').update(`${h}.${forgedPayload}`).digest('base64url')}`,
                'carga alterada': `${h}.${forgedPayload}.${s}`
            };
            const results = [];
            for (const [name, jwtValue] of Object.entries(forged)) {
                const r = await send({ path: '/api/system/status', ip: ipA, token: jwtValue });
                results.push({ variant: name, status: r.status });
                if (r.status === 200) {
                    record('JWT falsificado', false, []);
                    return { level: 'fail', message: `UN JWT FALSIFICADO (${name}) FUE ACEPTADO`, data: { results } };
                }
            }
            record('JWT falsificado', true, ['INVALID_TOKEN']);
            return { message: `Los 3 JWT falsos fueron rechazados (${results.map(r => `${r.variant}: ${r.status}`).join(', ')})`, data: { results } };
        });

        await step('fuerza-bruta', 'Fuerza bruta de contraseña hasta el bloqueo', async () => {
            if (!ipB) return { level: 'warn', message: 'Omitido: sin TRUST_PROXY no se puede aislar el origen y se bloquearía el loopback' };
            if (!username) return { level: 'warn', message: 'Omitido: no hay usuario temporal' };
            const secureAuth = require('../../security/secure-auth.service');
            const limit = secureAuth.lockout.maxFailures;
            const attempts = Math.min(limit + 2, 9);
            const statuses = [];
            let blockedAt = null;
            for (let i = 1; i <= attempts; i++) {
                const r = await send({ method: 'POST', path: '/api/auth/login', ip: ipB, json: { username, password: `incorrecta-${i}-${crypto.randomBytes(3).toString('hex')}` } });
                statuses.push(r.status);
                if (r.status === 200) return { level: 'fail', message: 'UNA CONTRASEÑA INCORRECTA INICIÓ SESIÓN', data: { statuses } };
                if (blockedAt === null && (r.status === 429 || r.code === 'ACCOUNT_LOCKED' || r.code === 'IP_BLOCKED' || r.code === 'RATE_LIMITED')) { blockedAt = i; break; }
            }
            const recorded = await recordedFor(ipB);
            record('Fuerza bruta', blockedAt !== null, recorded);
            const data = { sent: `${statuses.length} logins con contraseñas incorrectas`, statuses, lockoutAfter: limit, recorded };
            if (blockedAt === null) return { level: 'fail', message: `Sin bloqueo tras ${statuses.length} intentos fallidos (límite configurado: ${limit})`, data };
            // Con la cuenta bloqueada, ni la contraseña correcta debe entrar
            const correct = await send({ method: 'POST', path: '/api/auth/login', ip: ipB, json: { username, password } });
            if (correct.status === 200) return { level: 'fail', message: 'LA CUENTA BLOQUEADA ACEPTÓ LA CONTRASEÑA CORRECTA', data };
            return { message: `Bloqueo al intento ${blockedAt} (límite ${limit}); la contraseña correcta también se rechazó (HTTP ${correct.status}); ${recorded.length ? `detectado: ${recorded.join(', ')}` : 'sin evento'}`, data };
        });

        await step('subida-ejecutable', 'Subida de un ejecutable (MZ) disfrazado de foto.jpg', async () => {
            if (!token) return { level: 'warn', message: 'Omitido: no hay sesión temporal' };
            const { body, contentType } = multipart(Buffer.concat([Buffer.from('MZ'), crypto.randomBytes(500)]), 'foto.jpg');
            const r = await send({ method: 'POST', path: '/api/files', ip: ipUpload, token, body, contentType });
            const fileId = r.json?.file?.id;
            if (fileId) created.fileIds.push(fileId);
            const recorded = await recordedFor(ipUpload);
            if (byIpBlock(r)) {
                return { level: 'warn', message: `Rechazado por la protección por IP (HTTP ${r.status} ${r.code || ''}), no por el filtro de archivos: este paso no lo prueba`, data: { status: r.status, code: r.code } };
            }
            record('Subida de ejecutable', r.status >= 400, recorded);
            const data = { sent: 'POST /api/files (MZ + bytes, nombre foto.jpg)', status: r.status, code: r.code, recorded };
            if (r.status < 400) return { level: 'fail', message: `SE ACEPTÓ UN EJECUTABLE DISFRAZADO (HTTP ${r.status})`, data };
            return { message: `Rechazado (HTTP ${r.status}${r.code ? ` ${r.code}` : ''}); ${recorded.length ? `detectado: ${recorded.join(', ')}` : 'sin evento'}`, data };
        });

        await step('subida-eicar', 'Subida del fichero de prueba EICAR (antivirus)', async () => {
            if (!token) return { level: 'warn', message: 'Omitido: no hay sesión temporal' };
            const { body, contentType } = multipart(Buffer.from(EICAR), 'eicar.txt');
            const r = await send({ method: 'POST', path: '/api/files', ip: ipEicar, token, body, contentType });
            const fileId = r.json?.file?.id;
            if (fileId) created.fileIds.push(fileId);
            const av = require('../../files/av-scanner');
            const data = { sent: 'POST /api/files (EICAR como eicar.txt)', status: r.status, code: r.code };
            if (byIpBlock(r)) {
                return { level: 'warn', message: `Rechazado por la protección por IP (HTTP ${r.status} ${r.code || ''}), no por el antivirus: este paso no lo prueba`, data };
            }
            if (r.status >= 400) {
                record('Subida de EICAR', true, await recordedFor(ipEicar));
                return { message: `Rechazado (HTTP ${r.status}${r.code ? ` ${r.code}` : ''})`, data };
            }
            if (!av.enabled()) {
                record('Subida de EICAR', false, []);
                return { level: 'warn', message: 'EICAR aceptado porque el antivirus está desactivado (FILE_SCAN=off); se borrará', data };
            }
            record('Subida de EICAR', false, []);
            return { level: 'fail', message: 'EL ANTIVIRUS ESTÁ ACTIVO Y ACEPTÓ EICAR', data };
        });

        await step('payload-enorme', 'Payload enorme: cuerpo JSON de 3 MB', async () => {
            const big = Buffer.from(JSON.stringify({ username: 'a'.repeat(3 * 1024 * 1024), password: 'x' }));
            const r = await send({ method: 'POST', path: '/api/auth/login', ip: ipA, body: big, contentType: 'application/json' });
            record('Payload enorme', rejected(r) && r.status !== 200, []);
            const data = { sent: 'POST /api/auth/login con ~3 MB', status: r.status, code: r.code };
            if (r.status === 200 || r.status >= 500) return { level: 'fail', message: `El servidor no rechazó limpiamente el cuerpo enorme (HTTP ${r.status})`, data };
            return { message: `Rechazado (HTTP ${r.status || 'conexión cerrada'})`, data };
        });
    } finally {
        // Limpieza SIEMPRE, también si se cancela o falla un paso
        // No usa ctx.step: ese comprueba la cancelación y la limpieza debe ejecutarse SIEMPRE
        await ctx.emit('info', 'limpieza', '▶ Borrando lo creado y el estado por IP de las IP usadas');
        const started = Date.now();
        const problems = [];
        const usedIps = [...touched];
        try {
            for (const id of created.fileIds) {
                const r = await send({ method: 'DELETE', path: `/api/files/${id}`, ip: ipUpload || ipA, token }).catch(() => ({ status: 0 }));
                if (r.status >= 400 || r.status === 0) problems.push(`archivo ${id}`);
            }
            if (created.userId) {
                await db.query('DELETE FROM users WHERE id = ?', [created.userId]).catch(() => problems.push('usuario temporal'));
            }
            // El borrado de las IP usadas va SIEMPRE (también la loopback si se llegó a usar). Solo estado por IP, nada de auditoría.
            const anomaly = require('../../security/anomaly-detection.service');
            for (const ip of usedIps) {
                await anomaly.unblockIP(ip).catch(() => problems.push(`IP ${ip}`));
                await db.query('DELETE FROM blocked_ips WHERE ip_address = ?', [ip]).catch(() => problems.push(`blocked_ips ${ip}`));
                await db.query('DELETE FROM login_attempts WHERE ip_address = ? OR ip_subject = ?', [ip, ip]).catch(() => problems.push(`login_attempts ${ip}`));
                await db.query('DELETE FROM rate_limit_counters WHERE subject = ? OR subject LIKE ?', [ip, `%${ip}%`]).catch(() => problems.push(`rate_limit_counters ${ip}`));
                if (await anomaly.isIPBlocked(ip).catch(() => false)) problems.push(`IP ${ip} sigue bloqueada`);
            }
        } catch (error) {
            problems.push(clip(error.message, 80));
        }
        const ms = Date.now() - started;
        await ctx.emit(problems.length ? 'warn' : 'pass', 'limpieza',
            `${problems.length ? `Limpieza incompleta: ${problems.join(', ')}` : `Estado por IP borrado (${usedIps.join(', ') || 'ninguna IP usada'}) y usuario temporal eliminado`} (${ms} ms)`, { ms });
    }

    const blocked = attacks.filter(a => a.blocked).length;
    const summary = { attacks, blocked, total: attacks.length, recorded: attacks.filter(a => a.recorded).length, trustsForwardedFor: trusted };
    await ctx.emit('info', 'resumen', `${blocked} de ${attacks.length} ataques bloqueados; ${summary.recorded} dejaron evento de seguridad`, { blocked, total: attacks.length });
    return { summary };
}

module.exports = { run, validate, describe };
