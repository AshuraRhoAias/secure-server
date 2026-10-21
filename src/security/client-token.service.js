const crypto = require('crypto');
const secureEnv = require('../config/secure-env');

// Token web único por cliente, VARIABLE CADA DÍA y distinto para cada usuario.
//
// Qué es: un segundo factor de transporte, aparte del JWT. El servidor lo emite
// al iniciar sesión y el cliente debe enviarlo en CADA petición en la cabecera
// `X-Client-Token`. Sin él (o con uno de otro día u otro usuario), la petición
// se rechaza con 403.
//
// Cómo se construye (determinista, sin estado que almacenar):
//
//   token = HMAC_SHA256( secreto_servidor , "userId:FECHA_UTC" )
//
//   - Depende del userId  -> es único por usuario.
//   - Depende de la fecha UTC -> cambia solo cada día, sin temporizadores.
//   - Usa un secreto del servidor (el secreto de sesión derivado de las semillas)
//     -> el cliente no lo puede falsificar; sólo el servidor lo emite/valida.
//
// Como es determinista, no hay nada que guardar ni que sincronizar entre
// procesos: cualquier instancia valida el token recomputándolo.

const HEADER_NAME = 'x-client-token';

function todayUTC(d = new Date()) {
    return d.toISOString().slice(0, 10); // YYYY-MM-DD
}

function secret() {
    // El secreto de sesión ya rota con el juego de claves. Se le añade una
    // etiqueta para no reutilizar material de clave entre propósitos distintos.
    return secureEnv.getSecret('session') + '|client-token/v1';
}

// Token para un usuario y un día concretos.
function tokenFor(userId, date = todayUTC()) {
    return crypto
        .createHmac('sha256', secret())
        .update(`${userId}:${date}`)
        .digest('hex');
}

// Emite el token del día para un usuario, con su caducidad (fin del día UTC).
function issue(userId, date = todayUTC()) {
    const expiresAt = `${date}T23:59:59.999Z`;
    return { token: tokenFor(userId, date), expiresAt, date };
}

// Comparación en tiempo constante (evita fugas por tiempo).
function safeEqual(a, b) {
    const ba = Buffer.from(String(a), 'utf8');
    const bb = Buffer.from(String(b), 'utf8');
    if (ba.length !== bb.length) return false;
    return crypto.timingSafeEqual(ba, bb);
}

// Verifica el token recibido para un usuario. Acepta el de HOY y, con una
// pequeña tolerancia, el de AYER, para no cortar peticiones justo al cruzar la
// medianoche UTC mientras el cliente aún no ha renovado.
function verify(userId, provided, { graceYesterday = true } = {}) {
    if (!provided || typeof provided !== 'string') return false;
    const today = todayUTC();
    if (safeEqual(provided, tokenFor(userId, today))) return true;
    if (graceYesterday) {
        const yesterday = todayUTC(new Date(Date.now() - 24 * 60 * 60 * 1000));
        if (safeEqual(provided, tokenFor(userId, yesterday))) return true;
    }
    return false;
}

module.exports = { HEADER_NAME, issue, verify, tokenFor, todayUTC };
