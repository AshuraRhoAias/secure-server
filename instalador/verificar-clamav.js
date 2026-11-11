#!/usr/bin/env node
'use strict';
// Comprueba que clamd está listo para secure-server, por el MISMO camino que usa el servidor (src/files/av-scanner.js):
//   1) PING → PONG   2) VERSION (firmas cargadas)   3) INSTREAM con el archivo de prueba EICAR → debe salir "FOUND".
// Lee las mismas variables que el servidor: CLAMAV_SOCKET, o CLAMAV_HOST / CLAMAV_PORT (127.0.0.1:3310 por defecto).
//
// Uso:  node instalador/verificar-clamav.js [--esperar <segundos>]
//   --esperar: clamd tarda en cargar las firmas (30-90 s); reintenta durante ese tiempo antes de dar el fallo.
// Salida: 0 si todo bien; 1 si clamd no responde o no detecta EICAR.
const net = require('net');

const arg = (name, def) => { const i = process.argv.indexOf(name); return i > 0 ? process.argv[i + 1] : def; };
const waitSeconds = Number(arg('--esperar', '0')) || 0;
const target = process.env.CLAMAV_SOCKET
    ? { path: process.env.CLAMAV_SOCKET }
    : { host: process.env.CLAMAV_HOST || '127.0.0.1', port: Number(process.env.CLAMAV_PORT) || 3310 };
const where = target.path || `${target.host}:${target.port}`;

// El archivo EICAR (estándar de prueba, inofensivo) se compone en memoria: así ningún antivirus marca este script
const EICAR = ['X5O!P%@AP[4\\PZX54(P^)7CC)7}$', 'EICAR-STANDARD-ANTIVIRUS', '-TEST-FILE!$H+H*'].join('');

function command(cmd, payload) {
    return new Promise((resolve, reject) => {
        const socket = net.connect(target);
        let reply = '';
        const timer = setTimeout(() => { socket.destroy(); reject(new Error('sin respuesta en 15 s')); }, 15_000);
        socket.on('connect', () => {
            socket.write(`z${cmd}\0`);
            if (payload) {
                const size = Buffer.alloc(4);
                size.writeUInt32BE(payload.length);
                socket.write(Buffer.concat([size, payload, Buffer.alloc(4)])); // trozo + fin (longitud 0)
            }
        });
        socket.on('data', (d) => { reply += d; });
        socket.on('end', () => { clearTimeout(timer); resolve(reply.replace(/\0/g, '').trim()); });
        socket.on('error', (e) => { clearTimeout(timer); reject(e); });
    });
}

async function main() {
    const deadline = Date.now() + waitSeconds * 1000;
    let pong;
    for (;;) {
        try { pong = await command('PING'); break; } catch (e) {
            if (Date.now() >= deadline) {
                console.error(`✖  clamd no responde en ${where}: ${e.code || e.message}`);
                console.error('   ¿Está arrancado el servicio? Al iniciarse tarda hasta un minuto en cargar las firmas.');
                return 1;
            }
            await new Promise(r => setTimeout(r, 3000));
        }
    }
    if (pong !== 'PONG') { console.error(`✖  respuesta inesperada a PING: ${pong}`); return 1; }
    console.log(`✔  clamd responde en ${where}`);
    console.log(`✔  ${await command('VERSION')}`);
    const verdict = await command('INSTREAM', Buffer.from(EICAR));
    if (!/FOUND$/.test(verdict)) {
        console.error(`✖  clamd NO detectó el archivo de prueba EICAR (respuesta: ${verdict}). ¿Faltan firmas? Ejecuta freshclam.`);
        return 1;
    }
    console.log(`✔  detecta el archivo de prueba EICAR (${verdict.replace(/^stream: /, '')})`);
    console.log('   Para que el servidor analice cada subida: FILE_SCAN=required en su entorno (ver docs/SEGURIDAD.md).');
    return 0;
}

main().then((code) => process.exit(code)).catch((e) => { console.error(`✖  ${e.message}`); process.exit(1); });
