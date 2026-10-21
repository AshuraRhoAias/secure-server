// clamd SIMULADO (protocolo INSTREAM) para las pruebas. Detecta la cadena EICAR y permite provocar los fallos
// que un clamd real puede tener: caídas, silencio, errores, límite de tamaño.

const net = require('net');
const crypto = require('crypto');

const EICAR = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*';

async function startFakeClamd({ maxBytes = 25 * 1024 * 1024 } = {}) {
    const state = { behavior: 'normal', connections: 0, received: [], delayMs: 0, dropAfterBytes: null, maxBytes };

    const server = net.createServer((socket) => {
        state.connections++;
        let buffer = Buffer.alloc(0);
        let started = false;
        const data = [];
        let total = 0;
        socket.on('error', () => {});

        const reply = (text) => { if (!socket.destroyed) socket.end(text + '\0'); };

        socket.on('data', (chunk) => {
            buffer = Buffer.concat([buffer, chunk]);
            if (!started) {
                const nul = buffer.indexOf(0);
                if (nul < 0) return;
                const command = buffer.subarray(0, nul).toString();
                buffer = buffer.subarray(nul + 1);
                if (command === 'zPING') return reply('PONG');
                if (command !== 'zINSTREAM') return reply('UNKNOWN COMMAND');
                started = true;
            }
            while (buffer.length >= 4) {
                const length = buffer.readUInt32BE(0);
                if (length === 0) {
                    buffer = buffer.subarray(4);
                    return finish();
                }
                if (buffer.length < 4 + length) return;
                const part = buffer.subarray(4, 4 + length);
                buffer = buffer.subarray(4 + length);
                data.push(part);
                total += part.length;
                if (total > state.maxBytes) return reply('INSTREAM size limit exceeded. ERROR');
                if (state.dropAfterBytes !== null && total >= state.dropAfterBytes) return socket.destroy();
            }
        });

        function finish() {
            const all = Buffer.concat(data);
            state.received.push({ bytes: all.length, sha256: crypto.createHash('sha256').update(all).digest('hex') });
            const answer = () => {
                if (state.behavior === 'silent') return; // nunca contesta
                if (state.behavior === 'error') return reply('lstat() failed: No such file or directory. ERROR');
                reply(all.includes(EICAR) ? 'stream: Eicar-Test-Signature FOUND' : 'stream: OK');
            };
            state.delayMs ? setTimeout(answer, state.delayMs) : answer();
        }
    });

    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    return Object.assign(state, {
        port: server.address().port,
        close: () => new Promise(resolve => { server.close(resolve); server.closeAllConnections?.(); }),
        reset() { Object.assign(state, { behavior: 'normal', connections: 0, received: [], delayMs: 0, dropAfterBytes: null, maxBytes }); }
    });
}

module.exports = { startFakeClamd, EICAR };
