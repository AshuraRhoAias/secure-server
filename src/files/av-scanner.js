const net = require('net');
const { Transform } = require('stream');

// Antivirus: cliente del protocolo INSTREAM de ClamAV (clamd). Cada byte que se sube se envía a clamd MIENTRAS
// se cifra (no se guarda el archivo en claro en ningún sitio) y el veredicto llega antes de dar el archivo por
// bueno: si es malware, la subida se rechaza y se borra lo escrito.
//
// Variables de entorno:
//   FILE_SCAN              off (por defecto) | optional | required
//                          optional: si clamd no responde, el archivo se acepta marcado "unscanned" y queda un evento
//                          required: si clamd no responde, la subida se rechaza (503). Recomendado en producción.
//   CLAMAV_HOST / CLAMAV_PORT   clamd por TCP (127.0.0.1:3310 por defecto)
//   CLAMAV_SOCKET               o por socket Unix (/var/run/clamav/clamd.ctl)
//   CLAMAV_TIMEOUT_MS           espera máxima por el veredicto (60 000)
//   CLAMAV_MAX_BYTES            StreamMaxLength de clamd (25 MB por defecto en clamd; ajústalo a su clamd.conf)
//   FILE_SCAN_ON_OVERSIZE       reject (por defecto) | skip: qué hacer con archivos mayores que CLAMAV_MAX_BYTES
//
// Limitación honesta: ClamAV detecta lo que sus firmas conocen. Un malware nuevo o hecho a medida pasa. Es una
// capa más, no una garantía. Mantén freshclam al día y vuelve a revisar lo ya guardado con scripts/rescanFiles.js.

const config = () => ({
    mode: ['optional', 'required'].includes(process.env.FILE_SCAN) ? process.env.FILE_SCAN : 'off',
    host: process.env.CLAMAV_HOST || '127.0.0.1',
    port: Number(process.env.CLAMAV_PORT) || 3310,
    socket: process.env.CLAMAV_SOCKET || '',
    timeoutMs: Number(process.env.CLAMAV_TIMEOUT_MS) || 60_000,
    maxBytes: Number(process.env.CLAMAV_MAX_BYTES) || 25 * 1024 * 1024,
    onOversize: process.env.FILE_SCAN_ON_OVERSIZE === 'skip' ? 'skip' : 'reject'
});

const connect = (c) => new Promise((resolve, reject) => {
    const socket = c.socket ? net.connect(c.socket) : net.connect(c.port, c.host);
    const timer = setTimeout(() => { socket.destroy(); reject(new Error('timeout conectando con clamd')); }, Math.min(c.timeoutMs, 10_000));
    socket.once('connect', () => { clearTimeout(timer); resolve(socket); });
    socket.once('error', (error) => { clearTimeout(timer); reject(error); });
});

// "stream: Eicar-Test-Signature FOUND" -> { status: 'found', signature }
function parseReply(text) {
    const reply = text.replace(/\0/g, '').trim();
    if (/ OK$/.test(reply)) return { status: 'clean' };
    const found = /^stream: (.+) FOUND$/.exec(reply);
    if (found) return { status: 'found', signature: found[1].replace(/[^\w.\-/]/g, '_').slice(0, 60) };
    return { status: 'error', detail: reply.slice(0, 120) };
}

class ScanError extends Error {
    constructor(kind, message, detail) { super(message); this.kind = kind; this.detail = detail; }
}

// Una sesión INSTREAM con clamd. send(chunk) con contrapresión; finish() devuelve el veredicto.
class ClamSession {
    constructor(c) {
        this.c = c;
        this.socket = null;
        this.reply = '';
        this.closed = false;
        this.waiters = [];
    }

    async open() {
        this.socket = await connect(this.c);
        this.socket.setNoDelay(true);
        this.socket.on('data', (chunk) => { this.reply += chunk.toString('latin1'); this.notify(); });
        this.socket.on('error', (error) => { this.error = error; this.closed = true; this.notify(); });
        this.socket.on('close', () => { this.closed = true; this.notify(); });
        this.socket.write('zINSTREAM\0');
    }

    notify() { const w = this.waiters; this.waiters = []; w.forEach(fn => fn()); }

    // clamd puede contestar ANTES del final (p. ej. "INSTREAM size limit exceeded. ERROR")
    earlyReply() { return this.reply.includes('\0') ? parseReply(this.reply) : null; }

    async send(chunk) {
        if (this.closed) throw new ScanError('unavailable', 'clamd cerró la conexión', this.error?.message);
        const early = this.earlyReply();
        if (early) throw new ScanError(early.status === 'found' ? 'found' : 'error', 'clamd respondió antes de tiempo', early.signature || early.detail);

        const header = Buffer.alloc(4);
        header.writeUInt32BE(chunk.length);
        const ok = this.socket.write(Buffer.concat([header, chunk]));
        if (!ok) await new Promise((resolve) => this.socket.once('drain', resolve));
    }

    async finish() {
        if (!this.closed) this.socket.write(Buffer.alloc(4)); // longitud 0 = fin del flujo
        const deadline = Date.now() + this.c.timeoutMs;

        while (!this.reply.includes('\0')) {
            if (this.closed) throw new ScanError('unavailable', 'clamd cerró la conexión sin veredicto', this.error?.message);
            const remaining = deadline - Date.now();
            if (remaining <= 0) { this.destroy(); throw new ScanError('unavailable', 'clamd no respondió a tiempo'); }
            await new Promise((resolve) => {
                const timer = setTimeout(resolve, remaining);
                this.waiters.push(() => { clearTimeout(timer); resolve(); });
            });
        }
        this.destroy();
        return parseReply(this.reply);
    }

    destroy() { this.socket?.destroy(); }
}

// Transform que reenvía todo tal cual y, a la vez, lo manda a clamd. Se coloca DESPUÉS de decidir el tipo
// (un archivo rechazado por tipo ni siquiera llega al antivirus) y ANTES de cifrar.
class ScanTee extends Transform {
    constructor(UploadError) {
        super();
        this.UploadError = UploadError;
        this.c = config();
        this.session = null;
        this.sent = 0;
        this.state = 'pending';      // pending | scanning | skipped | failed | clean
    }

    get scanStatus() {
        return this.state === 'clean' ? 'clean' : this.state === 'skipped' ? 'skipped' : 'unscanned';
    }

    unavailable(detail) {
        return new this.UploadError(503, 'SCANNER_UNAVAILABLE', 'El antivirus no está disponible: inténtalo de nuevo más tarde', { severity: 'medium', rule: 'SCANNER_UNAVAILABLE', detail });
    }

    malware(signature) {
        return new this.UploadError(422, 'MALWARE_DETECTED', 'El archivo contiene malware y se ha rechazado', { severity: 'critical', rule: `MALWARE_${signature}`.slice(0, 64) });
    }

    // Un fallo del escáner: en "required" rechaza; en "optional" el archivo sigue sin escanear
    onScannerFailure(error) {
        if (error.kind === 'found') return this.malware(error.detail);
        this.session?.destroy();
        this.session = null;
        if (this.c.mode === 'required') return this.unavailable(error.detail || error.message);
        this.state = 'failed';
        this.scannerError = error.detail || error.message;
        return null;
    }

    async _transform(chunk, _encoding, callback) {
        try {
            if (this.state === 'failed' || this.state === 'skipped') { this.push(chunk); return callback(); }

            if (this.sent + chunk.length > this.c.maxBytes) {
                if (this.c.onOversize === 'reject') {
                    this.session?.destroy();
                    return callback(new this.UploadError(413, 'SCAN_SIZE_LIMIT', `El archivo supera el tamaño que el antivirus puede revisar (${Math.floor(this.c.maxBytes / 1048576)} MB)`, { severity: 'low', rule: 'SCAN_SIZE_LIMIT' }));
                }
                this.session?.destroy();
                this.session = null;
                this.state = 'skipped';
                this.push(chunk);
                return callback();
            }

            if (!this.session) {
                this.session = new ClamSession(this.c);
                await this.session.open();
                this.state = 'scanning';
            }
            await this.session.send(chunk);
            this.sent += chunk.length;
            this.push(chunk);
            callback();
        } catch (error) {
            this.state = this.state === 'pending' ? 'failed' : this.state;
            const failure = this.onScannerFailure(error instanceof ScanError ? error : new ScanError('unavailable', error.message, error.code || error.message));
            if (failure) return callback(failure);
            this.push(chunk);
            callback();
        }
    }

    async _flush(callback) {
        try {
            if (this.state === 'scanning') {
                const verdict = await this.session.finish();
                if (verdict.status === 'found') return callback(this.malware(verdict.signature));
                if (verdict.status === 'error') throw new ScanError('error', 'clamd devolvió un error', verdict.detail);
                this.state = 'clean';
            } else if (this.state === 'pending') {
                // Archivo vacío: no hay nada que escanear
                this.state = 'clean';
            }
            callback();
        } catch (error) {
            const failure = this.onScannerFailure(error instanceof ScanError ? error : new ScanError('unavailable', error.message, error.code || error.message));
            callback(failure || undefined);
        }
    }
}

// Escanea un flujo ya existente (lo usa scripts/rescanFiles.js). Devuelve { status: 'clean'|'found'|'error', signature }
async function scanBuffers(iterable) {
    const c = config();
    const session = new ClamSession(c);
    await session.open();
    let sent = 0;
    try {
        for await (const chunk of iterable) {
            sent += chunk.length;
            if (sent > c.maxBytes) { session.destroy(); return { status: 'error', detail: 'supera el límite de clamd' }; }
            await session.send(chunk);
        }
        return await session.finish();
    } catch (error) {
        session.destroy();
        if (error instanceof ScanError && error.kind === 'found') return { status: 'found', signature: error.detail };
        return { status: 'error', detail: error.detail || error.message };
    }
}

const enabled = () => config().mode !== 'off';

module.exports = { ScanTee, scanBuffers, config, enabled, parseReply, ClamSession };
