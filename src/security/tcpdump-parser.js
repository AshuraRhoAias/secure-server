// Convierte la salida de texto de
//     tcpdump -l -nn -tt -s 0 -x 'icmp[icmptype] = icmp-echo or icmp[icmptype] = icmp-echoreply'
// en paquetes { time, src, dst, type, id, seq, payload } para IcmpCovertChannelDetector.
//
// Formato esperado (con `-i any` se añade la interfaz y la dirección tras el timestamp):
//   1700000000.123456 IP 10.0.0.1 > 10.0.0.2: ICMP echo request, id 7, seq 1, length 64
//       0x0000:  4500 0054 1c46 4000 4001 ...      <- volcado hex desde la cabecera IP

const HEADER_RE = /^(\d+(?:\.\d+)?) .*?\bIP (\S+) > (\S+): ICMP echo (request|reply), id (\d+), seq (\d+), length (\d+)/;
const HEX_LINE_RE = /^\s+0x[0-9a-f]+:\s+((?:[0-9a-f]{2,4}\s?)+)/i;

class TcpdumpParser {
    constructor(onPacket) {
        this.onPacket = onPacket;
        this.current = null;
    }

    push(line) {
        const header = HEADER_RE.exec(line);
        if (header) {
            this.flush();
            this.current = {
                time: Math.round(parseFloat(header[1]) * 1000),
                src: header[2],
                dst: header[3],
                type: header[4] === 'request' ? 'echo-request' : 'echo-reply',
                id: Number(header[5]),
                seq: Number(header[6]),
                hex: ''
            };
            return;
        }

        if (!this.current) return;

        const hex = HEX_LINE_RE.exec(line);
        if (hex) {
            this.current.hex += hex[1].replace(/\s/g, '');
        } else if (line.trim() !== '' && !line.startsWith('\t') && !line.startsWith(' ')) {
            // Otra línea de cabecera que no es ICMP echo: cerrar el paquete actual
            this.flush();
        }
    }

    flush() {
        const pkt = this.current;
        this.current = null;
        if (!pkt) return;

        const bytes = Buffer.from(pkt.hex, 'hex');
        if (bytes.length < 20) return;

        const ipHeaderLength = (bytes[0] & 0x0f) * 4;
        const payload = bytes.subarray(ipHeaderLength + 8); // 8 = cabecera ICMP echo
        const { hex, ...rest } = pkt;

        this.onPacket({ ...rest, payload });
    }
}

module.exports = { TcpdumpParser };
