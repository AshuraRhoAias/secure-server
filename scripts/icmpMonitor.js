#!/usr/bin/env node
// Monitor de canales encubiertos ICMP (exfiltración con `ping -p`).
//
// Se ejecuta COMO PROCESO APARTE del servidor web: capturar paquetes requiere root o CAP_NET_RAW
// y el servidor web nunca debe tenerlos (ver README, "Defensa contra exfiltración por ICMP").
//
//   sudo npm run icmp-monitor                              # captura en vivo (todas las interfaces)
//   sudo npm run icmp-monitor -- --interface eth0
//   npm run icmp-monitor -- --file captura.txt --dry-run   # analiza una captura guardada, sin privilegios
//
// Opciones:
//   --interface <if>   interfaz a vigilar (por defecto "any")
//   --file <ruta>      leer salida de tcpdump desde un archivo en vez de capturar
//   --dry-run          solo imprimir alertas: no escribe en BD, no envía alertas, no bloquea IPs
//   --autoblock        bloquea en la capa HTTP las IPs externas con alertas high/critical (ver aviso)
//   --allowlist <ips>  IPs de monitoreo legítimas separadas por comas (también ICMP_MONITOR_ALLOWLIST)
//
// Aviso sobre --autoblock: la IP de origen de un paquete ICMP se puede falsificar. Con el bloqueo
// automático activo, un atacante podría provocar que bloqueemos a una IP inocente. Por eso está
// desactivado por defecto: las alertas se registran y se notifican, y bloquear es decisión tuya.
//
// Captura que se ejecuta (argumentos fijos, sin shell):
//   tcpdump -l -nn -tt -s 0 -x -i <if> 'icmp[icmptype] = icmp-echo or icmp[icmptype] = icmp-echoreply'

const fs = require('fs');
const path = require('path');
const readline = require('readline');
const { spawn } = require('child_process');

const { IcmpCovertChannelDetector, levelRank } = require('../src/security/icmp-covert-channel.service');
const { TcpdumpParser } = require('../src/security/tcpdump-parser');

const SEVERITY_BY_LEVEL = { medium: 'medium', high: 'high', critical: 'critical' };
const RISK_BY_LEVEL = { medium: 40, high: 70, critical: 95 };

function parseArgs(argv) {
    const args = { interface: 'any', file: null, dryRun: false, autoblock: false, allowlist: process.env.ICMP_MONITOR_ALLOWLIST || '' };
    for (let i = 0; i < argv.length; i++) {
        switch (argv[i]) {
            case '--interface': args.interface = argv[++i]; break;
            case '--file': args.file = argv[++i]; break;
            case '--allowlist': args.allowlist = argv[++i] || ''; break;
            case '--dry-run': args.dryRun = true; break;
            case '--autoblock': args.autoblock = true; break;
            default:
                console.error(`Opción desconocida: ${argv[i]}`);
                process.exit(1);
        }
    }
    // El nombre de interfaz acaba como argumento de tcpdump: solo caracteres seguros
    if (!/^[a-zA-Z0-9._-]+$/.test(args.interface || '')) {
        console.error('Nombre de interfaz inválido');
        process.exit(1);
    }
    return args;
}

function formatAlert(alert) {
    const reasons = alert.reasons.map(r => `${r.code}: ${r.detail}`).join('; ');
    return `🚨 [${alert.level.toUpperCase()}] ICMP encubierto (${alert.direction}) ${alert.src} → ${alert.dst} | ${reasons}`;
}

async function handleAlert(alert, { dryRun, autoblock, detector }) {
    console.log(formatAlert(alert));
    if (dryRun) return;

    // Los servicios se cargan solo aquí: en --dry-run no se toca BD ni disco
    const audit = require('../src/services/audit.service');
    const secureCommunications = require('../src/services/secure-communications.service');
    const anomalyDetection = require('../src/security/anomaly-detection.service');

    await audit.log('ICMP_COVERT_CHANNEL', alert, {
        severity: SEVERITY_BY_LEVEL[alert.level],
        riskScore: RISK_BY_LEVEL[alert.level]
    });

    try {
        await secureCommunications.sendSecureAlert({
            type: 'ICMP_COVERT_CHANNEL',
            severity: SEVERITY_BY_LEVEL[alert.level],
            details: `${formatAlert(alert)} (paquetes analizados: ${detector.getStats().packets})`,
            timestamp: new Date().toISOString()
        }, alert.level === 'critical' ? 'critical' : 'normal');
    } catch (error) {
        console.error('❌ No se pudo enviar la alerta:', error.message);
    }

    // Solo con --autoblock: una IP externa que nos envía ICMP encubierto se bloquea también en la
    // capa HTTP. El bloqueo de red real lo hace el firewall (scripts/icmp-firewall.sh); si el
    // origen es esta propia máquina (egress) NO se bloquea nada: hay que investigar el host.
    if (autoblock && alert.direction === 'ingress' && levelRank(alert.level) >= levelRank('high')) {
        await anomalyDetection.blockIP(alert.src, `ICMP_COVERT_CHANNEL: ${alert.reasons[0].code}`);
    }
}

async function main() {
    const args = parseArgs(process.argv.slice(2));

    if (!args.dryRun) {
        require('dotenv').config({ path: path.join(__dirname, '../.env') });
    }

    const detector = new IcmpCovertChannelDetector({
        allowlist: args.allowlist.split(',').map(s => s.trim()).filter(Boolean)
    });

    // Las alertas se procesan en cola para no solapar escrituras en BD
    let queue = Promise.resolve();
    const parser = new TcpdumpParser((pkt) => {
        const alert = detector.observe(pkt);
        if (alert) queue = queue.then(() => handleAlert(alert, { dryRun: args.dryRun, autoblock: args.autoblock, detector })).catch(e => console.error(e));
    });

    let input;
    let child = null;

    if (args.file) {
        input = fs.createReadStream(args.file);
    } else {
        const filter = 'icmp[icmptype] = icmp-echo or icmp[icmptype] = icmp-echoreply';
        child = spawn('tcpdump', ['-l', '-nn', '-tt', '-s', '0', '-x', '-i', args.interface, filter], {
            stdio: ['ignore', 'pipe', 'pipe']
        });
        child.on('error', (error) => {
            console.error(error.code === 'ENOENT'
                ? '❌ tcpdump no está instalado (apt install tcpdump)'
                : `❌ Error lanzando tcpdump: ${error.message}`);
            process.exit(1);
        });
        child.stderr.on('data', (chunk) => process.stderr.write(chunk));
        child.on('exit', (code) => {
            if (code) console.error(`❌ tcpdump terminó con código ${code} (¿faltan privilegios? se necesita root o CAP_NET_RAW)`);
            process.exit(code || 0);
        });
        input = child.stdout;
        console.log(`🛰️ Vigilando ICMP en "${args.interface}"${args.dryRun ? ' (dry-run)' : ''}...`);
    }

    const rl = readline.createInterface({ input });
    rl.on('line', (line) => parser.push(line));
    rl.on('close', async () => {
        parser.flush();
        await queue;
        const stats = detector.getStats();
        console.log(`✅ Análisis terminado: ${stats.packets} paquetes, ${stats.nonStandard} no estándar, ${stats.alerts} alertas`);
        if (args.file) process.exit(0);
    });

    const stop = () => { if (child) child.kill('SIGTERM'); else process.exit(0); };
    process.on('SIGINT', stop);
    process.on('SIGTERM', stop);
}

main();
