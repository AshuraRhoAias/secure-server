// Proceso hijo de kms.js: hace las llamadas (posiblemente de red) al KMS y devuelve el resultado por stdout.
// Entrada (stdin, JSON): { op: 'wrap'|'unwrap', items: [{name, value}], provider? }
// Salida (stdout, JSON): { ok: true, items: [{value}] } | { ok: false, error }
//
// Cada valor se envuelve junto con SU NOMBRE ("ENCRYPTION_SEED\n<valor>"): un blob de una variable no se puede
// copiar a otra (por ejemplo, pegar el blob de JWT_SEED como ENCRYPTION_SEED) sin que el descifrado lo detecte.

const PREFIX = 'kms:';

const fail = (message) => { process.stdout.write(JSON.stringify({ ok: false, error: message })); process.exit(0); };

const { providers } = require('./kms-providers');

async function main() {
    let input = '';
    for await (const chunk of process.stdin) input += chunk;
    const { op, items, provider } = JSON.parse(input);

    const out = [];
    for (const { name, value } of items) {
        if (op === 'wrap') {
            const impl = providers[provider];
            if (!impl) fail(`proveedor desconocido: ${provider} (file | vault | aws)`);
            out.push({ value: `${PREFIX}${provider}:${await impl.wrap(name, value)}` });
        } else {
            const [, providerName, ...rest] = value.split(':');
            const impl = providers[providerName];
            if (!impl) fail(`proveedor desconocido en el valor de ${name}: ${providerName}`);
            out.push({ value: await impl.unwrap(name, rest.join(':')) });
        }
    }
    process.stdout.write(JSON.stringify({ ok: true, items: out }));
}

main().catch(error => fail(`${error.name === 'Error' ? '' : error.name + ': '}${error.message}`));
