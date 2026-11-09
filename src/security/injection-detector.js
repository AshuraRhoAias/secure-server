// Detector de intentos de inyección. Módulo PURO: no toca BD, red ni disco.
//
// IMPORTANTE: esto NO es lo que protege contra la inyección SQL. Lo que la impide es que toda
// consulta usa parámetros (ver src/config/sql.js). Este detector es defensa en profundidad y
// sobre todo SEÑAL: cada hallazgo se guarda en `security_events` para analizar después quién
// prueba qué, y alimenta el bloqueo automático de IPs que insisten.
//
// Cada regla tiene una severidad:
//   high    firma inequívoca de ataque (UNION SELECT, <script>, ../, ${jndi:...}). Casi no hay
//           texto legítimo que la active.
//   medium  sospechosa pero con falsos positivos posibles en texto libre (un artículo sobre SQL
//           contiene "SELECT ... FROM"). Solo se registra, no se rechaza.
//
// Las expresiones evitan cuantificadores anidados y todo el texto se acota a MAX_SCAN caracteres
// por campo, para que el propio detector no sea un vector de ReDoS.

const MAX_SCAN = 8192;
const MAX_NODES = 2000;
const MAX_DEPTH = 8;

const RULES = [
    // ---- SQL ----
    { id: 'SQLI_UNION', family: 'SQL_INJECTION', severity: 'high', re: /\bunion(?: all| distinct)? ?\(? ?select\b/ },
    { id: 'SQLI_STACKED', family: 'SQL_INJECTION', severity: 'high', re: /; ?(?:drop (?:table|database|schema|view|user)|truncate (?:table )?\w|alter (?:table|user|database)|delete from|insert into|update \w+ set|create (?:table|user|database)|exec(?:ute)?[ (]|grant |shutdown\b)/ },
    { id: 'SQLI_TAUTOLOGY', family: 'SQL_INJECTION', severity: 'high', re: /['"`] ?(?:or|and|\|\||&&) ?['"`(]?\w+['"`)]? ?(?:=|like|<>|!=) ?['"`(]?\w+/ },
    { id: 'SQLI_TAUTOLOGY_BARE', family: 'SQL_INJECTION', severity: 'high', re: /\b(?:or|and) (\d+|'[^']{0,40}'|"[^"]{0,40}") ?= ?\1/ },
    { id: 'SQLI_TIME_BASED', family: 'SQL_INJECTION', severity: 'high', re: /\b(?:sleep|benchmark|pg_sleep)\s?\(|\bwaitfor delay\b|dbms_pipe\.receive_message/ },
    { id: 'SQLI_SCHEMA_PROBE', family: 'SQL_INJECTION', severity: 'high', re: /\b(?:information_schema|mysql\.user|sysobjects|pg_catalog|sqlite_master)\b/ },
    { id: 'SQLI_DANGEROUS_FUNC', family: 'SQL_INJECTION', severity: 'high', re: /\bload_file ?\(|\binto (?:out|dump)file\b|\bextractvalue ?\(|\bupdatexml ?\(|@@(?:version|datadir|hostname)|\bxp_cmdshell\b/ },
    { id: 'SQLI_COMMENT_TAIL', family: 'SQL_INJECTION', severity: 'medium', re: /['"] ?(?:-- |--$|#)/ },
    { id: 'SQLI_SELECT_FROM', family: 'SQL_INJECTION', severity: 'medium', re: /\bselect\b.{1,200}?\bfrom\b/ },

    // ---- XSS ----
    { id: 'XSS_SCRIPT_TAG', family: 'XSS', severity: 'high', re: /<\s?\/?\s?script\b/ },
    { id: 'XSS_EVENT_HANDLER', family: 'XSS', severity: 'high', re: /<[a-z][^>]{0,200}?[\s/"']on[a-z]{3,20} ?=/ },
    { id: 'XSS_EMBED_TAG', family: 'XSS', severity: 'high', re: /<\s?(?:iframe|object|embed)\b|<\s?meta[^>]{0,80}http-equiv/ },
    { id: 'XSS_DATA_HTML', family: 'XSS', severity: 'high', re: /data:text\/html/ },
    { id: 'XSS_JS_URL', family: 'XSS', severity: 'medium', re: /\b(?:javascript|vbscript) ?:/ },
    { id: 'XSS_HTML_TAG', family: 'XSS', severity: 'medium', re: /<\s?(?:svg|math|link|base|form|style|img|body|input|video|audio|details|marquee)\b[^>]{0,200}>/ },

    // ---- Ruta / archivos ----
    { id: 'PATH_TRAVERSAL', family: 'PATH_TRAVERSAL', severity: 'high', re: /\.\.[\\/]|[\\/]\.\.(?:[\\/]|$)/ },
    { id: 'PATH_SENSITIVE_FILE', family: 'PATH_TRAVERSAL', severity: 'high', re: /\/etc\/(?:passwd|shadow|hosts)|\/proc\/self|[a-z]:\\windows|\bboot\.ini\b|\/\.git\/|\/\.env\b/ },

    // ---- Comandos / plantillas ----
    { id: 'CMD_DESTRUCTIVE', family: 'COMMAND_INJECTION', severity: 'high', re: /\brm -rf?\b|\/bin\/(?:ba)?sh\b|\bcmd(?:\.exe)? \/c\b|\bpowershell(?:\.exe)? -/ },
    { id: 'CMD_CHAIN', family: 'COMMAND_INJECTION', severity: 'medium', re: /[;|&]{1,2} ?(?:cat|ls|id|whoami|uname|wget|curl|nc|ncat|bash|sh|zsh|python\d?|perl|php|ruby|node) (?:-|\/|\w)/ },
    { id: 'CMD_SUBSHELL', family: 'COMMAND_INJECTION', severity: 'medium', re: /\$\([^)]{1,100}\)|`[^`]{1,100}`/ },
    { id: 'LOG4SHELL_JNDI', family: 'CODE_INJECTION', severity: 'high', re: /\$\{ ?(?:jndi|env|sys|java|lower|upper) ?[:}]/ },

    // ---- Protocolo ----
    { id: 'CRLF_INJECTION', family: 'HEADER_INJECTION', severity: 'high', re: /[\r\n] ?(?:set-cookie|location|content-type|content-length|http\/\d)/i, raw: true },
    { id: 'NUL_BYTE', family: 'PROTOCOL', severity: 'high', re: /\u0000/, raw: true }
];

const NOSQL_KEY = /^\$(?:where|ne|gt|gte|lt|lte|in|nin|regex|or|and|not|nor|exists|expr|function|accumulator|jsonSchema)$/;
const POLLUTION_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

// Campos cuyo contenido jamás se inspecciona ni se guarda en eventos (pueden llevar cualquier carácter)
const SECRET_FIELD = /pass(?:word|wd)?|secret|token|authorization|api[-_]?key|cookie/i;

// Cabeceras que un cliente controla y que nunca deberían llevar sintaxis de ataque
const SCANNED_HEADERS = ['user-agent', 'referer', 'origin', 'host', 'x-forwarded-for', 'x-forwarded-host', 'x-forwarded-proto', 'x-requested-with', 'accept', 'accept-language', 'content-type'];

// eslint-disable-next-line security/detect-unsafe-regex -- es la expresión "unrolled" estándar de comentario C: lineal; probada con 1 000 000 de "/*" en test_security.js (ReDoS)
const C_COMMENT = /\/\*[^*]*\*+(?:[^/*][^*]*\*+)*\//g; // comentario /* ... */ en tiempo lineal

function percentDecode(text) {
    return text.replace(/%([0-9a-f]{2})/gi, (_, hex) => String.fromCharCode(parseInt(hex, 16)));
}

// Forma canónica para comparar: decodifica %xx (hasta 2 veces), unifica Unicode (＜ → <),
// elimina comentarios SQL usados para ofuscar (UNION/**/SELECT; /*!50000UNION*/) y colapsa espacios.
function normalize(value) {
    let text = String(value).slice(0, MAX_SCAN);
    for (let i = 0; i < 2 && /%[0-9a-f]{2}/i.test(text); i++) {
        try { text = decodeURIComponent(text); } catch { text = percentDecode(text); }
    }
    return text
        .normalize('NFKC')
        .replace(/\/\*!\d*/g, ' ')      // /*!50000UNION*/ : MySQL ejecuta lo de dentro, así que se conserva
        .replace(C_COMMENT, ' ')
        .replace(/\*\//g, ' ')
        .replace(/\s+/g, ' ')
        .toLowerCase();
}

// Valores y claves de un objeto, con su ruta ("body.notes[0].title")
function* walk(value, path = '', depth = 0, budget = { n: 0 }) {
    if (budget.n++ > MAX_NODES || depth > MAX_DEPTH) return;

    if (typeof value === 'string') {
        yield { kind: 'value', path, text: value };
    } else if (Array.isArray(value)) {
        for (let i = 0; i < value.length; i++) yield* walk(value[i], `${path}[${i}]`, depth + 1, budget);
    } else if (value && typeof value === 'object') {
        for (const key of Object.keys(value)) {
            const child = path ? `${path}.${key}` : key;
            yield { kind: 'key', path: child, text: key };
            if (SECRET_FIELD.test(key)) continue; // no se inspecciona ni se registra
            yield* walk(value[key], child, depth + 1, budget);
        }
    }
}

function scanText(text, { location, field, bodyLike = false }) {
    const findings = [];
    const raw = String(text).slice(0, MAX_SCAN);
    const canonical = normalize(text);

    for (const rule of RULES) {
        const haystack = rule.raw ? percentDecode(raw) : canonical;
        const match = rule.re.exec(haystack);
        if (!match) continue;

        // En el CUERPO (texto libre del usuario) "../" o "ls -la" no ejecutan nada: el servidor nunca usa
        // el cuerpo como ruta ni como comando. Se registran pero no se rechazan.
        const demoted = bodyLike && (rule.family === 'PATH_TRAVERSAL' || rule.family === 'COMMAND_INJECTION');

        findings.push({
            rule: rule.id,
            family: rule.family,
            severity: demoted ? 'medium' : rule.severity,
            location,
            field,
            bodyLike,
            // Solo un trozo acotado alrededor del hallazgo, nunca el campo entero
            sample: haystack.slice(Math.max(0, match.index - 20), match.index + 100).replace(/[\r\n]/g, ' ')
        });
    }
    return findings;
}

function scanObject(obj, location, bodyLike) {
    const findings = [];
    for (const node of walk(obj, location)) {
        if (node.kind === 'key') {
            if (NOSQL_KEY.test(node.text)) {
                findings.push({ rule: 'NOSQL_OPERATOR', family: 'NOSQL_INJECTION', severity: 'high', location, field: node.path, bodyLike, sample: node.text });
            }
            if (POLLUTION_KEYS.has(node.text)) {
                findings.push({ rule: 'PROTOTYPE_POLLUTION', family: 'CODE_INJECTION', severity: 'high', location, field: node.path, bodyLike, sample: node.text });
            }
            findings.push(...scanText(node.text, { location, field: node.path, bodyLike }));
        } else {
            findings.push(...scanText(node.text, { location, field: node.path, bodyLike }));
        }
    }
    return findings;
}

// Inspecciona una petición Express ya parseada. Devuelve { findings, highestSeverity }.
function scanRequest(req) {
    const findings = [];

    findings.push(...scanText(req.path || '', { location: 'url', field: 'path' }));
    const queryIndex = (req.originalUrl || req.url || '').indexOf('?');
    if (queryIndex >= 0) findings.push(...scanText((req.originalUrl || req.url).slice(queryIndex), { location: 'url', field: 'querystring' }));

    findings.push(...scanObject(req.query, 'query', false));
    findings.push(...scanObject(req.params, 'params', false));

    for (const name of SCANNED_HEADERS) {
        const value = req.headers?.[name];
        if (typeof value === 'string' && value) findings.push(...scanText(value, { location: 'headers', field: name }));
    }

    if (req.body && typeof req.body === 'object') findings.push(...scanObject(req.body, 'body', true));

    const rank = { medium: 1, high: 2 };
    const highest = findings.reduce((acc, f) => (rank[f.severity] > rank[acc] ? f.severity : acc), 'none');
    return { findings, highestSeverity: highest === 'none' ? null : highest };
}

module.exports = { scanRequest, scanText, scanObject, normalize, RULES, SECRET_FIELD, POLLUTION_KEYS };
