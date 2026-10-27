// Qué archivos se aceptan y cómo se reconoce su TIPO REAL.
//
// El tipo se decide por los PRIMEROS BYTES del contenido ("magic bytes"), nunca por la extensión del
// nombre ni por el Content-Type que declara el cliente (ambos los controla quien sube el archivo).
// Un .jpg cuyo contenido es un ejecutable se rechaza; un .png que en realidad es un JPEG también
// (la extensión debe coincidir con el contenido).
//
// Lo que NO se acepta, aunque lo pidan: SVG, HTML, XML, JavaScript, ejecutables, scripts, archivos
// comprimidos/ofimáticos (ZIP, DOCX...). Son los que permiten ejecutar código al abrirlos.

const CATEGORIES = ['image', 'video', 'audio', 'document', 'text'];

// mime → extensiones válidas de ese contenido
const TYPES = {
    'image/jpeg': { category: 'image', ext: ['jpg', 'jpeg'] },
    'image/png': { category: 'image', ext: ['png'] },
    'image/gif': { category: 'image', ext: ['gif'] },
    'image/webp': { category: 'image', ext: ['webp'] },
    'image/avif': { category: 'image', ext: ['avif'] },
    'image/heic': { category: 'image', ext: ['heic', 'heif'] },
    'video/mp4': { category: 'video', ext: ['mp4', 'm4v'] },
    'video/quicktime': { category: 'video', ext: ['mov'] },
    'video/3gpp': { category: 'video', ext: ['3gp', '3g2'] },
    'video/webm': { category: 'video', ext: ['webm'] },
    'video/x-matroska': { category: 'video', ext: ['mkv'] },
    'video/x-msvideo': { category: 'video', ext: ['avi'] },
    'audio/mpeg': { category: 'audio', ext: ['mp3'] },
    'audio/mp4': { category: 'audio', ext: ['m4a', 'm4b'] },
    'audio/wav': { category: 'audio', ext: ['wav'] },
    'audio/ogg': { category: 'audio', ext: ['ogg', 'oga', 'opus'] },
    'audio/flac': { category: 'audio', ext: ['flac'] },
    'audio/aac': { category: 'audio', ext: ['aac'] },
    'application/pdf': { category: 'document', ext: ['pdf'] },
    'text/plain': { category: 'text', ext: ['txt', 'csv', 'md', 'json', 'log'] }
};

// Segmentos de nombre que nunca se admiten (doble extensión tipo "foto.php.jpg" incluida)
const FORBIDDEN_EXTENSIONS = new Set([
    'exe', 'dll', 'com', 'scr', 'msi', 'bat', 'cmd', 'ps1', 'psm1', 'vbs', 'vbe', 'wsf', 'hta', 'lnk', 'jar', 'apk',
    'sh', 'bash', 'zsh', 'csh', 'run', 'bin', 'elf', 'so', 'dylib',
    'js', 'mjs', 'cjs', 'jse', 'ts', 'html', 'htm', 'xhtml', 'shtml', 'svg', 'xml', 'xsl', 'xslt', 'swf',
    'php', 'php3', 'php4', 'php5', 'phtml', 'phar', 'asp', 'aspx', 'ashx', 'jsp', 'jspx', 'cgi', 'pl', 'py', 'rb', 'war',
    'htaccess', 'htpasswd', 'config', 'ini', 'reg', 'iso', 'dmg'
]);

// eslint-disable-next-line security/detect-unsafe-regex -- un único `.*` final, sin cuantificadores anidados; el nombre ya está acotado a 120 caracteres
const WINDOWS_RESERVED = /^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?$/i;

const startsWith = (buf, bytes, offset = 0) => bytes.every((b, i) => buf[offset + i] === b);
const ascii = (buf, start, end) => buf.toString('latin1', start, end);

// --------------------------------------------------------------------------------------------
// Detección por contenido. `head` son los primeros bytes (basta con 4096).
// Devuelve { mime, category } | { rejected: 'MOTIVO' } | null (no reconocido)
// --------------------------------------------------------------------------------------------
function detectType(head) {
    if (!head || head.length < 4) return null;

    // ---- contenido peligroso: se rechaza con motivo propio ----
    if (startsWith(head, [0x4d, 0x5a])) return { rejected: 'EXECUTABLE_CONTENT' };                    // MZ (Windows PE)
    if (startsWith(head, [0x7f, 0x45, 0x4c, 0x46])) return { rejected: 'EXECUTABLE_CONTENT' };         // ELF
    if (startsWith(head, [0xca, 0xfe, 0xba, 0xbe]) || startsWith(head, [0xfe, 0xed, 0xfa, 0xce]) ||
        startsWith(head, [0xfe, 0xed, 0xfa, 0xcf]) || startsWith(head, [0xcf, 0xfa, 0xed, 0xfe])) return { rejected: 'EXECUTABLE_CONTENT' }; // Mach-O / clase Java
    if (startsWith(head, [0x23, 0x21])) return { rejected: 'EXECUTABLE_CONTENT' };                     // #! script
    if (startsWith(head, [0x50, 0x4b, 0x03, 0x04]) || startsWith(head, [0x50, 0x4b, 0x05, 0x06])) return { rejected: 'ARCHIVE_NOT_ALLOWED' }; // ZIP/JAR/DOCX
    if (startsWith(head, [0x1f, 0x8b]) || startsWith(head, [0x52, 0x61, 0x72, 0x21]) || startsWith(head, [0x37, 0x7a, 0xbc, 0xaf])) return { rejected: 'ARCHIVE_NOT_ALLOWED' };

    // ---- imágenes ----
    if (startsWith(head, [0xff, 0xd8, 0xff])) return { mime: 'image/jpeg' };
    if (startsWith(head, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])) return { mime: 'image/png' };
    if (ascii(head, 0, 6) === 'GIF87a' || ascii(head, 0, 6) === 'GIF89a') return { mime: 'image/gif' };

    // ---- contenedor RIFF: WEBP / WAV / AVI ----
    if (ascii(head, 0, 4) === 'RIFF' && head.length >= 12) {
        const form = ascii(head, 8, 12);
        if (form === 'WEBP') return { mime: 'image/webp' };
        if (form === 'WAVE') return { mime: 'audio/wav' };
        if (form === 'AVI ') return { mime: 'video/x-msvideo' };
        return null;
    }

    // ---- ISO base media (MP4, MOV, M4A, AVIF, HEIC, 3GP) ----
    if (head.length >= 12 && ascii(head, 4, 8) === 'ftyp') {
        const brand = ascii(head, 8, 12);
        if (['M4A ', 'M4B ', 'F4A '].includes(brand)) return { mime: 'audio/mp4' };
        if (brand === 'qt  ') return { mime: 'video/quicktime' };
        if (['avif', 'avis'].includes(brand)) return { mime: 'image/avif' };
        if (['heic', 'heix', 'hevc', 'heim', 'heis', 'mif1', 'msf1'].includes(brand)) return { mime: 'image/heic' };
        if (/^3g[p2]/.test(brand)) return { mime: 'video/3gpp' };
        return { mime: 'video/mp4' };
    }

    // ---- Matroska / WebM ----
    if (startsWith(head, [0x1a, 0x45, 0xdf, 0xa3])) {
        const probe = ascii(head, 0, Math.min(head.length, 80));
        if (probe.includes('webm')) return { mime: 'video/webm' };
        if (probe.includes('matroska')) return { mime: 'video/x-matroska' };
        return null;
    }

    // ---- audio ----
    if (ascii(head, 0, 4) === 'OggS') return { mime: 'audio/ogg' };
    if (ascii(head, 0, 4) === 'fLaC') return { mime: 'audio/flac' };
    if (ascii(head, 0, 3) === 'ID3' && head[3] <= 4) return { mime: 'audio/mpeg' };
    if (head[0] === 0xff && (head[1] & 0xf6) === 0xf0) return { mime: 'audio/aac' };                    // ADTS
    if (head[0] === 0xff && (head[1] & 0xe0) === 0xe0) {                                                // cabecera de trama MPEG
        const version = (head[1] >> 3) & 3, layer = (head[1] >> 1) & 3, bitrate = head[2] >> 4, sampleRate = (head[2] >> 2) & 3;
        if (version !== 1 && layer !== 0 && bitrate !== 15 && bitrate !== 0 && sampleRate !== 3) return { mime: 'audio/mpeg' };
    }

    // ---- documento ----
    if (ascii(head, 0, 5) === '%PDF-') return { mime: 'application/pdf' };

    return null;
}

// ¿Parece texto plano? (UTF-8 válido, sin NUL ni controles raros) y sin marcas de contenido activo
// (HTML, SVG, scripts, PHP...) en las primeras líneas. Se usa solo cuando no hay firma binaria.
function looksLikeText(head) {
    if (head.includes(0)) return false;
    try {
        new TextDecoder('utf-8', { fatal: true }).decode(head, { stream: true });
    } catch {
        return false;
    }
    for (const byte of head) {
        if (byte < 0x20 && byte !== 0x09 && byte !== 0x0a && byte !== 0x0d) return false;
    }
    return true;
}

const ACTIVE_CONTENT = /<\s*(?:!doctype\s+html|html|head|body|script|svg|iframe|object|embed|\?php|\?xml)|<%|^\s*#!|javascript:/i;

function hasActiveContent(head) {
    return ACTIVE_CONTENT.test(head.toString('utf8', 0, Math.min(head.length, 4096)));
}

// --------------------------------------------------------------------------------------------
// Nombres de archivo
// --------------------------------------------------------------------------------------------
function sanitizeFilename(raw) {
    let name = String(raw ?? '').normalize('NFC');

    name = name
        .replace(/[\u0000-\u001f\u007f-\u009f]/g, '')                                       // controles (incluye NUL, CR, LF)
        .replace(/[\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff]/g, '');      // invisibles y bidi (U+202E invierte la extension que se ve)

    name = name.split(/[\\/]/).pop();             // solo el nombre, sin ruta (ambos separadores)
    name = name.replace(/[<>:"|?*]/g, '_');       // ilegales en Windows
    name = name.replace(/^\.+/, '');              // sin nombres ocultos ni "..";
    name = name.replace(/[ .]+$/, '');            // sin puntos/espacios finales

    if (name.length > 120) {
        const dot = name.lastIndexOf('.');
        const ext = dot > 0 ? name.slice(dot).slice(0, 12) : '';
        name = name.slice(0, 120 - ext.length) + ext;
    }
    if (!name) name = 'archivo';
    if (WINDOWS_RESERVED.test(name)) name = `_${name}`;
    return name;
}

function extensionOf(name) {
    const dot = name.lastIndexOf('.');
    return dot > 0 && dot < name.length - 1 ? name.slice(dot + 1).toLowerCase() : '';
}

// Cualquier segmento del nombre (no solo el último) con extensión prohibida: "foto.php.jpg" también
function hasForbiddenExtension(name) {
    return name.toLowerCase().split('.').slice(1).some(segment => FORBIDDEN_EXTENSIONS.has(segment));
}

// ASCII seguro para la cabecera Content-Disposition (el nombre real va aparte en filename*=UTF-8'')
function asciiFallbackName(name) {
    return name.replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 100) || 'archivo';
}

function contentDisposition(name, disposition = 'attachment') {
    const encoded = encodeURIComponent(name).replace(/['()*]/g, c => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);
    return `${disposition}; filename="${asciiFallbackName(name)}"; filename*=UTF-8''${encoded}`;
}

module.exports = {
    CATEGORIES, TYPES, FORBIDDEN_EXTENSIONS,
    detectType, looksLikeText, hasActiveContent,
    sanitizeFilename, extensionOf, hasForbiddenExtension, contentDisposition, asciiFallbackName
};
