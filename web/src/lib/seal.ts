import { createCipheriv, createDecipheriv, hkdfSync, randomBytes } from 'node:crypto';

// Cookies cifradas y autenticadas (AES-256-GCM). El navegador solo guarda un blob opaco: los tokens del API NUNCA llegan al JavaScript
// de la página (XSS no puede leerlos) ni se pueden alterar (la etiqueta GCM lo detecta). El "propósito" va como dato autenticado: una
// cookie de MFA no vale como cookie de sesión aunque se copie su valor.
//
// WEB_SESSION_SECRET (≥ 32 caracteres, aleatorio) deriva la clave con HKDF. WEB_SESSION_SECRET_PREVIOUS permite rotarla sin cerrar las
// sesiones vigentes: se descifra con cualquiera de las dos, se cifra siempre con la actual.

const VERSION = 'v1';
const b64u = (buffer: Buffer): string => buffer.toString('base64url');

function derive(secret: string): Buffer {
  if (secret.length < 32) throw new Error('WEB_SESSION_SECRET debe tener al menos 32 caracteres');
  return Buffer.from(hkdfSync('sha256', secret, Buffer.alloc(0), 'secure-server-ops/cookie/v1', 32));
}

function keys(): Buffer[] {
  const current = process.env.WEB_SESSION_SECRET;
  if (!current) throw new Error('Falta WEB_SESSION_SECRET');
  const previous = process.env.WEB_SESSION_SECRET_PREVIOUS;
  return [derive(current), ...(previous ? [derive(previous)] : [])];
}

export function seal(payload: unknown, purpose: string, ttlMs: number): string {
  const key = keys()[0] as Buffer;
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(Buffer.from(purpose));
  const body = Buffer.from(JSON.stringify({ p: payload, e: Date.now() + ttlMs }), 'utf8');
  const data = Buffer.concat([cipher.update(body), cipher.final()]);
  return [VERSION, b64u(iv), b64u(cipher.getAuthTag()), b64u(data)].join('.');
}

export function unseal<T>(value: string | undefined | null, purpose: string): T | null {
  if (!value || value.length > 8192) return null;
  const [version, ivText, tagText, dataText, extra] = value.split('.');
  if (version !== VERSION || !ivText || !tagText || !dataText || extra !== undefined) return null;

  let candidates: Buffer[];
  try { candidates = keys(); } catch { return null; }

  for (const key of candidates) {
    try {
      const iv = Buffer.from(ivText, 'base64url');
      const tag = Buffer.from(tagText, 'base64url');
      if (iv.length !== 12 || tag.length !== 16) return null;
      const decipher = createDecipheriv('aes-256-gcm', key, iv);
      decipher.setAAD(Buffer.from(purpose));
      decipher.setAuthTag(tag);
      const plain = Buffer.concat([decipher.update(Buffer.from(dataText, 'base64url')), decipher.final()]);
      const wrapper = JSON.parse(plain.toString('utf8')) as { p: T; e: number };
      if (typeof wrapper.e !== 'number' || wrapper.e < Date.now()) return null;
      return wrapper.p;
    } catch {
      // clave equivocada o blob alterado: se prueba la siguiente
    }
  }
  return null;
}
