// Defensa CSRF de las rutas que cambian cosas, además de la cookie SameSite=Strict:
//   1. cabecera personalizada X-Ops-Csrf (un formulario o <img> de otro sitio no puede añadirla; un fetch de otro origen exigiría CORS,
//      que esta aplicación no concede);
//   2. Origin presente y igual al propio (los navegadores siempre lo envían en POST/DELETE);
//   3. si el navegador manda Sec-Fetch-Site, debe ser same-origin.
export const CSRF_HEADER = 'x-ops-csrf';

export function ownOrigin(headers: Headers): string | null {
  const fixed = process.env.WEB_ORIGIN;
  if (fixed) return fixed.replace(/\/+$/, '');
  const host = headers.get('x-forwarded-host') || headers.get('host');
  if (!host) return null;
  const proto = headers.get('x-forwarded-proto') || (process.env.NODE_ENV === 'production' ? 'https' : 'http');
  return `${proto.split(',')[0]?.trim()}://${host.split(',')[0]?.trim()}`;
}

export function csrfOk(method: string, headers: Headers): boolean {
  if (method === 'GET' || method === 'HEAD') return true;
  if (headers.get(CSRF_HEADER) !== '1') return false;
  const site = headers.get('sec-fetch-site');
  if (site && site !== 'same-origin') return false;
  const origin = headers.get('origin');
  const own = ownOrigin(headers);
  return Boolean(origin && own && origin === own);
}
