// Configuración del BFF. Todo se lee de forma perezosa (en cada uso) para que las pruebas puedan cambiar el entorno.

export function apiBase(): URL {
  const raw = process.env.OPS_API_URL;
  if (!raw) throw new Error('Falta OPS_API_URL (URL del API de secure-server, p. ej. https://api.ejemplo.com)');
  const url = new URL(raw);
  const production = process.env.NODE_ENV === 'production';
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && (!production || process.env.OPS_API_ALLOW_HTTP === 'true'))) {
    throw new Error('OPS_API_URL debe ser https:// en producción (OPS_API_ALLOW_HTTP=true solo para redes internas de confianza)');
  }
  return url;
}

// Cookies "__Host-" (Secure, Path=/, sin Domain: no las puede fijar un subdominio) cuando se sirve por HTTPS
export const cookieSecure = (): boolean =>
  process.env.WEB_COOKIE_SECURE ? process.env.WEB_COOKIE_SECURE === 'true' : process.env.NODE_ENV === 'production';
export const sessionCookieName = (): string => (cookieSecure() ? '__Host-ops_session' : 'ops_session');
export const mfaCookieName = (): string => (cookieSecure() ? '__Host-ops_mfa' : 'ops_mfa');

// Cuántos proxies de confianza hay DELANTE de esta aplicación (balanceador, CDN…). 0 = expuesta directamente: se ignora X-Forwarded-For
export const trustedProxyHops = (): number => {
  const n = Number(process.env.WEB_TRUST_PROXY_HOPS);
  return Number.isInteger(n) && n >= 0 ? n : 1;
};

export const upstreamTimeoutMs = (): number => Number(process.env.OPS_API_TIMEOUT_MS) || 10_000;
