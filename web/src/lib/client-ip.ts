import { trustedProxyHops } from './config';

// IP REAL del cliente para el API (límites de peticiones y bloqueos por IP). X-Forwarded-For lo escribe cada proxy añadiendo la IP que
// vio; solo se puede confiar en lo que añaden NUESTROS proxies (los últimos N saltos), no en lo que el cliente puso al principio.
// Con WEB_TRUST_PROXY_HOPS=0 (aplicación expuesta directamente) se ignora la cabecera: el API verá la IP de esta aplicación.
const IPV4 = /^(?:\d{1,3}\.){3}\d{1,3}$/;
const IPV6 = /^[0-9a-fA-F:.]+$/;

export function clientIp(headers: Headers): string | null {
  const hops = trustedProxyHops();
  if (hops === 0) return null;
  const chain = (headers.get('x-forwarded-for') || '').split(',').map(part => part.trim()).filter(Boolean);
  if (chain.length === 0) return null;
  const candidate = chain[Math.max(0, chain.length - hops)] as string;
  const valid = candidate.length <= 45 && (IPV4.test(candidate) || (candidate.includes(':') && IPV6.test(candidate)));
  return valid ? candidate : null;
}
