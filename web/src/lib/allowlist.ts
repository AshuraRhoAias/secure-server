// Lista CERRADA de rutas del API que el BFF reenvía. No es un proxy abierto: lo que no esté aquí no existe para el navegador
// (p. ej. rotar claves, o cualquier ruta nueva del API, hasta que se añada a propósito).
type Method = 'GET' | 'POST' | 'DELETE';

const RULES: ReadonlyArray<{ method: Method; path: RegExp }> = [
  { method: 'GET', path: /^\/api\/system\/(status|rotation|blocked-ips|security-events|security-summary|approvals|alerts|dashboard)$/ },
  { method: 'GET', path: /^\/api\/system\/logs$/ },
  { method: 'GET', path: /^\/api\/metrics$/ },
  { method: 'DELETE', path: /^\/api\/system\/blocked-ips\/[0-9a-fA-F:.]{1,45}$/ },
  { method: 'POST', path: /^\/api\/system\/accounts\/(unlock|mfa-reset)$/ },
  { method: 'POST', path: /^\/api\/system\/approvals\/[1-9]\d{0,9}\/(approve|reject)$/ },
  { method: 'POST', path: /^\/api\/system\/alerts\/evaluate$/ },
  { method: 'POST', path: /^\/api\/system\/alerts\/[1-9]\d{0,9}\/(ack|resolve)$/ },
  { method: 'GET', path: /^\/api\/system\/users\/[1-9]\d{0,9}\/export$/ },
  { method: 'POST', path: /^\/api\/system\/users\/[1-9]\d{0,9}\/(erase|revoke-sessions)$/ },
  { method: 'POST', path: /^\/api\/system\/sessions\/revoke-all$/ },
  { method: 'POST', path: /^\/api\/system\/(integrity-check|test-communications)$/ }
];

export const allowedMethods = (method: string): method is Method => method === 'GET' || method === 'POST' || method === 'DELETE';

// segments: partes de la ruta ya separadas (params.path). Devuelve la ruta del API o null si no está permitida.
export function upstreamPath(method: string, segments: string[]): string | null {
  if (!allowedMethods(method) || segments.length === 0 || segments.length > 6) return null;
  // Cada segmento llega decodificado por Next: se rechazan los que intentan salir del árbol o esconder separadores
  if (segments.some(s => s === '' || s === '.' || s === '..' || /[\\/\u0000-\u001f%?#]/.test(s))) return null;
  const path = `/${segments.join('/')}`;
  return RULES.some(rule => rule.method === method && rule.path.test(path)) ? path : null;
}
