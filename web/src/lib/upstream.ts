import { apiBase, upstreamTimeoutMs } from './config';
import { clientIp } from './client-ip';
import { decodeAccessToken } from './jwt';
import { sessionFromTokens, type Session } from './session';

export interface UpstreamResult { status: number; body: string; contentType: string; retryAfter: string | null; requestId: string | null }

// Llamada al API. Las cabeceras que se envían son SIEMPRE las que decide esta función (nunca las del navegador): así el navegador no
// puede añadir X-Forwarded-For, Authorization ni nada más. La IP real del cliente va en X-Forwarded-For (el API debe tener TRUST_PROXY).
export async function callApi(path: string, init: { method: string; token?: string; json?: unknown; text?: string; headers?: Headers; query?: string }): Promise<UpstreamResult> {
  const base = apiBase();
  const url = new URL(path + (init.query ? `?${init.query}` : ''), base);
  if (url.origin !== base.origin) throw new Error('destino fuera del API configurado');

  const headers: Record<string, string> = { Accept: 'application/json, text/plain' };
  if (init.token) headers.Authorization = `Bearer ${init.token}`;
  const ip = init.headers ? clientIp(init.headers) : null;
  if (ip) headers['X-Forwarded-For'] = ip;
  const ua = init.headers?.get('user-agent');
  if (ua) headers['User-Agent'] = ua.slice(0, 300);

  let body: string | undefined;
  if (init.json !== undefined) { body = JSON.stringify(init.json); headers['Content-Type'] = 'application/json'; }
  else if (init.text !== undefined) { body = init.text; headers['Content-Type'] = 'application/json'; }

  const response = await fetch(url, { method: init.method, headers, body, redirect: 'manual', cache: 'no-store', signal: AbortSignal.timeout(upstreamTimeoutMs()) });
  return {
    status: response.status,
    body: await response.text(),
    contentType: response.headers.get('content-type') || 'application/json',
    retryAfter: response.headers.get('retry-after'),
    requestId: response.headers.get('x-request-id')
  };
}

export const parseJson = (text: string): Record<string, unknown> | null => {
  try { const value = JSON.parse(text) as unknown; return value && typeof value === 'object' && !Array.isArray(value) ? (value as Record<string, unknown>) : null; } catch { return null; }
};

// ---------------------------------------------------------------- renovación de la sesión
// Varias peticiones del navegador pueden llegar a la vez con la MISMA cookie caducada (el panel pide tres cosas al cargar). Si cada
// una renovara por su cuenta, la segunda presentaría un refresh token ya gastado. Dentro de este proceso se comparte UNA renovación por
// refresh token. Con varias instancias de la web, una renovación puede perder la carrera: el API responde 409 REFRESH_CONFLICT sin
// revocar nada y el cliente reintenta (ya con la cookie nueva que le entregó la otra instancia).
export type RefreshOutcome = { ok: true; session: Session } | { ok: false; status: number; code: string };
const inflight = new Map<string, Promise<RefreshOutcome>>();

export function refreshSession(session: Session, headers?: Headers): Promise<RefreshOutcome> {
  const existing = inflight.get(session.rt);
  if (existing) return existing;

  const task = (async (): Promise<RefreshOutcome> => {
    try {
      const result = await callApi('/api/auth/refresh', { method: 'POST', json: { refreshToken: session.rt }, headers });
      const body = parseJson(result.body);
      if (result.status !== 200 || !body) return { ok: false, status: result.status, code: typeof body?.code === 'string' ? body.code : 'REFRESH_FAILED' };
      const claims = typeof body.token === 'string' ? decodeAccessToken(body.token) : null;
      const next = sessionFromTokens(body, { u: claims?.username ?? session.u, uid: claims?.userId ?? session.uid });
      if (!next) return { ok: false, status: 502, code: 'BAD_UPSTREAM' };
      next.se = Math.min(next.se, session.se); // el tope absoluto nunca se alarga
      return { ok: true, session: next };
    } catch {
      return { ok: false, status: 502, code: 'UPSTREAM_UNAVAILABLE' };
    } finally {
      setTimeout(() => inflight.delete(session.rt), 15_000).unref?.(); // el resultado se comparte unos segundos y luego se olvida
    }
  })();
  inflight.set(session.rt, task);
  return task;
}
