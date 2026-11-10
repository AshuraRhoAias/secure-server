import { apiBase } from './config';
import { clientIp } from './client-ip';
import { clearSessionCookie, sessionCookie, type Session } from './session';
import { json, serializeCookie, sessionFrom } from './bff';
import { refreshSession } from './upstream';

// GET /bff/stream → GET /api/system/stream (Server-Sent Events) con el Bearer de la sesión.
//
// El cuerpo del API se reenvía TAL CUAL, trozo a trozo (no se acumula). Al cerrarse la pestaña se aborta también la conexión con el
// API. El API cierra el stream cuando caduca el token de acceso (15 min): EventSource reconecta solo con Last-Event-ID y, en esa
// reconexión, este relevo renueva la sesión si le queda poco (la cookie nueva viaja en la respuesta del stream).

const RENEW_BEFORE_MS = 20_000; // igual que el proxy de datos; al caducar, el API cierra el stream y la reconexión renueva
const LAST_EVENT_ID = /^e\d{1,15}\.a\d{1,15}$/;
const SEVERITIES = new Set(['info', 'low', 'medium', 'high', 'critical']);

async function openUpstream(request: Request, session: Session): Promise<Response> {
  const base = apiBase();
  const url = new URL('/api/system/stream', base);
  const severity = new URL(request.url).searchParams.get('minSeverity');
  if (severity && SEVERITIES.has(severity)) url.searchParams.set('minSeverity', severity);

  const headers: Record<string, string> = { Accept: 'text/event-stream', Authorization: `Bearer ${session.at}` };
  const ip = clientIp(request.headers);
  if (ip) headers['X-Forwarded-For'] = ip;
  const ua = request.headers.get('user-agent');
  if (ua) headers['User-Agent'] = ua.slice(0, 300);
  const lastId = request.headers.get('last-event-id');
  if (lastId && LAST_EVENT_ID.test(lastId)) headers['Last-Event-ID'] = lastId;

  // Sin tiempo máximo (es una conexión larga): termina cuando el navegador se va o cuando el API la cierra
  return fetch(url, { method: 'GET', headers, redirect: 'manual', cache: 'no-store', signal: request.signal });
}

export async function proxyStream(request: Request): Promise<Response> {
  let session = sessionFrom(request);
  if (!session) return json(401, { success: false, message: 'Inicia sesión', code: 'NO_SESSION' }, [clearSessionCookie()]);

  let renewed = false;
  const renew = async (): Promise<Response | null> => {
    const outcome = await refreshSession(session as Session, request.headers);
    if (!outcome.ok) {
      if (outcome.status === 409) return json(409, { success: false, message: 'La sesión se está renovando: reintenta', code: 'REFRESH_CONFLICT' }, [], { 'Retry-After': '1' });
      return json(401, { success: false, message: 'Inicia sesión', code: 'NO_SESSION' }, [clearSessionCookie()]);
    }
    session = outcome.session;
    renewed = true;
    return null;
  };

  if (session.ae - Date.now() < RENEW_BEFORE_MS) {
    const failure = await renew();
    if (failure) return failure;
  }

  let upstream: Response;
  try {
    upstream = await openUpstream(request, session);
    if (upstream.status === 401 && !renewed) {
      await upstream.body?.cancel();
      const failure = await renew();
      if (failure) return failure;
      upstream = await openUpstream(request, session);
    }
  } catch {
    return json(502, { success: false, message: 'El API no responde', code: 'UPSTREAM_UNAVAILABLE' });
  }

  const type = upstream.headers.get('content-type') || '';
  if (upstream.status !== 200 || !type.startsWith('text/event-stream') || !upstream.body) {
    const text = await upstream.text().catch(() => '');
    const response = new Response(text || JSON.stringify({ success: false, message: `Error ${upstream.status}` }), {
      status: upstream.status === 200 ? 502 : upstream.status,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...(upstream.headers.get('retry-after') && { 'Retry-After': upstream.headers.get('retry-after') as string }) }
    });
    if (upstream.status === 401) response.headers.append('Set-Cookie', serializeCookie(clearSessionCookie()));
    return response;
  }

  const response = new Response(upstream.body, {
    status: 200,
    headers: { 'Content-Type': 'text/event-stream; charset=utf-8', 'Cache-Control': 'no-store, no-transform', 'X-Accel-Buffering': 'no' }
  });
  if (renewed) response.headers.append('Set-Cookie', serializeCookie(sessionCookie(session)));
  return response;
}
