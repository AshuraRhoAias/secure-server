import { allowedMethods, upstreamPath } from './allowlist';
import { sessionCookieName, mfaCookieName } from './config';
import { csrfOk } from './csrf';
import { decodeAccessToken } from './jwt';
import {
  clearMfaCookie, clearSessionCookie, mfaCookie, readMfaChallenge, readSession, sessionCookie, sessionFromTokens,
  type CookieSpec, type Session
} from './session';
import { callApi, parseJson, refreshSession, type UpstreamResult } from './upstream';

// Núcleo del BFF (backend-for-frontend), separado de las rutas de Next para poder probarlo sin servidor.
//
// El navegador habla SOLO con esta aplicación (mismo origen, cookie httpOnly cifrada); esta aplicación habla con el API con el
// Bearer. Resultado: los tokens no están al alcance del JavaScript de la página y no hay CORS que abrir.

const json = (status: number, body: unknown, cookies: CookieSpec[] = [], extra: HeadersInit = {}): Response => {
  const headers = new Headers({ 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...extra });
  const response = new Response(JSON.stringify(body), { status, headers });
  for (const cookie of cookies) response.headers.append('Set-Cookie', serializeCookie(cookie));
  return response;
};

export function serializeCookie({ name, value, options }: CookieSpec): string {
  const parts = [`${name}=${value}`, `Path=${options.path}`, `Max-Age=${options.maxAge}`, 'HttpOnly', 'SameSite=Strict'];
  if (options.secure) parts.push('Secure');
  return parts.join('; ');
}

const cookieValue = (request: Request, name: string): string | undefined => {
  const header = request.headers.get('cookie');
  if (!header) return undefined;
  for (const part of header.split(';')) {
    const index = part.indexOf('=');
    if (index > 0 && part.slice(0, index).trim() === name) return part.slice(index + 1).trim();
  }
  return undefined;
};

export const sessionFrom = (request: Request): Session | null => readSession(cookieValue(request, sessionCookieName()));

const forbidden = () => json(403, { success: false, message: 'Solicitud no permitida', code: 'CSRF' });
const noSession = (cookies: CookieSpec[] = []) => json(401, { success: false, message: 'Inicia sesión', code: 'NO_SESSION' }, cookies);

// ---------------------------------------------------------------- datos: /bff/...
export async function proxyData(request: Request, segments: string[], query: string): Promise<Response> {
  const method = request.method.toUpperCase();
  if (!allowedMethods(method)) return json(405, { success: false, message: 'Método no permitido' });
  const path = upstreamPath(method, segments);
  if (!path) return json(404, { success: false, message: 'Ruta no encontrada', code: 'NOT_FOUND' });
  if (!csrfOk(method, request.headers)) return forbidden();

  let session = sessionFrom(request);
  if (!session) return noSession([clearSessionCookie()]);

  let body: string | undefined;
  if (method === 'POST') {
    body = await request.text();
    if (body.length > 64 * 1024) return json(413, { success: false, message: 'Cuerpo demasiado grande' });
    if (body && !parseJson(body)) return json(400, { success: false, message: 'JSON no válido', code: 'VALIDATION_ERROR' });
  }

  let renewed = false;
  const renew = async (): Promise<Response | null> => {
    const outcome = await refreshSession(session as Session, request.headers);
    if (!outcome.ok) {
      // 409: otra pestaña/instancia renovó a la vez; el navegador ya tendrá (o tendrá enseguida) la cookie nueva: que reintente
      if (outcome.status === 409) return json(409, { success: false, message: 'La sesión se está renovando: reintenta', code: 'REFRESH_CONFLICT' });
      return noSession([clearSessionCookie()]);
    }
    session = outcome.session;
    renewed = true;
    return null;
  };

  // Renovación PREVENTIVA: el token de acceso caduca en menos de 20 s
  if (session.ae - Date.now() < 20_000) {
    const failure = await renew();
    if (failure) return failure;
  }

  const send = (): Promise<UpstreamResult> => callApi(path, { method, token: (session as Session).at, text: body, headers: request.headers, query: query.replace(/^\?/, '') });

  let result: UpstreamResult;
  try {
    result = await send();
    if (result.status === 401 && !renewed) {
      const failure = await renew();
      if (failure) return failure;
      result = await send();
    }
  } catch {
    return json(502, { success: false, message: 'El API no responde', code: 'UPSTREAM_UNAVAILABLE' });
  }

  const response = new Response(result.body, {
    status: result.status,
    headers: {
      'Content-Type': result.contentType.split(';')[0]?.trim() === 'application/json' ? 'application/json' : 'text/plain; charset=utf-8',
      'Cache-Control': 'no-store',
      ...(result.retryAfter && { 'Retry-After': result.retryAfter }),
      ...(result.requestId && { 'X-Request-Id': result.requestId })
    }
  });
  if (result.status === 401) response.headers.append('Set-Cookie', serializeCookie(clearSessionCookie()));
  else if (renewed) response.headers.append('Set-Cookie', serializeCookie(sessionCookie(session)));
  return response;
}

// ---------------------------------------------------------------- inicio de sesión
interface CompleteResult { response: Response }

// Entrega tokens → comprueba que el usuario es ADMINISTRADOR (la interfaz es solo para ellos) → cookie de sesión
async function completeLogin(request: Request, body: Record<string, unknown>): Promise<CompleteResult> {
  const claims = typeof body.token === 'string' ? decodeAccessToken(body.token) : null;
  const session = claims ? sessionFromTokens(body, { u: claims.username, uid: claims.userId }) : null;
  if (!session) return { response: json(502, { success: false, message: 'Respuesta inesperada del API', code: 'BAD_UPSTREAM' }) };

  // dashboard:read es solo de admin: si lo permite, es admin (y si exige MFA y no se usó, lo dirá el API con 403 MFA_REQUIRED)
  const probe = await callApi('/api/system/dashboard', { method: 'GET', token: session.at, query: 'hours=1', headers: request.headers });
  if (probe.status !== 200) {
    await callApi('/api/auth/logout', { method: 'POST', token: session.at, text: '{}', headers: request.headers }).catch(() => undefined);
    const code = parseJson(probe.body)?.code;
    if (probe.status === 403 && code === 'MFA_REQUIRED') {
      return { response: json(403, { success: false, message: 'Los administradores necesitan autenticación en dos pasos: activa TOTP o una passkey', code: 'MFA_REQUIRED' }, [clearMfaCookie()]) };
    }
    return { response: json(403, { success: false, message: 'Esta interfaz es solo para administradores', code: 'NOT_ADMIN' }, [clearMfaCookie()]) };
  }
  return { response: json(200, { success: true, user: session.u, sessionExpiresAt: new Date(session.se).toISOString() }, [sessionCookie(session), clearMfaCookie()]) };
}

const upstreamError = (result: UpstreamResult): Response => {
  const body = parseJson(result.body);
  const status = result.status >= 400 && result.status < 600 ? result.status : 502;
  return json(status, {
    success: false,
    message: typeof body?.message === 'string' ? body.message : 'No se pudo iniciar sesión',
    code: typeof body?.code === 'string' ? body.code : 'LOGIN_FAILED',
    ...(typeof body?.retryAfter === 'number' && { retryAfter: body.retryAfter })
  }, [], result.retryAfter ? { 'Retry-After': result.retryAfter } : {});
};

export async function login(request: Request): Promise<Response> {
  if (!csrfOk('POST', request.headers)) return forbidden();
  const input = parseJson(await request.text().catch(() => ''));
  const username = input?.username, password = input?.password;
  if (typeof username !== 'string' || typeof password !== 'string' || !username || !password || username.length > 64 || password.length > 128) {
    return json(400, { success: false, message: 'Usuario y contraseña son obligatorios', code: 'VALIDATION_ERROR' });
  }
  let result: UpstreamResult;
  try { result = await callApi('/api/auth/login', { method: 'POST', json: { username, password }, headers: request.headers }); }
  catch { return json(502, { success: false, message: 'El API no responde', code: 'UPSTREAM_UNAVAILABLE' }); }

  const body = parseJson(result.body);
  if (result.status !== 200 || !body) return upstreamError(result);

  if (body.mfaRequired === true && typeof body.mfaToken === 'string') {
    // El reto de MFA (5 min) no pasa por JavaScript: va a una cookie httpOnly cifrada
    const methods = Array.isArray(body.methods) ? body.methods.filter((m): m is string => typeof m === 'string') : ['otp', 'recovery'];
    return json(200, { success: true, mfaRequired: true, methods }, [mfaCookie({ token: body.mfaToken, u: username.slice(0, 64) })]);
  }
  return (await completeLogin(request, body)).response;
}

export async function loginMfa(request: Request): Promise<Response> {
  if (!csrfOk('POST', request.headers)) return forbidden();
  const challenge = readMfaChallenge(cookieValue(request, mfaCookieName()));
  if (!challenge) return json(401, { success: false, message: 'El paso anterior caducó: vuelve a escribir usuario y contraseña', code: 'MFA_EXPIRED' }, [clearMfaCookie()]);

  const input = parseJson(await request.text().catch(() => ''));
  const otp = typeof input?.otp === 'string' ? input.otp.trim() : '';
  const recoveryCode = typeof input?.recoveryCode === 'string' ? input.recoveryCode.trim() : '';
  if ((otp ? 1 : 0) + (recoveryCode ? 1 : 0) !== 1 || otp.length > 8 || recoveryCode.length > 40) {
    return json(400, { success: false, message: 'Escribe el código de 6 dígitos o un código de recuperación', code: 'VALIDATION_ERROR' });
  }

  let result: UpstreamResult;
  try {
    result = await callApi('/api/auth/login/mfa', { method: 'POST', json: { mfaToken: challenge.token, ...(otp ? { otp } : { recoveryCode }) }, headers: request.headers });
  } catch { return json(502, { success: false, message: 'El API no responde', code: 'UPSTREAM_UNAVAILABLE' }); }

  const body = parseJson(result.body);
  if (result.status !== 200 || !body) return upstreamError(result);
  return (await completeLogin(request, body)).response;
}

export async function logout(request: Request): Promise<Response> {
  if (!csrfOk('POST', request.headers)) return forbidden();
  const session = sessionFrom(request);
  if (session) await callApi('/api/auth/logout', { method: 'POST', token: session.at, text: '{}', headers: request.headers }).catch(() => undefined);
  return json(200, { success: true }, [clearSessionCookie(), clearMfaCookie()]);
}

export function me(request: Request): Response {
  const session = sessionFrom(request);
  if (!session) return noSession();
  return json(200, { success: true, user: session.u, userId: session.uid, sessionExpiresAt: new Date(session.se).toISOString(), accessExpiresAt: new Date(session.ae).toISOString() });
}
