import { createHash, randomBytes } from 'node:crypto';
import { ssoCookieName } from './config';
import { clearMfaCookie, clearSsoCookie, readSsoStart, sessionCookie, ssoCookie, type CookieSpec, type SsoStart } from './session';
import { cookieValue, establishSession, json, serializeCookie } from './bff';
import { callApi, parseJson } from './upstream';

// Inicio de sesión con SSO (OpenID Connect o SAML) desde la interfaz, SIN que los tokens pasen por el navegador.
//
//   GET /session/sso/start?provider=oidc|saml
//       verificador aleatorio (32 bytes) → cookie httpOnly cifrada (SameSite=Lax, 10 min);
//       el API registra sha256(verificador) y devuelve la URL del proveedor → 302 al proveedor
//   … el usuario se autentica en su proveedor; el API valida la respuesta y redirige a SSO_HANDOFF_URL (= /session/sso/callback)
//   GET /session/sso/callback?code=…
//       el BFF canjea code + verificador en POST /api/sso/exchange (servidor a servidor) → comprueba que es admin → cookie de sesión
//
// La página de vuelta NO redirige con 302: responde una página mínima que navega a "/" ella misma. Motivo: la cadena de
// redirecciones empezó en OTRO sitio (el proveedor), y en esa navegación el navegador no enviaría la cookie de sesión
// SameSite=Strict recién creada; una navegación iniciada por esta misma página sí la envía.

type Provider = SsoStart['p'];
const PROVIDERS: Record<Provider, string> = { oidc: '/api/sso', saml: '/api/saml' };

const redirect = (location: string, cookies: CookieSpec[] = []): Response => {
  const response = new Response(null, { status: 302, headers: { Location: location, 'Cache-Control': 'no-store' } });
  for (const cookie of cookies) response.headers.append('Set-Cookie', serializeCookie(cookie));
  return response;
};

// Página mínima de salida (sin scripts: la CSP de esta respuesta lo prohíbe todo salvo la navegación por meta refresh)
function landing(target: string, message: string, cookies: CookieSpec[]): Response {
  const safeTarget = target.startsWith('/') && !target.startsWith('//') ? target : '/login';
  const escaped = (s: string) => s.replace(/[&<>"']/g, c => `&#${c.charCodeAt(0)};`);
  const html = `<!doctype html><html lang="es"><head><meta charset="utf-8"><meta http-equiv="refresh" content="0;url=${escaped(safeTarget)}"><title>secure-server</title></head><body><p>${escaped(message)} <a href="${escaped(safeTarget)}">Continuar</a></p></body></html>`;
  const response = new Response(html, {
    status: 200,
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-store',
      'Content-Security-Policy': "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
      'Referrer-Policy': 'no-referrer'
    }
  });
  for (const cookie of cookies) response.headers.append('Set-Cookie', serializeCookie(cookie));
  return response;
}

const failTo = (code: string) => `/login?sso_error=${encodeURIComponent(code)}`;

export async function ssoStatus(request: Request): Promise<Response> {
  const probe = async (base: string): Promise<boolean> => {
    try {
      const result = await callApi(`${base}/status`, { method: 'GET', headers: request.headers });
      return result.status === 200 && parseJson(result.body)?.enabled === true;
    } catch { return false; }
  };
  const [oidc, saml] = await Promise.all([probe(PROVIDERS.oidc), probe(PROVIDERS.saml)]);
  return json(200, { success: true, oidc, saml });
}

export async function ssoStart(request: Request): Promise<Response> {
  // Solo desde esta misma interfaz (el botón de /login). Un enlace desde otro sitio no puede empezar un login a nombre del usuario.
  const site = request.headers.get('sec-fetch-site');
  if (site && site !== 'same-origin' && site !== 'none') return redirect(failTo('SSO_FORBIDDEN'));

  const provider = new URL(request.url).searchParams.get('provider');
  if (provider !== 'oidc' && provider !== 'saml') return redirect(failTo('SSO_BAD_PROVIDER'));

  const verifier = randomBytes(32).toString('base64url');
  const challenge = createHash('sha256').update(verifier).digest('base64url');
  let target: string | null = null;
  let code = 'SSO_UNAVAILABLE';
  try {
    const result = await callApi(`${PROVIDERS[provider]}/login`, { method: 'GET', query: new URLSearchParams({ format: 'json', handoff: challenge }).toString(), headers: request.headers });
    const body = parseJson(result.body);
    if (result.status === 200 && typeof body?.url === 'string' && /^https?:\/\//.test(body.url)) target = body.url;
    else if (typeof body?.code === 'string') code = body.code;
  } catch { code = 'UPSTREAM_UNAVAILABLE'; }

  if (!target) return redirect(failTo(code), [clearSsoCookie()]);
  return redirect(target, [ssoCookie({ v: verifier, p: provider })]);
}

export async function ssoCallback(request: Request): Promise<Response> {
  const params = new URL(request.url).searchParams;
  const start = readSsoStart(cookieValue(request, ssoCookieName()));
  const clear = [clearSsoCookie()];
  if (!start) return landing(failTo('SSO_EXPIRED'), 'El inicio de sesión caducó.', clear);

  const code = params.get('code') ?? '';
  if (!/^[A-Za-z0-9_-]{43}$/.test(code)) return landing(failTo('SSO_BAD_CALLBACK'), 'Respuesta no válida.', clear);

  let body: Record<string, unknown> | null = null;
  let errorCode = 'SSO_FAILED';
  try {
    const result = await callApi('/api/sso/exchange', { method: 'POST', json: { code, verifier: start.v }, headers: request.headers });
    body = parseJson(result.body);
    if (result.status !== 200 || !body) { errorCode = typeof body?.code === 'string' ? body.code : 'SSO_FAILED'; body = null; }
  } catch { errorCode = 'UPSTREAM_UNAVAILABLE'; }
  if (!body) return landing(failTo(errorCode), 'No se pudo iniciar sesión.', clear);

  const outcome = await establishSession(request, body);
  if (!outcome.ok) return landing(failTo(outcome.code), outcome.message, [...clear, clearMfaCookie()]);
  return landing('/', 'Sesión iniciada.', [...clear, clearMfaCookie(), sessionCookie(outcome.session)]);
}
