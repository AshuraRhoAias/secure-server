import { createHash } from 'node:crypto';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { login } from './bff';
import { mfaCookieName, sessionCookieName, ssoCookieName } from './config';
import { passkeyLogin, passkeyOptions } from './passkey';
import { seal, unseal } from './seal';
import type { Session, SsoStart } from './session';
import { ssoCallback, ssoStart, ssoStatus } from './sso';
import { proxyStream } from './stream';

// API simulado: lo justo para SSO por código de entrega, passkey como segundo factor y el stream en vivo.
const jwt = (claims: object) => `h.${Buffer.from(JSON.stringify(claims)).toString('base64url')}.s`;
const state = {
  counter: 0, admin: new Set<string>(), valid: new Set<string>(), refresh: new Set<string>(), logoutCalls: 0,
  seen: [] as { path: string; query: string; headers: http.IncomingHttpHeaders; body: string }[],
  handoffs: new Map<string, { challenge: string; user: string }>(), lastChallenge: '', samlEnabled: false, streamStatus: 200
};
function issue(user: string) {
  const n = ++state.counter;
  const token = jwt({ userId: user === 'admin' ? 7 : 8, username: user, n });
  state.valid.add(token);
  state.refresh.add(`rt_${n}`);
  if (user === 'admin') state.admin.add(token);
  return { success: true, token, refreshToken: `rt_${n}`, expiresIn: 900, expiresAt: new Date(Date.now() + 900_000).toISOString(), sessionExpiresAt: new Date(Date.now() + 86_400_000).toISOString() };
}

let server: http.Server;
let base = '';
beforeAll(async () => {
  server = http.createServer((req, res) => {
    let body = '';
    req.on('data', c => { body += c; });
    req.on('end', () => {
      const [path = '', query = ''] = (req.url || '').split('?');
      state.seen.push({ path, query, headers: req.headers, body });
      const send = (status: number, payload: unknown) => { res.writeHead(status, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(payload)); };
      const input = body ? JSON.parse(body) : {};
      const auth = (req.headers.authorization || '').replace('Bearer ', '');
      const params = new URLSearchParams(query);

      if (path === '/api/auth/login') {
        if (input.username === 'pk') return send(200, { success: true, mfaRequired: true, mfaToken: 'MFA-PK', methods: ['webauthn', 'recovery'] });
        return send(401, { success: false, code: 'INVALID_CREDENTIALS', message: 'no' });
      }
      if (path === '/api/auth/login/webauthn/options') {
        if (input.mfaToken !== 'MFA-PK') return send(401, { success: false, code: 'INVALID_MFA_TOKEN', message: 'reto no válido' });
        return send(200, { success: true, options: { challenge: 'Y2hhbGxlbmdl', rpId: 'ops.test', allowCredentials: [{ id: 'Y3JlZA', type: 'public-key' }], timeout: 60000, userVerification: 'preferred' } });
      }
      if (path === '/api/auth/login/webauthn') {
        if (input.mfaToken === 'MFA-PK' && input.credential?.id === 'cred-ok') return send(200, issue('admin'));
        return send(401, { success: false, code: 'WEBAUTHN_FAILED', message: 'firma no válida' });
      }
      if (path === '/api/sso/status') return send(200, { success: true, enabled: true, provider: 'oidc' });
      if (path === '/api/saml/status') return send(200, { success: true, enabled: state.samlEnabled, provider: 'saml' });
      if (path === '/api/sso/login' || path === '/api/saml/login') {
        state.lastChallenge = params.get('handoff') || '';
        if (params.get('format') !== 'json' || !/^[A-Za-z0-9_-]{43}$/.test(state.lastChallenge)) return send(400, { success: false, code: 'VALIDATION_ERROR', message: 'mal' });
        return send(200, { success: true, url: `https://idp.example/authorize?from=${path.includes('saml') ? 'saml' : 'oidc'}` });
      }
      if (path === '/api/sso/exchange') {
        const handoff = state.handoffs.get(input.code);
        state.handoffs.delete(input.code);
        const challenge = createHash('sha256').update(String(input.verifier)).digest('base64url');
        if (!handoff || handoff.challenge !== challenge) return send(401, { success: false, code: 'SSO_HANDOFF_INVALID', message: 'caducó' });
        return send(200, issue(handoff.user));
      }
      if (path === '/api/auth/refresh') {
        if (!state.refresh.has(input.refreshToken)) return send(401, { success: false, code: 'INVALID_REFRESH_TOKEN', message: 'no' });
        state.refresh.delete(input.refreshToken);
        return send(200, issue('admin'));
      }
      if (path === '/api/auth/logout') { state.logoutCalls++; return send(200, { success: true }); }
      if (!state.valid.has(auth)) return send(401, { success: false, code: 'INVALID_TOKEN', message: 'no' });
      if (path === '/api/system/dashboard') return state.admin.has(auth) ? send(200, { success: true }) : send(403, { success: false, code: 'FORBIDDEN', message: 'no' });
      if (path === '/api/system/stream') {
        if (state.streamStatus !== 200) { res.writeHead(state.streamStatus, { 'Content-Type': 'application/json', 'Retry-After': '30' }); return res.end(JSON.stringify({ success: false, code: 'STREAM_LIMIT' })); }
        res.writeHead(200, { 'Content-Type': 'text/event-stream; charset=utf-8' });
        res.write('retry: 5000\n\n');
        res.write(`id: e5.a2\nevent: hello\ndata: {"lastEventId":${JSON.stringify(req.headers['last-event-id'] ?? null)}}\n\n`);
        return setTimeout(() => res.end('event: alert\ndata: {"id":3,"severity":"critical"}\n\n'), 20);
      }
      return send(404, { success: false });
    });
  });
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});
afterAll(() => new Promise<void>(resolve => server.close(() => resolve())));

beforeEach(() => {
  process.env.WEB_SESSION_SECRET = 's'.repeat(40);
  process.env.OPS_API_URL = base;
  process.env.WEB_COOKIE_SECURE = 'false';
  process.env.WEB_ORIGIN = 'http://ops.test';
  Object.assign(state, { seen: [], logoutCalls: 0, samlEnabled: false, streamStatus: 200 });
});

const post = (url: string, body: unknown, headers: Record<string, string> = {}) =>
  new Request(`http://ops.test${url}`, { method: 'POST', body: typeof body === 'string' ? body : JSON.stringify(body), headers: { origin: 'http://ops.test', 'x-ops-csrf': '1', 'content-type': 'application/json', ...headers } });
const get = (url: string, headers: Record<string, string> = {}) => new Request(`http://ops.test${url}`, { headers });
const setCookie = (response: Response, name: string) => response.headers.getSetCookie().find(c => c.startsWith(`${name}=`));
const cookieOf = (response: Response, name: string) => setCookie(response, name)?.split(';')[0]?.slice(name.length + 1);
const seen = (path: string) => state.seen.filter(s => s.path === path);

// ============================================================================ SSO
describe('SSO por código de entrega (sin tokens en el navegador)', () => {
  async function start(provider = 'oidc', headers: Record<string, string> = { 'sec-fetch-site': 'same-origin' }) {
    const response = await ssoStart(get(`/session/sso/start?provider=${provider}`, headers));
    return { response, cookie: cookieOf(response, ssoCookieName()) };
  }

  it('start: verificador en cookie httpOnly cifrada SameSite=Lax; al API solo va sha256(verificador); 302 al proveedor', async () => {
    const { response, cookie } = await start();
    expect(response.status).toBe(302);
    expect(response.headers.get('location')).toBe('https://idp.example/authorize?from=oidc');
    const header = setCookie(response, ssoCookieName()) as string;
    expect(header).toMatch(/HttpOnly/);
    expect(header).toMatch(/SameSite=Lax/);
    const sealed = unseal<SsoStart>(cookie, 'sso') as SsoStart;
    expect(sealed.p).toBe('oidc');
    expect(sealed.v).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(state.lastChallenge).toBe(createHash('sha256').update(sealed.v).digest('base64url'));
    expect(seen('/api/sso/login')[0]?.query).not.toContain(sealed.v);
  });

  it('start: no se puede empezar desde otro sitio ni con un proveedor inventado', async () => {
    const cross = await start('oidc', { 'sec-fetch-site': 'cross-site' });
    expect(cross.response.headers.get('location')).toBe('/login?sso_error=SSO_FORBIDDEN');
    expect(cross.cookie).toBeUndefined();
    const bad = await start('ldap');
    expect(bad.response.headers.get('location')).toBe('/login?sso_error=SSO_BAD_PROVIDER');
    expect(seen('/api/sso/login')).toHaveLength(0);
  });

  it('callback: canjea código + verificador, comprueba admin y entrega la sesión con una página que navega sola (sin tokens)', async () => {
    const { cookie } = await start('saml');
    const verifier = (unseal<SsoStart>(cookie, 'sso') as SsoStart).v;
    const code = 'C'.repeat(43);
    state.handoffs.set(code, { challenge: createHash('sha256').update(verifier).digest('base64url'), user: 'admin' });

    const response = await ssoCallback(get(`/session/sso/callback?code=${code}`, { cookie: `${ssoCookieName()}=${cookie}` }));
    expect(response.status).toBe(200);
    const html = await response.text();
    expect(html).toContain('<meta http-equiv="refresh" content="0;url=/">');
    expect(html).not.toMatch(/h\.|rt_|token/i);
    expect(response.headers.get('content-security-policy')).toContain("default-src 'none'");
    expect(setCookie(response, sessionCookieName())).toMatch(/SameSite=Strict/);
    expect(setCookie(response, ssoCookieName())).toMatch(/Max-Age=0/);
    expect(JSON.parse(seen('/api/sso/exchange')[0]?.body as string)).toEqual({ code, verifier });
  });

  it('callback: sin la cookie del navegador que empezó, el código no se canjea', async () => {
    const response = await ssoCallback(get(`/session/sso/callback?code=${'D'.repeat(43)}`));
    expect(await response.text()).toContain('url=/login?sso_error=SSO_EXPIRED');
    expect(seen('/api/sso/exchange')).toHaveLength(0);
    expect(setCookie(response, sessionCookieName())).toBeUndefined();
  });

  it('callback: código con otro verificador → error y sin sesión; código con formato raro → ni se llama al API', async () => {
    const { cookie } = await start();
    state.handoffs.set('E'.repeat(43), { challenge: 'x'.repeat(43), user: 'admin' });
    const wrong = await ssoCallback(get(`/session/sso/callback?code=${'E'.repeat(43)}`, { cookie: `${ssoCookieName()}=${cookie}` }));
    expect(await wrong.text()).toContain('sso_error=SSO_HANDOFF_INVALID');
    expect(setCookie(wrong, sessionCookieName())).toBeUndefined();

    const odd = await ssoCallback(get('/session/sso/callback?code=../../x', { cookie: `${ssoCookieName()}=${cookie}` }));
    expect(await odd.text()).toContain('sso_error=SSO_BAD_CALLBACK');
    expect(seen('/api/sso/exchange')).toHaveLength(1);
  });

  it('callback: un usuario que no es admin no entra y su sesión se cierra en el API', async () => {
    const { cookie } = await start();
    const verifier = (unseal<SsoStart>(cookie, 'sso') as SsoStart).v;
    state.handoffs.set('F'.repeat(43), { challenge: createHash('sha256').update(verifier).digest('base64url'), user: 'plain' });
    const response = await ssoCallback(get(`/session/sso/callback?code=${'F'.repeat(43)}`, { cookie: `${ssoCookieName()}=${cookie}` }));
    expect(await response.text()).toContain('sso_error=NOT_ADMIN');
    expect(setCookie(response, sessionCookieName())).toBeUndefined();
    expect(state.logoutCalls).toBe(1);
  });

  it('status: qué proveedores están activos', async () => {
    state.samlEnabled = true;
    expect(await (await ssoStatus(get('/session/sso/status'))).json()).toEqual({ success: true, oidc: true, saml: true });
  });
});

// ============================================================================ Passkey
describe('passkey como segundo factor', () => {
  async function mfaCookie() {
    const response = await login(post('/session/login', { username: 'pk', password: 'x' }));
    expect(await response.json()).toMatchObject({ mfaRequired: true, methods: ['webauthn', 'recovery'] });
    return `${mfaCookieName()}=${cookieOf(response, mfaCookieName())}`;
  }

  it('opciones: usan el reto MFA de la cookie (el navegador nunca ve el mfaToken); sin reto → MFA_EXPIRED; sin CSRF → 403', async () => {
    const cookie = await mfaCookie();
    const response = await passkeyOptions(post('/session/webauthn/options', {}, { cookie }));
    const body = await response.json();
    expect(body.options.challenge).toBe('Y2hhbGxlbmdl');
    expect(JSON.stringify(body)).not.toContain('MFA-PK');
    expect(JSON.parse(seen('/api/auth/login/webauthn/options')[0]?.body as string).mfaToken).toBe('MFA-PK');

    expect((await passkeyOptions(post('/session/webauthn/options', {}))).status).toBe(401);
    expect((await passkeyOptions(new Request('http://ops.test/session/webauthn/options', { method: 'POST', headers: { cookie } }))).status).toBe(403);
  });

  it('firma correcta → sesión de admin; firma mala → error del API; vacía o enorme → 400/413', async () => {
    const cookie = await mfaCookie();
    const ok = await passkeyLogin(post('/session/webauthn', { credential: { id: 'cred-ok', response: {} } }, { cookie }));
    expect(ok.status).toBe(200);
    expect(setCookie(ok, sessionCookieName())).toBeTruthy();
    expect(setCookie(ok, mfaCookieName())).toMatch(/Max-Age=0/);

    const bad = await passkeyLogin(post('/session/webauthn', { credential: { id: 'otra' } }, { cookie }));
    expect(bad.status).toBe(401);
    expect((await passkeyLogin(post('/session/webauthn', {}, { cookie }))).status).toBe(400);
    expect((await passkeyLogin(post('/session/webauthn', { credential: { x: 'a'.repeat(20_000) } }, { cookie }))).status).toBe(413);
  });
});

// ============================================================================ Stream en vivo
describe('relevo del stream (Server-Sent Events)', () => {
  function sessionCookie(overrides: Partial<Session> = {}) {
    const issued = issue('admin');
    const session: Session = { at: issued.token, rt: issued.refreshToken, ae: Date.now() + 900_000, se: Date.now() + 86_400_000, u: 'admin', uid: 7, ...overrides };
    return `${sessionCookieName()}=${seal(session, 'session', 86_400_000)}`;
  }

  it('sin sesión → 401', async () => {
    expect((await proxyStream(get('/bff/stream'))).status).toBe(401);
  });

  it('reenvía el stream tal cual con el Bearer de la sesión; Last-Event-ID válido pasa, uno inventado no', async () => {
    const response = await proxyStream(get('/bff/stream', { cookie: sessionCookie(), 'last-event-id': 'e10.a4' }));
    expect(response.status).toBe(200);
    expect(response.headers.get('content-type')).toContain('text/event-stream');
    const text = await response.text();
    expect(text).toContain('event: hello');
    expect(text).toContain('"lastEventId":"e10.a4"');
    expect(text).toContain('event: alert');
    expect(seen('/api/system/stream')[0]?.headers.authorization).toMatch(/^Bearer h\./);

    await (await proxyStream(get('/bff/stream', { cookie: sessionCookie(), 'last-event-id': '"><script>' }))).text();
    expect(seen('/api/system/stream')[1]?.headers['last-event-id']).toBeUndefined();
  });

  it('si al token le queda poco, renueva ANTES de abrir y entrega la cookie nueva en la respuesta del stream', async () => {
    const response = await proxyStream(get('/bff/stream', { cookie: sessionCookie({ ae: Date.now() + 10_000 }) }));
    expect(response.status).toBe(200);
    await response.text();
    expect(seen('/api/auth/refresh')).toHaveLength(1);
    expect(setCookie(response, sessionCookieName())).toBeTruthy();
  });

  it('token rechazado por el API → renueva una vez y reintenta', async () => {
    const response = await proxyStream(get('/bff/stream', { cookie: sessionCookie({ at: 'h.caducado.s' }) }));
    expect(response.status).toBe(200);
    await response.text();
    expect(seen('/api/system/stream')).toHaveLength(2);
  });

  it('un error del API (429 STREAM_LIMIT) se devuelve como tal, con Retry-After', async () => {
    state.streamStatus = 429;
    const response = await proxyStream(get('/bff/stream', { cookie: sessionCookie() }));
    expect(response.status).toBe(429);
    expect(response.headers.get('retry-after')).toBe('30');
    expect((await response.json()).code).toBe('STREAM_LIMIT');
  });
});
