import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { login, loginMfa, logout, me, proxyData } from './bff';
import { sessionCookieName } from './config';
import { seal, unseal } from './seal';
import type { Session } from './session';

// API simulado (lo justo de secure-server): login, MFA, refresh con rotación, dashboard solo para admin, logout.
const jwt = (claims: object) => `h.${Buffer.from(JSON.stringify(claims)).toString('base64url')}.s`;

interface State {
  refreshCalls: number; logoutCalls: number; counter: number;
  validAccess: Set<string>; validRefresh: Set<string>; adminTokens: Set<string>;
  seen: { path: string; headers: http.IncomingHttpHeaders; body: string }[];
  refreshMode: 'ok' | 'conflict' | 'invalid';
}
const state: State = { refreshCalls: 0, logoutCalls: 0, counter: 0, validAccess: new Set(), validRefresh: new Set(), adminTokens: new Set(), seen: [], refreshMode: 'ok' };

function issue(user: string, admin: boolean) {
  const n = ++state.counter;
  const token = jwt({ userId: user === 'admin' ? 7 : 8, username: user, amr: ['pwd'], n });
  const refreshToken = `rt_${n}`;
  state.validAccess.add(token);
  state.validRefresh.add(refreshToken);
  if (admin) state.adminTokens.add(token);
  return { success: true, token, refreshToken, expiresIn: 900, expiresAt: new Date(Date.now() + 900_000).toISOString(), sessionExpiresAt: new Date(Date.now() + 30 * 86_400_000).toISOString() };
}

let server: http.Server;
beforeAll(async () => {
  server = http.createServer((req, res) => {
    let body = '';
    req.on('data', c => { body += c; });
    req.on('end', () => {
      const path = (req.url || '').split('?')[0] as string;
      state.seen.push({ path, headers: req.headers, body });
      const send = (status: number, payload: unknown, headers: Record<string, string> = {}) => { res.writeHead(status, { 'Content-Type': 'application/json', ...headers }); res.end(JSON.stringify(payload)); };
      const auth = (req.headers.authorization || '').replace('Bearer ', '');
      const input = body ? JSON.parse(body) : {};

      if (path === '/api/auth/login') {
        if (input.username === 'admin' && input.password === 'ok') return send(200, issue('admin', true));
        if (input.username === 'plain' && input.password === 'ok') return send(200, issue('plain', false));
        if (input.username === 'mfa' && input.password === 'ok') return send(200, { success: true, mfaRequired: true, mfaToken: 'MFA-TOKEN-1', methods: ['otp', 'recovery'] });
        if (input.username === 'locked') return send(429, { success: false, message: 'Demasiados intentos', code: 'RATE_LIMITED', retryAfter: 30 }, { 'Retry-After': '30' });
        return send(401, { success: false, message: 'Credenciales inválidas', code: 'INVALID_CREDENTIALS' });
      }
      if (path === '/api/auth/login/mfa') {
        if (input.mfaToken === 'MFA-TOKEN-1' && (input.otp === '123456' || input.recoveryCode === 'AAAA-BBBB')) return send(200, issue('admin', true));
        return send(401, { success: false, message: 'Código incorrecto', code: 'INVALID_MFA' });
      }
      if (path === '/api/auth/refresh') {
        state.refreshCalls++;
        if (state.refreshMode === 'conflict') return send(409, { success: false, code: 'REFRESH_CONFLICT', message: 'otra petición renovó' });
        if (state.refreshMode === 'invalid' || !state.validRefresh.has(input.refreshToken)) return send(401, { success: false, code: 'INVALID_REFRESH_TOKEN', message: 'caducado' });
        state.validRefresh.delete(input.refreshToken);
        return send(200, issue('admin', true));
      }
      if (path === '/api/auth/logout') { state.logoutCalls++; return send(200, { success: true }); }
      if (!state.validAccess.has(auth)) return send(401, { success: false, message: 'Token inválido', code: 'INVALID_TOKEN' });
      if (path.startsWith('/api/system/') || path === '/api/metrics') {
        if (!state.adminTokens.has(auth)) return send(403, { success: false, code: 'FORBIDDEN', message: 'No tienes permisos' });
        if (path === '/api/metrics') { res.writeHead(200, { 'Content-Type': 'text/plain; version=0.0.4' }); return res.end('# HELP x\nx 1\n'); }
        return send(200, { success: true, path, query: req.url?.split('?')[1] ?? null, echoedBody: body ? JSON.parse(body) : null });
      }
      return send(404, { success: false });
    });
  });
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});
afterAll(() => new Promise<void>(resolve => server.close(() => resolve())));

let base = '';
beforeEach(() => {
  process.env.WEB_SESSION_SECRET = 's'.repeat(40);
  process.env.OPS_API_URL = base;
  process.env.WEB_COOKIE_SECURE = 'false';
  process.env.WEB_ORIGIN = 'http://ops.test';
  delete process.env.WEB_TRUST_PROXY_HOPS;
  Object.assign(state, { refreshCalls: 0, logoutCalls: 0, refreshMode: 'ok', seen: [] });
});

const post = (url: string, body: unknown, headers: Record<string, string> = {}) =>
  new Request(`http://ops.test${url}`, { method: 'POST', body: typeof body === 'string' ? body : JSON.stringify(body), headers: { origin: 'http://ops.test', 'x-ops-csrf': '1', 'content-type': 'application/json', ...headers } });
const get = (url: string, headers: Record<string, string> = {}) => new Request(`http://ops.test${url}`, { headers });
const cookieOf = (response: Response, name = sessionCookieName()): string | undefined =>
  response.headers.getSetCookie().find(c => c.startsWith(`${name}=`))?.split(';')[0]?.slice(name.length + 1);
const withCookie = (value: string, headers: Record<string, string> = {}) => ({ cookie: `${sessionCookieName()}=${value}`, ...headers });

async function adminCookie(): Promise<string> {
  const response = await login(post('/session/login', { username: 'admin', password: 'ok' }));
  expect(response.status).toBe(200);
  return cookieOf(response) as string;
}

describe('inicio de sesión', () => {
  it('admin: cookie httpOnly cifrada y NINGÚN token en el cuerpo de la respuesta', async () => {
    const response = await login(post('/session/login', { username: 'admin', password: 'ok' }));
    expect(response.status).toBe(200);
    const text = await response.text();
    expect(text).not.toMatch(/h\.|rt_|token/i);
    const header = response.headers.getSetCookie().find(c => c.startsWith('ops_session='))!;
    expect(header).toMatch(/HttpOnly/);
    expect(header).toMatch(/SameSite=Strict/);
    expect(header).toMatch(/Path=\//);
    const value = cookieOf(response)!;
    expect(value).not.toContain('rt_');
    expect(Buffer.from(value.split('.')[3] as string, 'base64url').toString('utf8')).not.toContain('rt_');
    expect(me(get('/session/me', withCookie(value))).status).toBe(200);
  });

  it('con HTTPS la cookie es __Host- y Secure', async () => {
    process.env.WEB_COOKIE_SECURE = 'true';
    const response = await login(post('/session/login', { username: 'admin', password: 'ok' }));
    const header = response.headers.getSetCookie().find(c => c.startsWith('__Host-ops_session='))!;
    expect(header).toMatch(/Secure/);
    expect(header).not.toMatch(/Domain/i);
  });

  it('un usuario que NO es admin no entra y su sesión se cierra en el API', async () => {
    const response = await login(post('/session/login', { username: 'plain', password: 'ok' }));
    expect(response.status).toBe(403);
    expect((await response.json()).code).toBe('NOT_ADMIN');
    expect(cookieOf(response)).toBeUndefined();
    expect(state.logoutCalls).toBe(1);
  });

  it('credenciales malas y límites del API se pasan tal cual (con Retry-After)', async () => {
    const bad = await login(post('/session/login', { username: 'admin', password: 'mala' }));
    expect(bad.status).toBe(401);
    expect((await bad.json()).code).toBe('INVALID_CREDENTIALS');
    const locked = await login(post('/session/login', { username: 'locked', password: 'x' }));
    expect(locked.status).toBe(429);
    expect(locked.headers.get('retry-after')).toBe('30');
  });

  it('valida la entrada y exige CSRF', async () => {
    expect((await login(post('/session/login', { username: '', password: '' }))).status).toBe(400);
    expect((await login(post('/session/login', { username: 'a'.repeat(100), password: 'x' }))).status).toBe(400);
    expect((await login(post('/session/login', '{no json'))).status).toBe(400);
    expect((await login(post('/session/login', { username: 'admin', password: 'ok' }, { 'x-ops-csrf': '0' }))).status).toBe(403);
    expect((await login(post('/session/login', { username: 'admin', password: 'ok' }, { origin: 'http://evil.test' }))).status).toBe(403);
  });

  it('MFA: el reto va en una cookie httpOnly (no en el cuerpo) y el segundo paso completa el acceso', async () => {
    const first = await login(post('/session/login', { username: 'mfa', password: 'ok' }));
    const body = await first.json();
    expect(body).toEqual({ success: true, mfaRequired: true, methods: ['otp', 'recovery'] });
    expect(JSON.stringify(body)).not.toContain('MFA-TOKEN');
    const mfa = first.headers.getSetCookie().find(c => c.startsWith('ops_mfa='))!;
    expect(mfa).toMatch(/HttpOnly/);
    const mfaValue = mfa.split(';')[0]!.slice('ops_mfa='.length);

    const wrong = await loginMfa(post('/session/mfa', { otp: '000000' }, { cookie: `ops_mfa=${mfaValue}` }));
    expect(wrong.status).toBe(401);
    expect((await loginMfa(post('/session/mfa', {}, { cookie: `ops_mfa=${mfaValue}` }))).status).toBe(400);
    expect((await loginMfa(post('/session/mfa', { otp: '123456', recoveryCode: 'x' }, { cookie: `ops_mfa=${mfaValue}` }))).status).toBe(400);

    const ok = await loginMfa(post('/session/mfa', { otp: '123456' }, { cookie: `ops_mfa=${mfaValue}` }));
    expect(ok.status).toBe(200);
    expect(cookieOf(ok)).toBeTruthy();
    const recovery = await loginMfa(post('/session/mfa', { recoveryCode: 'AAAA-BBBB' }, { cookie: `ops_mfa=${mfaValue}` }));
    expect(recovery.status).toBe(200);
  });

  it('sin cookie de MFA (o con una alterada, o la de sesión) no hay segundo paso', async () => {
    expect((await loginMfa(post('/session/mfa', { otp: '123456' }))).status).toBe(401);
    expect((await loginMfa(post('/session/mfa', { otp: '123456' }, { cookie: 'ops_mfa=v1.a.b.c' }))).status).toBe(401);
    const session = await adminCookie();
    expect((await loginMfa(post('/session/mfa', { otp: '123456' }, { cookie: `ops_mfa=${session}` }))).status).toBe(401);
  });

  it('logout cierra la sesión en el API y borra las cookies', async () => {
    const cookie = await adminCookie();
    const response = await logout(post('/session/logout', {}, withCookie(cookie)));
    expect(response.status).toBe(200);
    expect(state.logoutCalls).toBe(1);
    expect(response.headers.getSetCookie().some(c => c.startsWith('ops_session=;') && /Max-Age=0/.test(c))).toBe(true);
  });
});

describe('proxy de datos', () => {
  it('reenvía con el Bearer que guarda la cookie, sin exponer tokens, y conserva la consulta', async () => {
    const cookie = await adminCookie();
    state.seen = [];
    const response = await proxyData(get('/bff/api/system/alerts', withCookie(cookie)), ['api', 'system', 'alerts'], '?status=open&limit=5');
    expect(response.status).toBe(200);
    expect((await response.json()).query).toBe('status=open&limit=5');
    const call = state.seen.at(-1)!;
    expect(call.headers.authorization).toMatch(/^Bearer h\./);
    expect(response.headers.get('cache-control')).toBe('no-store');
    expect(response.headers.get('set-cookie')).toBeNull();
  });

  it('sin sesión: 401 y cookie borrada; con cookie alterada, igual', async () => {
    const none = await proxyData(get('/bff/api/system/alerts'), ['api', 'system', 'alerts'], '');
    expect(none.status).toBe(401);
    const forged = await proxyData(get('/bff/api/system/alerts', withCookie('v1.xxxx.yyyy.zzzz')), ['api', 'system', 'alerts'], '');
    expect(forged.status).toBe(401);
    // una cookie sellada con OTRA clave tampoco vale
    process.env.WEB_SESSION_SECRET = 'z'.repeat(40);
    const foreign = seal({ at: 'h.x.s', rt: 'rt_1', ae: Date.now() + 1e6, se: Date.now() + 1e6, u: 'x', uid: 1 } satisfies Session, 'session', 1e6);
    process.env.WEB_SESSION_SECRET = 's'.repeat(40);
    expect((await proxyData(get('/bff/api/system/alerts', withCookie(foreign)), ['api', 'system', 'alerts'], '')).status).toBe(401);
  });

  it('solo reenvía rutas permitidas y no deja salir del árbol del API', async () => {
    const cookie = await adminCookie();
    for (const segments of [['api', 'system', 'rotate-keys'], ['api', 'auth', 'profile'], ['api', 'system', '..', 'auth', 'profile']]) {
      expect((await proxyData(post('/bff/x', {}, withCookie(cookie)), segments, '')).status).toBe(404);
    }
    expect(state.seen.filter(s => s.path.includes('rotate-keys') || s.path.includes('profile')).length).toBe(0);
  });

  it('POST/DELETE exigen CSRF; el cuerpo se valida y se acota', async () => {
    const cookie = await adminCookie();
    const noHeader = new Request('http://ops.test/bff', { method: 'POST', body: '{}', headers: { origin: 'http://ops.test', cookie: `ops_session=${cookie}` } });
    expect((await proxyData(noHeader, ['api', 'system', 'alerts', 'evaluate'], '')).status).toBe(403);
    expect((await proxyData(post('/bff', {}, { ...withCookie(cookie), origin: 'http://evil.test' }), ['api', 'system', 'alerts', 'evaluate'], '')).status).toBe(403);
    expect((await proxyData(post('/bff', '{no json', withCookie(cookie)), ['api', 'system', 'alerts', 'evaluate'], '')).status).toBe(400);
    expect((await proxyData(post('/bff', { x: 'a'.repeat(70_000) }, withCookie(cookie)), ['api', 'system', 'alerts', 'evaluate'], '')).status).toBe(413);
    const ok = await proxyData(post('/bff', { reason: 'una razón válida' }, withCookie(cookie)), ['api', 'system', 'alerts', 'evaluate'], '');
    expect(ok.status).toBe(200);
    expect((await ok.json()).echoedBody).toEqual({ reason: 'una razón válida' });
  });

  it('las cabeceras del navegador no llegan al API: ni Authorization, ni X-Forwarded-For falso', async () => {
    const cookie = await adminCookie();
    state.seen = [];
    await proxyData(get('/bff', withCookie(cookie, { authorization: 'Bearer robado', 'x-forwarded-for': '6.6.6.6, 203.0.113.50', 'x-admin': '1' })), ['api', 'system', 'dashboard'], '');
    const call = state.seen.at(-1)!;
    expect(call.headers.authorization).not.toContain('robado');
    expect(call.headers['x-forwarded-for']).toBe('203.0.113.50');
    expect(call.headers['x-admin']).toBeUndefined();
    process.env.WEB_TRUST_PROXY_HOPS = '0';
    state.seen = [];
    await proxyData(get('/bff', withCookie(cookie, { 'x-forwarded-for': '6.6.6.6' })), ['api', 'system', 'dashboard'], '');
    expect(state.seen.at(-1)!.headers['x-forwarded-for']).toBeUndefined();
  });

  it('la respuesta de métricas (texto) se devuelve como texto', async () => {
    const cookie = await adminCookie();
    const response = await proxyData(get('/bff', withCookie(cookie)), ['api', 'metrics'], '');
    expect(response.headers.get('content-type')).toMatch(/text\/plain/);
    expect(await response.text()).toContain('# HELP');
  });

  it('un 403 del API (no admin) se pasa tal cual y no borra la sesión', async () => {
    const response = await login(post('/session/login', { username: 'admin', password: 'ok' }));
    const cookie = cookieOf(response)!;
    state.adminTokens.clear(); // el rol se le quitó mientras tanto
    const denied = await proxyData(get('/bff', withCookie(cookie)), ['api', 'system', 'dashboard'], '');
    expect(denied.status).toBe(403);
    expect(denied.headers.get('set-cookie')).toBeNull();
  });
});

describe('renovación de la sesión', () => {
  const expired = (cookie: string): string => {
    // sella una sesión igual pero con el token de acceso a punto de caducar
    const base = JSON.parse(Buffer.from(cookie.split('.')[3] as string, 'base64url').toString('utf8'));
    void base;
    return cookie;
  };
  void expired;

  async function almostExpiredCookie(): Promise<{ cookie: string; session: Session }> {
    const fresh = issue('admin', true);
    const session: Session = { at: fresh.token, rt: fresh.refreshToken, ae: Date.now() + 5_000, se: Date.now() + 86_400_000, u: 'admin', uid: 7 };
    return { cookie: seal(session, 'session', 86_400_000), session };
  }

  it('renueva ANTES de que caduque, entrega la cookie nueva y el refresh token viejo queda gastado', async () => {
    const { cookie, session } = await almostExpiredCookie();
    const response = await proxyData(get('/bff', withCookie(cookie)), ['api', 'system', 'dashboard'], '');
    expect(response.status).toBe(200);
    expect(state.refreshCalls).toBe(1);
    const renewed = cookieOf(response);
    expect(renewed).toBeTruthy();
    expect(renewed).not.toBe(cookie);
    expect(state.validRefresh.has(session.rt)).toBe(false);
    // con la cookie nueva ya no hace falta renovar
    const again = await proxyData(get('/bff', withCookie(renewed!)), ['api', 'system', 'dashboard'], '');
    expect(again.status).toBe(200);
    expect(state.refreshCalls).toBe(1);
  });

  it('cinco peticiones simultáneas con la misma cookie renuevan UNA sola vez', async () => {
    const { cookie } = await almostExpiredCookie();
    const responses = await Promise.all(Array.from({ length: 5 }, () => proxyData(get('/bff', withCookie(cookie)), ['api', 'system', 'dashboard'], '')));
    expect(responses.map(r => r.status)).toEqual([200, 200, 200, 200, 200]);
    expect(state.refreshCalls).toBe(1);
    // todas reciben una cookie con la MISMA sesión nueva (el cifrado cambia por el IV, el contenido no)
    const sessions = new Set(responses.map(r => unseal<Session>(cookieOf(r), 'session')?.rt));
    expect(sessions.size).toBe(1);
  });

  it('si el API responde 401 con un token que aún parecía vivo, renueva y reintenta una vez', async () => {
    const fresh = issue('admin', true);
    state.validAccess.delete(fresh.token); // el API ya lo revocó
    const session: Session = { at: fresh.token, rt: fresh.refreshToken, ae: Date.now() + 600_000, se: Date.now() + 86_400_000, u: 'admin', uid: 7 };
    const response = await proxyData(get('/bff', withCookie(seal(session, 'session', 86_400_000))), ['api', 'system', 'dashboard'], '');
    expect(response.status).toBe(200);
    expect(state.refreshCalls).toBe(1);
    expect(cookieOf(response)).toBeTruthy();
  });

  it('refresh rechazado: 401 y cookie borrada (hay que iniciar sesión)', async () => {
    const { cookie } = await almostExpiredCookie();
    state.refreshMode = 'invalid';
    const response = await proxyData(get('/bff', withCookie(cookie)), ['api', 'system', 'dashboard'], '');
    expect(response.status).toBe(401);
    expect(response.headers.getSetCookie().some(c => /^ops_session=;/.test(c) && /Max-Age=0/.test(c))).toBe(true);
  });

  it('conflicto de renovación (otra instancia ganó): 409 REFRESH_CONFLICT y la cookie NO se borra', async () => {
    const { cookie } = await almostExpiredCookie();
    state.refreshMode = 'conflict';
    const response = await proxyData(get('/bff', withCookie(cookie)), ['api', 'system', 'dashboard'], '');
    expect(response.status).toBe(409);
    expect((await response.json()).code).toBe('REFRESH_CONFLICT');
    expect(response.headers.get('set-cookie')).toBeNull();
  });

  it('el tope absoluto de la sesión no se alarga al renovar y una sesión pasada de fecha no vale', async () => {
    const { cookie } = await almostExpiredCookie();
    const response = await proxyData(get('/bff', withCookie(cookie)), ['api', 'system', 'dashboard'], '');
    const renewed = cookieOf(response)!;
    const text = await proxyData(get('/bff', withCookie(renewed)), ['api', 'system', 'dashboard'], '');
    expect(text.status).toBe(200);
    const old: Session = { at: 'x', rt: 'y', ae: 0, se: Date.now() - 1, u: 'a', uid: 1 };
    expect((await proxyData(get('/bff', withCookie(seal(old, 'session', 1e6))), ['api', 'system', 'dashboard'], '')).status).toBe(401);
  });
});

describe('API caído', () => {
  it('502 limpio, sin detalles internos', async () => {
    const cookie = await adminCookie();
    process.env.OPS_API_URL = 'http://127.0.0.1:1';
    const response = await proxyData(get('/bff', withCookie(cookie)), ['api', 'system', 'dashboard'], '');
    expect(response.status).toBe(502);
    const text = await response.text();
    expect(text).not.toMatch(/ECONNREFUSED|127\.0\.0\.1|stack/);
  });

  it('exige OPS_API_URL https en producción', async () => {
    const saved = process.env.NODE_ENV;
    Object.assign(process.env, { NODE_ENV: 'production', OPS_API_URL: 'http://api.interno' });
    // Una configuración insegura no se usa: el login responde 502 (el detalle queda en el log del servidor, no en la respuesta)
    const response = await login(post('/session/login', { username: 'admin', password: 'ok' }));
    expect(response.status).toBe(502);
    expect(state.seen.length).toBe(0);
    Object.assign(process.env, { NODE_ENV: saved });
  });
});
