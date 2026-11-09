// Extremo a extremo de lo añadido en la interfaz: novedades en vivo (SSE), passkey como segundo factor, SSO por OpenID Connect con
// entrega por código (sin tokens en el navegador), dos administradores aprobando a la vez, accesibilidad (axe) y los mismos
// controles en Firefox y WebKit. API real + web real + navegadores reales; el proveedor de identidad es simulado.
//
//   npm run build && npm run test:e2e        (MariaDB; Chromium, Firefox y WebKit de Playwright; @axe-core/playwright)
'use strict';
const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { ROOT, helpers, totp, startApi, startWeb, db, playwright, axe, sleep, filesDir, freePort } = require('../e2e-support/harness.cjs');

const { api, registerAndLogin, uniqueName, testIp, prepareDatabase, PASSWORD } = helpers;
const { createMockIdp } = require(path.join(ROOT, 'test_helpers/mock-idp'));
const { SoftAuthenticator } = require(path.join(ROOT, 'test_helpers/webauthn-authenticator'));

const CLIENT_ID = 'ops-e2e', CLIENT_SECRET = 'secreto-del-cliente-e2e';
let dbAvailable = false, apiProc, webProc, pool, idp, pw, chromium;
let WEB = '';
const users = {};
const contexts = [];

test.before(async () => {
  dbAvailable = await prepareDatabase();
  if (!dbAvailable) return;
  // Los orígenes tienen que conocerse ANTES de arrancar el API (WebAuthn firma el origen; el SSO redirige a la interfaz).
  // La interfaz se usa por http://localhost: es contexto seguro (WebAuthn) y un RP ID válido (una IP no lo es).
  const [apiPort, webPort] = [await freePort(), await freePort()];
  WEB = `http://localhost:${webPort}`;
  idp = await createMockIdp({ clientId: CLIENT_ID, clientSecret: CLIENT_SECRET });
  apiProc = await startApi({
    WEBAUTHN_RP_ID: 'localhost', WEBAUTHN_ORIGINS: WEB, WEBAUTHN_RP_NAME: 'secure-server e2e',
    SSO_ISSUER: idp.issuer, SSO_CLIENT_ID: CLIENT_ID, SSO_CLIENT_SECRET: CLIENT_SECRET,
    SSO_REDIRECT_URI: `http://127.0.0.1:${apiPort}/api/sso/callback`, SSO_HANDOFF_URL: `${WEB}/session/sso/callback`,
    SSO_ADMIN_CLAIM: 'groups', SSO_ADMIN_VALUE: 'ops-admins',
    STREAM_POLL_MS: '500'
  }, { port: apiPort });
  webProc = await startWeb(apiProc.base, {}, { port: webPort });
  pool = await db();

  const make = async (key, role) => {
    const user = await registerAndLogin(apiProc.base, { ip: testIp(), username: uniqueName() });
    if (role) await pool.query('UPDATE users SET role = ? WHERE id = ?', [role, user.userId]);
    users[key] = user;
  };
  for (const key of ['live', 'pk', 'a1', 'a2', 'requester', 'axe', 'xb']) await make(key, 'admin');
  await make('target', null);

  pw = playwright();
  chromium = await pw.chromium.launch();
});

test.after(async () => {
  for (const c of contexts) await c.close().catch(() => {});
  await chromium?.close().catch(() => {});
  await pool?.end().catch(() => {});
  await webProc?.stop();
  await apiProc?.stop();
  await idp?.close().catch(() => {});
  if (apiProc?.envDir) fs.rmSync(apiProc.envDir, { recursive: true, force: true });
  fs.rmSync(filesDir, { recursive: true, force: true });
});

const itE2e = (name, fn) => test(name, async (t) => { if (!dbAvailable) return t.skip('sin base de datos'); await fn(t); });

async function newPage(browser = chromium) {
  const context = await browser.newContext({ baseURL: WEB, locale: 'es-ES' });
  contexts.push(context);
  await context.addInitScript(() => {
    document.addEventListener('securitypolicyviolation', (e) => { (window.__csp = window.__csp || []).push(`${e.violatedDirective} ${e.blockedURI}`); });
  });
  const page = await context.newPage();
  const errors = [];
  page.on('pageerror', (error) => errors.push(`pageerror: ${error.message}`));
  page.on('console', (message) => { if (message.type() === 'error' && !/Failed to load resource/.test(message.text())) errors.push(`console: ${message.text()}`); });
  page.collectProblems = async () => [...errors, ...(await page.evaluate(() => window.__csp || []).catch(() => [])).map(v => `CSP: ${v}`)];
  page.context_ = context;
  return page;
}

async function login(page, user) {
  await page.goto('/login');
  await page.getByLabel('Usuario').fill(user.username);
  await page.getByLabel('Contraseña').fill(PASSWORD);
  await page.getByRole('button', { name: 'Entrar' }).click();
}

const adminStatus = async (user) => (await api(apiProc.base, 'GET', '/api/system/status', { token: user.token, ip: testIp() })).body?.status;
async function until(fn, { timeout = 15_000, every = 200, message = 'condición' } = {}) {
  const end = Date.now() + timeout;
  for (;;) {
    const value = await fn();
    if (value) return value;
    if (Date.now() > end) throw new Error(`tiempo agotado: ${message}`);
    await sleep(every);
  }
}

// ---------------------------------------------------------------------------------------------------------------------------------
itE2e('en vivo: una alerta crítica nueva aparece al momento (aviso + contador) sin recargar, y al cerrar la pestaña no queda conexión abierta', async () => {
  const page = await newPage();
  await login(page, users.live);
  await page.getByRole('heading', { name: 'Panel de seguridad' }).waitFor();
  await page.getByRole('status').filter({ hasText: 'En vivo' }).waitFor();
  assert.ok((await adminStatus(users.live)).cluster.workers[0].streams >= 1, 'el API ve la conexión en vivo');

  const title = `Alerta en vivo E2E ${crypto.randomBytes(3).toString('hex')}`;
  await pool.query("INSERT INTO security_alerts (rule, subject, dedupe_key, severity, title) VALUES ('E2E_LIVE', 'global', ?, 'critical', ?)", [`e2e-live:${title}`, title]);
  await page.getByText(`Alerta critical: ${title}`).waitFor({ timeout: 10_000 });
  await page.getByRole('link', { name: /Alertas/ }).locator('.count').waitFor();
  assert.deepStrictEqual(await page.collectProblems(), []);

  await page.context_.close();
  await until(async () => (await adminStatus(users.live)).cluster.workers[0].streams === 0, { message: 'el stream se cierra también en el API' });
});

itE2e('passkey: segundo factor con la llave (autenticador virtual de Chromium); el reto y los tokens no llegan a la página', async () => {
  // Alta de la llave por el API (contraseña), con el ORIGEN de la interfaz
  const soft = new SoftAuthenticator({ origin: WEB, rpId: 'localhost' });
  const ip = testIp();
  const options = await api(apiProc.base, 'POST', '/api/auth/webauthn/register/options', { token: users.pk.token, ip, json: { password: PASSWORD } });
  assert.strictEqual(options.status, 200, options.text);
  const done = await api(apiProc.base, 'POST', '/api/auth/webauthn/register', { token: users.pk.token, ip, json: { credential: soft.register(options.body.options), name: 'Llave e2e' } });
  assert.strictEqual(done.status, 200, done.text);

  const page = await newPage();
  const cdp = await page.context_.newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true }
  });
  await cdp.send('WebAuthn.addCredential', {
    authenticatorId,
    credential: {
      credentialId: soft.credentialId.toString('base64'), isResidentCredential: false, rpId: 'localhost',
      privateKey: soft.privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64'), signCount: soft.counter
    }
  });

  await login(page, users.pk);
  const button = page.getByRole('button', { name: 'Usar passkey o llave de seguridad' });
  await button.waitFor();
  const html = await page.content();
  assert.ok(!/eyJ/.test(html), 'el reto MFA no está en la página');
  await button.click();
  await page.getByRole('heading', { name: 'Panel de seguridad' }).waitFor();

  const [[session]] = await pool.query('SELECT amr FROM user_sessions WHERE user_id = ? AND revoked_at IS NULL ORDER BY id DESC LIMIT 1', [users.pk.userId]);
  assert.match(String(session.amr), /webauthn/);
  const exposure = await page.evaluate(() => document.cookie + JSON.stringify({ ...localStorage }) + document.documentElement.outerHTML);
  assert.ok(!/eyJ|rt_[0-9A-Za-z_-]{8}/.test(exposure), 'ningún token al alcance del JavaScript');
  assert.deepStrictEqual(await page.collectProblems(), []);
  await page.context_.close();
});

// El navegador va al proveedor: aquí el proveedor simulado "autentica" y redirige al callback del API (como haría uno real)
async function routeIdp(context, identity) {
  await context.route(`${idp.issuer}/authorize**`, async (route) => {
    const { callbackPath } = idp.authorize(route.request().url(), identity);
    await route.fulfill({ status: 302, headers: { location: `${apiProc.base}${callbackPath}` } });
  });
}

itE2e('SSO (OpenID Connect): el botón lleva al proveedor y vuelve con sesión; en ninguna URL ni en la página aparecen tokens', async () => {
  const page = await newPage();
  const sub = `e2e-${crypto.randomUUID()}`;
  await routeIdp(page.context_, { sub, email: `${sub}@acme.com`, claims: { groups: ['ops-admins'] } });
  const urls = [];
  page.on('request', (request) => { if (request.isNavigationRequest()) urls.push(request.url()); });

  await page.goto('/login');
  await page.getByRole('link', { name: 'Entrar con SSO (OpenID Connect)' }).click();
  await page.getByRole('heading', { name: 'Panel de seguridad' }).waitFor();

  assert.ok(urls.some(u => u.includes('/session/sso/callback?code=')), 'volvió por el código de entrega');
  for (const u of urls) assert.ok(!/token=|refreshToken|#.*token|eyJ/.test(u), `ningún token en la URL: ${u}`);
  const cookies = await page.context_.cookies();
  assert.ok(cookies.find(c => c.name === 'ops_session' && c.httpOnly && c.sameSite === 'Strict'), 'cookie de sesión httpOnly Strict');
  assert.ok(!cookies.some(c => c.name === 'ops_sso' && c.value), 'la cookie del verificador se borró');
  const [[row]] = await pool.query('SELECT used_at, payload_encrypted FROM sso_handoffs ORDER BY id DESC LIMIT 1');
  assert.ok(row.used_at && row.payload_encrypted === null, 'código canjeado y sin payload guardado');
  assert.deepStrictEqual(await page.collectProblems(), []);
  await page.context_.close();
});

itE2e('SSO: una identidad que no es admin vuelve al login con un mensaje claro (y sin sesión)', async () => {
  const page = await newPage();
  const sub = `e2e-${crypto.randomUUID()}`;
  await routeIdp(page.context_, { sub, email: `${sub}@acme.com`, claims: { groups: ['otros'] } });
  await page.goto('/login');
  await page.getByRole('link', { name: 'Entrar con SSO (OpenID Connect)' }).click();
  await page.getByText('Tu cuenta no es de administrador').waitFor();
  assert.match(page.url(), /\/login\?sso_error=NOT_ADMIN$/);
  assert.ok(!(await page.context_.cookies()).some(c => c.name === 'ops_session' && c.value));
  await page.context_.close();
});

itE2e('aprobaciones: dos administradores aprueban la MISMA solicitud a la vez → se ejecuta una sola vez', async () => {
  // Objetivo con MFA activo; la solicitud la hace un tercer admin
  const ip = testIp();
  const setup = await api(apiProc.base, 'POST', '/api/auth/mfa/setup', { token: users.target.token, ip });
  await api(apiProc.base, 'POST', '/api/auth/mfa/enable', { token: users.target.token, ip, json: { otp: totp.totp(setup.body.secret) } });
  const request = await api(apiProc.base, 'POST', '/api/system/accounts/mfa-reset', {
    token: users.requester.token, ip: testIp(), json: { username: users.target.username, reason: 'Dispositivo perdido (prueba de concurrencia e2e)' }
  });
  assert.strictEqual(request.status, 202, request.text);

  const pages = [await newPage(), await newPage()];
  await login(pages[0], users.a1);
  await login(pages[1], users.a2);
  for (const page of pages) {
    await page.getByRole('heading', { name: 'Panel de seguridad' }).waitFor();
    await page.goto('/approvals');
    const row = page.getByRole('row', { name: new RegExp(users.target.username) });
    await row.getByRole('button', { name: 'Aprobar' }).click();
    await page.getByRole('dialog').getByRole('button', { name: 'Aprobar y ejecutar' }).waitFor();
  }
  // Los dos confirman a la vez
  await Promise.all(pages.map(page => page.getByRole('dialog').getByRole('button', { name: 'Aprobar y ejecutar' }).click()));
  const outcomes = await Promise.all(pages.map(page => Promise.race([
    page.getByText(/^Aprobada/).waitFor({ timeout: 15_000 }).then(() => 'ok'),
    page.locator('.toast[data-tone="error"]').first().waitFor({ timeout: 15_000 }).then(() => 'error')
  ])));
  assert.deepStrictEqual(outcomes.sort(), ['error', 'ok'], `uno gana y el otro recibe error: ${outcomes}`);

  const [rows] = await pool.query("SELECT status, approved_by FROM admin_approvals WHERE target_user_id = ? AND action = 'mfa_reset'", [users.target.userId]);
  assert.strictEqual(rows.length, 1);
  assert.strictEqual(rows[0].status, 'executed');
  assert.ok([users.a1.userId, users.a2.userId].includes(rows[0].approved_by));
  const [[mfa]] = await pool.query('SELECT mfa_enabled FROM users WHERE id = ?', [users.target.userId]);
  assert.strictEqual(Number(mfa.mfa_enabled), 0, 'el reset se ejecutó');
  for (const page of pages) await page.context_.close();
});

itE2e('accesibilidad (axe, WCAG 2.1 A/AA): ninguna página tiene fallos graves o críticos', async () => {
  const { AxeBuilder } = axe();
  const page = await newPage();
  const audit = async (where) => {
    const result = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa']).analyze();
    return result.violations.filter(v => v.impact === 'serious' || v.impact === 'critical')
      .map(v => `${where}: ${v.id} (${v.impact}) ${v.nodes.slice(0, 3).map(n => n.target.join(' ')).join(' | ')}`);
  };
  const problems = [];
  await page.goto('/login');
  await page.getByLabel('Usuario').waitFor();
  problems.push(...await audit('/login'));

  await login(page, users.axe);
  await page.getByRole('heading', { name: 'Panel de seguridad' }).waitFor();
  for (const [route, heading] of [['/', 'Panel de seguridad'], ['/alerts', 'Alertas'], ['/approvals', 'Aprobaciones'], ['/events', 'Eventos de seguridad'], ['/network', /IP/], ['/users', /Usuarios/], ['/metrics', 'Métricas'], ['/system', 'Sistema']]) {
    await page.goto(route);
    await page.getByRole('heading', { name: heading, level: 1 }).waitFor();
    await sleep(300);
    problems.push(...await audit(route));
  }
  assert.deepStrictEqual(problems, [], problems.join('\n'));
  await page.context_.close();
});

for (const name of ['firefox', 'webkit']) {
  itE2e(`${name}: login, panel, en vivo, CSP sin violaciones y ningún token al alcance del JavaScript`, async () => {
    const browser = await pw[name].launch();
    try {
      const page = await newPage(browser);
      await login(page, users.xb);
      await page.getByRole('heading', { name: 'Panel de seguridad' }).waitFor();
      await page.getByRole('status').filter({ hasText: 'En vivo' }).waitFor();
      const exposure = await page.evaluate(() => ({ cookie: document.cookie, local: JSON.stringify({ ...localStorage }), html: document.documentElement.outerHTML }));
      assert.strictEqual(exposure.cookie, '');
      for (const [where, text] of Object.entries(exposure)) assert.ok(!/eyJ|rt_[0-9A-Za-z_-]{8}/.test(text), `token visible en ${where}`);
      const session = (await page.context_.cookies()).find(c => c.name === 'ops_session');
      assert.ok(session?.httpOnly);
      await page.getByRole('link', { name: /Alertas/ }).click();
      await page.getByRole('heading', { name: 'Alertas' }).waitFor();
      assert.deepStrictEqual(await page.collectProblems(), []);
      await page.context_.close();
    } finally { await browser.close(); }
  });
}
