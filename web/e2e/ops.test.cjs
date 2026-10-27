// Extremo a extremo: API real + aplicación web real + navegador real. Comprueba lo que importa de verdad:
// que un administrador puede operar desde la interfaz, que un usuario normal NO, que los tokens nunca llegan al JavaScript de la página,
// que la CSP no se viola, que CSRF se rechaza y que la sesión se renueva sola.
//
//   npm run build && npm run test:e2e        (necesita MariaDB y Chromium de Playwright)
'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const { helpers, totp, startApi, startWeb, db, playwright, sleep, filesDir } = require('../e2e-support/harness.cjs');

const { api, registerAndLogin, uniqueName, testIp, prepareDatabase, PASSWORD } = helpers;

let dbAvailable = false, apiProc, webProc, pool, browser, context;
const users = {};
const cspViolations = [];

test.before(async () => {
  dbAvailable = await prepareDatabase();
  if (!dbAvailable) return;
  // Token de acceso de 36 s: la interfaz tiene que renovarlo sola varias veces durante las pruebas
  apiProc = await startApi({ ACCESS_TOKEN_MINUTES: '0.6' });
  webProc = await startWeb(apiProc.base);
  pool = await db();

  const make = async (key, role) => {
    const user = await registerAndLogin(apiProc.base, { ip: testIp(), username: uniqueName() });
    if (role) await pool.query('UPDATE users SET role = ? WHERE id = ?', [role, user.userId]);
    users[key] = user;
  };
  await make('plain', null);
  await make('admin', 'admin');
  await make('admin2', 'admin');
  await make('target', null);

  // Un administrador con MFA (TOTP + códigos de recuperación)
  await make('mfa', 'admin');
  const setup = await api(apiProc.base, 'POST', '/api/auth/mfa/setup', { token: users.mfa.token, ip: testIp() });
  users.mfa.secret = setup.body.secret;
  const enable = await api(apiProc.base, 'POST', '/api/auth/mfa/enable', { token: users.mfa.token, ip: testIp(), json: { otp: totp.totp(users.mfa.secret) } });
  assert.strictEqual(enable.status, 200, enable.text);
  users.mfa.recoveryCodes = enable.body.recoveryCodes;

  const { chromium } = playwright();
  browser = await chromium.launch();
});

test.after(async () => {
  await context?.close().catch(() => {});
  await browser?.close().catch(() => {});
  await pool?.end().catch(() => {});
  await webProc?.stop();
  await apiProc?.stop();
  if (apiProc?.envDir) fs.rmSync(apiProc.envDir, { recursive: true, force: true });
  fs.rmSync(filesDir, { recursive: true, force: true });
});

const itE2e = (name, fn) => test(name, async (t) => { if (!dbAvailable) return t.skip('sin base de datos'); await fn(t); });

async function newPage() {
  context = await browser.newContext({ baseURL: webProc.base, locale: 'es-ES' });
  await context.addInitScript(() => {
    document.addEventListener('securitypolicyviolation', (e) => { (window.__csp = window.__csp || []).push(`${e.violatedDirective} ${e.blockedURI}`); });
  });
  const page = await context.newPage();
  const errors = [];
  page.on('pageerror', (error) => errors.push(`pageerror: ${error.message}`));
  page.on('console', (message) => { if (message.type() === 'error' && !/Failed to load resource/.test(message.text())) errors.push(`console: ${message.text()}`); });
  page.collectProblems = async () => [...errors, ...(await page.evaluate(() => window.__csp || []).catch(() => [])).map(v => `CSP: ${v}`)];
  return page;
}

async function login(page, user, { code } = {}) {
  await page.goto('/login');
  await page.getByLabel('Usuario').fill(user.username);
  await page.getByLabel('Contraseña').fill(PASSWORD);
  await page.getByRole('button', { name: 'Entrar' }).click();
  if (code) {
    await page.getByLabel(/^Código/).fill(code);
    await page.getByRole('button', { name: 'Verificar' }).click();
  }
}

// ---------------------------------------------------------------------------------------------------------------------------------
itE2e('sin sesión: las páginas redirigen a /login, la CSP lleva nonce y los datos devuelven 401', async () => {
  const page = await newPage();
  const response = await page.goto('/alerts');
  assert.match(page.url(), /\/login$/);
  const csp = response.headers()['content-security-policy'];
  assert.match(csp, /script-src 'self' 'nonce-[A-Za-z0-9+/=]+' 'strict-dynamic'/);
  assert.match(csp, /frame-ancestors 'none'/);
  assert.match(csp, /style-src-attr 'none'/);
  assert.ok(!/unsafe-inline|unsafe-eval/.test(csp), csp);
  assert.strictEqual(response.headers()['x-frame-options'], 'DENY');
  assert.strictEqual(response.headers()['referrer-policy'], 'no-referrer');
  assert.ok(!response.headers()['x-powered-by']);

  const data = await context.request.get('/bff/api/system/dashboard');
  assert.strictEqual(data.status(), 401);
  assert.deepStrictEqual(await page.collectProblems(), []);
  await context.close();
});

itE2e('la CSP está ACTIVA de verdad: un script o un manejador en línea inyectado no se ejecuta y queda registrado', async () => {
  const page = await newPage();
  await page.goto('/login');
  // Un atacante XSS inyecta HTML (parser-inserted): sin nonce, ni el <script> en línea ni el manejador onerror pueden ejecutarse.
  // (Un script creado con createElement por código ya de confianza SÍ se permite: es lo que significa 'strict-dynamic'.)
  await page.evaluate(() => {
    document.body.insertAdjacentHTML('beforeend', '<img src="x" onerror="window.__pwn2 = 1">');
  });
  await sleep(300);
  assert.strictEqual(await page.evaluate(() => window.__pwn2), undefined, 'el manejador en línea no debe ejecutarse');
  const problems = await page.collectProblems();
  assert.ok(problems.some(p => /script-src/.test(p)), `la violación debe registrarse: ${problems}`);

  await page.evaluate(() => { document.write('<script>window.__pwn = 1<' + '/script>'); });
  await sleep(300);
  assert.strictEqual(await page.evaluate(() => window.__pwn), undefined, 'el <script> en línea inyectado no debe ejecutarse');
  await context.close();
});

itE2e('un usuario normal NO entra: la interfaz es solo para administradores', async () => {
  const page = await newPage();
  await login(page, users.plain);
  await page.getByText('Esta interfaz es solo para administradores').waitFor();
  assert.match(page.url(), /\/login$/);
  assert.strictEqual((await context.cookies()).filter(c => /ops_session/.test(c.name)).length, 0);
  // Su sesión en el API se cerró (no queda una sesión abierta de un usuario rechazado)
  const [[row]] = await pool.query('SELECT COUNT(*) AS n FROM user_sessions WHERE user_id = ? AND revoked_at IS NULL AND expires_at > NOW()', [users.plain.userId]);
  assert.strictEqual(Number(row.n), 1, 'solo la sesión de la preparación de la prueba (la del navegador se cerró)');
  await context.close();
});

itE2e('credenciales incorrectas: mensaje claro y ninguna cookie de sesión', async () => {
  const page = await newPage();
  await page.goto('/login');
  await page.getByLabel('Usuario').fill(users.admin.username);
  await page.getByLabel('Contraseña').fill('contraseña-equivocada');
  await page.getByRole('button', { name: 'Entrar' }).click();
  await page.getByRole('alert').waitFor();
  assert.strictEqual((await context.cookies()).length, 0);
  await context.close();
});

itE2e('administrador: panel con datos, cookie httpOnly y NINGÚN token al alcance del JavaScript', async () => {
  const page = await newPage();
  await login(page, users.admin);
  await page.getByRole('heading', { name: 'Panel de seguridad' }).waitFor();
  await page.getByText('Alertas abiertas').first().waitFor();

  const cookies = await context.cookies();
  const session = cookies.find(c => c.name === 'ops_session');
  assert.ok(session, 'hay cookie de sesión');
  assert.strictEqual(session.httpOnly, true);
  assert.strictEqual(session.sameSite, 'Strict');
  assert.strictEqual(session.path, '/');

  const exposure = await page.evaluate(() => ({
    cookie: document.cookie, local: JSON.stringify({ ...localStorage }), session: JSON.stringify({ ...sessionStorage }),
    html: document.documentElement.outerHTML
  }));
  for (const [where, text] of Object.entries(exposure)) {
    assert.ok(!/eyJ|rt_[0-9a-f]{8}/.test(text), `token visible en ${where}`);
  }
  assert.strictEqual(exposure.cookie, '', 'document.cookie no ve la cookie de sesión');
  assert.ok(!session.value.includes('eyJ'), 'la cookie no contiene el JWT en claro');
  assert.deepStrictEqual(await page.collectProblems(), [], 'sin errores de consola ni violaciones de CSP');
  await context.close();
});

itE2e('alertas: se ven, se detallan, se reconocen y se resuelven desde la interfaz', async () => {
  await pool.query(
    `INSERT INTO security_alerts (rule, subject, dedupe_key, severity, title, status, event_count, details)
     VALUES ('E2E_REGLA', 'e2e-sujeto', 'E2E_REGLA:e2e-sujeto', 'high', 'Alerta de prueba E2E', 'open', 7, ?)`, [JSON.stringify({ origen: 'e2e' })]);
  const page = await newPage();
  await login(page, users.admin);
  await page.getByRole('link', { name: /Alertas/ }).click();
  await page.getByRole('heading', { name: 'Alertas' }).waitFor();
  const row = page.getByRole('row', { name: /Alerta de prueba E2E/ });
  await row.waitFor();

  await row.getByRole('button', { name: 'Alerta de prueba E2E' }).click();
  await page.getByText('"origen": "e2e"').waitFor();
  await page.getByRole('dialog').getByRole('button', { name: 'Cerrar' }).click();

  await row.getByRole('button', { name: 'Reconocer' }).click();
  await page.getByRole('dialog').getByRole('button', { name: 'Reconocer' }).click();
  await page.getByText('Alerta reconocida', { exact: true }).waitFor();
  let [[a]] = await pool.query("SELECT status FROM security_alerts WHERE rule = 'E2E_REGLA'");
  assert.strictEqual(a.status, 'acknowledged');

  await page.getByRole('button', { name: 'Todas' }).first().click();
  await page.getByRole('row', { name: /Alerta de prueba E2E/ }).getByRole('button', { name: 'Resolver' }).click();
  await page.getByRole('dialog').getByRole('button', { name: 'Resolver' }).click();
  await page.getByText('Alerta resuelta', { exact: true }).waitFor();
  [[a]] = await pool.query("SELECT status FROM security_alerts WHERE rule = 'E2E_REGLA'");
  assert.strictEqual(a.status, 'resolved');
  assert.deepStrictEqual(await page.collectProblems(), []);
  await context.close();
});

itE2e('aprobaciones: no se puede aprobar la propia solicitud; otro admin aprueba y se ejecuta (reset de MFA)', async () => {
  const request = await api(apiProc.base, 'POST', '/api/system/accounts/mfa-reset', {
    token: users.admin.token, ip: testIp(), json: { username: users.mfa.username, reason: 'Pérdida de dispositivo verificada por teléfono' }
  });
  assert.strictEqual(request.status, 202, request.text);

  // Admin 1 (quien pidió): el botón Aprobar está deshabilitado
  let page = await newPage();
  await login(page, users.admin);
  await page.getByRole('link', { name: /Aprobaciones/ }).click();
  const row = page.getByRole('row', { name: /Reset de MFA/ });
  await row.waitFor();
  assert.strictEqual(await row.getByRole('button', { name: 'Aprobar' }).isDisabled(), true);
  await context.close();

  // Admin 2 aprueba desde la interfaz
  page = await newPage();
  await login(page, users.admin2);
  await page.getByRole('link', { name: /Aprobaciones/ }).click();
  const row2 = page.getByRole('row', { name: /Reset de MFA/ });
  await row2.waitFor();
  await row2.getByRole('button', { name: 'Aprobar' }).click();
  await page.getByRole('dialog').getByRole('button', { name: 'Aprobar y ejecutar' }).click();
  await page.getByText(/Aprobada/).first().waitFor();
  const [[u]] = await pool.query('SELECT mfa_enabled FROM users WHERE id = ?', [users.mfa.userId]);
  assert.strictEqual(Number(u.mfa_enabled), 0, 'el MFA del usuario quedó desactivado');
  assert.deepStrictEqual(await page.collectProblems(), []);
  await context.close();
});

itE2e('eventos: filtros, detalle y exportación CSV', async () => {
  const page = await newPage();
  await login(page, users.admin);
  await page.getByRole('link', { name: /Eventos/ }).click();
  await page.getByRole('heading', { name: 'Eventos de seguridad' }).waitFor();
  await page.getByText(/[1-9]\d* eventos cargados/).waitFor();

  await page.getByLabel('Tipo').fill('TIPO_QUE_NO_EXISTE');
  await page.getByRole('button', { name: 'Filtrar' }).click();
  await page.getByText('Ningún evento con estos filtros.').waitFor();
  await page.getByRole('button', { name: 'Limpiar' }).click();
  await page.getByText(/[1-9]\d* eventos cargados/).waitFor();

  const [download] = await Promise.all([page.waitForEvent('download'), page.getByRole('button', { name: 'Exportar CSV' }).click()]);
  const file = await download.path();
  assert.match(fs.readFileSync(file, 'utf8').split('\n')[0], /^id,fecha,tipo,regla,severidad/);
  assert.deepStrictEqual(await page.collectProblems(), []);
  await context.close();
});

itE2e('IP bloqueadas: se listan y se desbloquean', async () => {
  await pool.query("INSERT INTO blocked_ips (ip_address, reason, blocked_until, block_count) VALUES ('198.51.100.77', 'prueba e2e', DATE_ADD(NOW(), INTERVAL 2 HOUR), 2)");
  const page = await newPage();
  await login(page, users.admin);
  await page.getByRole('link', { name: /IP y cuentas/ }).click();
  const row = page.getByRole('row', { name: /198\.51\.100\.77/ });
  await row.waitFor();
  await row.getByRole('button', { name: 'Desbloquear' }).click();
  await page.getByRole('dialog').getByRole('button', { name: 'Desbloquear' }).click();
  await page.getByText('IP 198.51.100.77 desbloqueada').waitFor();
  const [rows] = await pool.query("SELECT 1 FROM blocked_ips WHERE ip_address = '198.51.100.77'");
  assert.strictEqual(rows.length, 0);
  await context.close();
});

itE2e('usuarios: cerrar las sesiones de un usuario exige motivo y deja su token inservible', async () => {
  const before = await api(apiProc.base, 'GET', '/api/files/quota', { token: users.target.token, ip: testIp() });
  assert.strictEqual(before.status, 200);

  const page = await newPage();
  await login(page, users.admin);
  await page.getByRole('link', { name: /Usuarios y sesiones/ }).click();
  await page.getByLabel('Id de usuario').first().fill(String(users.target.userId));
  await page.getByRole('button', { name: 'Cerrar sus sesiones' }).click();
  const confirm = page.getByRole('dialog').getByRole('button', { name: 'Confirmar' });
  assert.strictEqual(await confirm.isDisabled(), true, 'sin motivo no se puede confirmar');
  await page.getByRole('dialog').getByLabel(/Motivo/).fill('Prueba de extremo a extremo de cierre de sesiones');
  await confirm.click();
  await page.getByText(/sesión\(es\) cerradas/).waitFor();

  const after = await api(apiProc.base, 'GET', '/api/files/quota', { token: users.target.token, ip: testIp() });
  assert.strictEqual(after.status, 401);
  assert.deepStrictEqual(await page.collectProblems(), []);
  await context.close();
});

itE2e('métricas: la vista de resumen se calcula con lo que devuelve /api/metrics', async () => {
  const page = await newPage();
  await login(page, users.admin);
  await page.getByRole('link', { name: /Métricas/ }).click();
  await page.getByText('Peticiones totales').waitFor();
  const text = await page.locator('.stat', { hasText: 'Peticiones totales' }).textContent();
  assert.match(text, /\d/);
  await page.getByRole('button', { name: 'Ver texto Prometheus' }).click();
  await page.getByText('# HELP secure_server_http_requests_total').waitFor();
  assert.deepStrictEqual(await page.collectProblems(), []);
  await context.close();
});

itE2e('CSRF: sin cabecera, con otro origen o desde otro sitio se rechaza; la página sí puede', async () => {
  const page = await newPage();
  await login(page, users.admin);
  await page.getByRole('heading', { name: 'Panel de seguridad' }).waitFor();

  const noHeader = await context.request.post('/bff/api/system/alerts/evaluate', { data: {}, headers: { origin: webProc.base } });
  assert.strictEqual(noHeader.status(), 403);
  const evil = await context.request.post('/bff/api/system/alerts/evaluate', { data: {}, headers: { origin: 'http://evil.example', 'x-ops-csrf': '1' } });
  assert.strictEqual(evil.status(), 403);
  const fine = await context.request.post('/bff/api/system/alerts/evaluate', { data: {}, headers: { origin: webProc.base, 'x-ops-csrf': '1' } });
  assert.strictEqual(fine.status(), 200);

  // No es un proxy abierto
  for (const path of ['/bff/api/system/rotate-keys', '/bff/api/auth/profile', '/bff/api/notes']) {
    assert.strictEqual((await context.request.get(path)).status(), 404, path);
  }
  await context.close();
});

itE2e('la sesión se renueva sola (token de 36 s) sin pedir otra vez la contraseña, y rota el refresh token', async () => {
  const page = await newPage();
  await login(page, users.admin);
  await page.getByRole('heading', { name: 'Panel de seguridad' }).waitFor();
  const [[a]] = await pool.query('SELECT refresh_hash FROM user_sessions WHERE user_id = ? AND revoked_at IS NULL ORDER BY id DESC LIMIT 1', [users.admin.userId]);

  await sleep(24_000); // el token de acceso (36 s) queda por debajo del umbral de renovación (20 s)
  await page.getByRole('button', { name: 'Actualizar' }).click();
  await page.getByText(/Actualizado/).waitFor();
  const me = await context.request.get('/session/me');
  assert.strictEqual(me.status(), 200);
  assert.ok(new Date((await me.json()).accessExpiresAt).getTime() > Date.now() + 10_000, 'el token de acceso se renovó');

  const [[b]] = await pool.query('SELECT refresh_hash FROM user_sessions WHERE user_id = ? AND revoked_at IS NULL ORDER BY id DESC LIMIT 1', [users.admin.userId]);
  assert.notStrictEqual(a.refresh_hash, b.refresh_hash, 'el refresh token rotó');
  assert.match(page.url(), /\/$/, 'sigue dentro');
  assert.deepStrictEqual(await page.collectProblems(), []);
  await context.close();
});

itE2e('administrador con MFA: código incorrecto, TOTP correcto y código de recuperación', async () => {
  // El reset de la prueba de aprobaciones desactivó el MFA de este usuario: se vuelve a activar
  const login1 = await api(apiProc.base, 'POST', '/api/auth/login', { ip: testIp(), json: { username: users.mfa.username, password: PASSWORD } });
  assert.strictEqual(login1.status, 200);
  await pool.query('UPDATE users SET role = ? WHERE id = ?', ['admin', users.mfa.userId]);
  const setup = await api(apiProc.base, 'POST', '/api/auth/mfa/setup', { token: login1.body.token, ip: testIp() });
  users.mfa.secret = setup.body.secret;
  const enable = await api(apiProc.base, 'POST', '/api/auth/mfa/enable', { token: login1.body.token, ip: testIp(), json: { otp: totp.totp(users.mfa.secret) } });
  assert.strictEqual(enable.status, 200, enable.text);
  const recoveryCodes = enable.body.recoveryCodes;

  let page = await newPage();
  await login(page, users.mfa, { code: '000000' });
  await page.getByRole('alert').waitFor();
  assert.match(page.url(), /\/login$/);
  assert.ok(!(await context.cookies()).some(c => c.name === 'ops_session'));

  // El reto MFA nunca está al alcance de la página
  const cookies = await context.cookies();
  const mfa = cookies.find(c => c.name === 'ops_mfa');
  assert.ok(mfa && mfa.httpOnly);
  const html = await page.content();
  assert.ok(!/MFA|eyJ/.test(html.replace(/segundo factor|MFA_/gi, '')) || !/eyJ/.test(html));

  // TOTP del SIGUIENTE paso de 30 s (el del paso actual lo consumió la activación)
  await page.getByLabel(/^Código/).fill(totp.totp(users.mfa.secret, { timeMs: Date.now() + 30_000 }));
  await page.getByRole('button', { name: 'Verificar' }).click();
  await page.getByRole('heading', { name: 'Panel de seguridad' }).waitFor();
  await context.close();

  // Código de recuperación
  page = await newPage();
  await login(page, users.mfa);
  await page.getByRole('button', { name: 'Usar un código de recuperación' }).click();
  await page.getByLabel('Código de recuperación').fill(recoveryCodes[0]);
  await page.getByRole('button', { name: 'Verificar' }).click();
  await page.getByRole('heading', { name: 'Panel de seguridad' }).waitFor();
  assert.deepStrictEqual(await page.collectProblems(), []);
  await context.close();
});

itE2e('cerrar sesión: vuelve al login, borra la cookie y revoca la sesión en el API', async () => {
  const page = await newPage();
  await login(page, users.admin2);
  await page.getByRole('heading', { name: 'Panel de seguridad' }).waitFor();
  const [[open]] = await pool.query('SELECT COUNT(*) AS n FROM user_sessions WHERE user_id = ? AND revoked_at IS NULL AND expires_at > NOW()', [users.admin2.userId]);
  await page.getByRole('button', { name: 'Cerrar sesión' }).click();
  await page.waitForURL(/\/login$/);
  assert.ok(!(await context.cookies()).some(c => c.name === 'ops_session' && c.value));
  const [[after]] = await pool.query('SELECT COUNT(*) AS n FROM user_sessions WHERE user_id = ? AND revoked_at IS NULL AND expires_at > NOW()', [users.admin2.userId]);
  assert.strictEqual(Number(after.n), Number(open.n) - 1);
  // Con la cookie vieja ya no hay acceso
  assert.strictEqual((await context.request.get('/bff/api/system/dashboard')).status(), 401);
  await context.close();
});
