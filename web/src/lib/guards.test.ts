import { afterEach, describe, expect, it } from 'vitest';
import { upstreamPath } from './allowlist';
import { clientIp } from './client-ip';
import { csrfOk } from './csrf';

describe('allowlist del BFF', () => {
  it('permite las rutas de operación y solo con su método', () => {
    expect(upstreamPath('GET', ['api', 'system', 'dashboard'])).toBe('/api/system/dashboard');
    expect(upstreamPath('GET', ['api', 'metrics'])).toBe('/api/metrics');
    expect(upstreamPath('POST', ['api', 'system', 'approvals', '12', 'approve'])).toBe('/api/system/approvals/12/approve');
    expect(upstreamPath('DELETE', ['api', 'system', 'blocked-ips', '203.0.113.5'])).toBe('/api/system/blocked-ips/203.0.113.5');
    expect(upstreamPath('DELETE', ['api', 'system', 'blocked-ips', '2001:db8::1'])).toBe('/api/system/blocked-ips/2001:db8::1');
    expect(upstreamPath('POST', ['api', 'system', 'dashboard'])).toBeNull();
    expect(upstreamPath('GET', ['api', 'system', 'approvals', '1', 'approve'])).toBeNull();
    expect(upstreamPath('PUT', ['api', 'system', 'alerts'])).toBeNull();
  });

  it('no es un proxy abierto: rutas no listadas, rotar claves y otras APIs', () => {
    for (const path of [['api', 'system', 'rotate-keys'], ['api', 'auth', 'profile'], ['api', 'notes'], ['api', 'files'], ['health'], ['api'], []]) {
      expect(upstreamPath('POST', path)).toBeNull();
      expect(upstreamPath('GET', path)).toBeNull();
    }
  });

  it('rechaza recorridos de directorio, separadores y codificaciones raras', () => {
    const attacks = [
      ['api', 'system', '..', 'auth', 'profile'], ['api', 'system', 'dashboard', '..'], ['api', '.', 'system', 'dashboard'],
      ['api', 'system', 'dashboard/..'], ['api', 'system\\dashboard'], ['api', 'system', 'dashboard?x=1'], ['api', 'system', 'dashboard#x'],
      ['api', 'system', 'blocked-ips', '%2e%2e'], ['api', 'system', 'blocked-ips', '1.2.3.4/../../x'], ['api', 'system', 'dashboard\u0000'],
      ['api', 'system', 'approvals', '0', 'approve'], ['api', 'system', 'approvals', '01', 'approve'], ['api', 'system', 'approvals', '99999999999', 'approve'],
      ['api', 'system', 'approvals', '1 ', 'approve'], ['api', 'system', '', 'dashboard']
    ];
    for (const attack of attacks) expect(upstreamPath('GET', attack) ?? upstreamPath('POST', attack) ?? upstreamPath('DELETE', attack)).toBeNull();
  });
});

describe('CSRF', () => {
  const headers = (h: Record<string, string>) => new Headers({ host: 'ops.example.com', 'x-forwarded-proto': 'https', ...h });
  afterEach(() => { delete process.env.WEB_ORIGIN; });

  it('GET no se comprueba; POST/DELETE exigen cabecera, Origin propio y Sec-Fetch-Site same-origin', () => {
    expect(csrfOk('GET', headers({}))).toBe(true);
    const good = { 'x-ops-csrf': '1', origin: 'https://ops.example.com' };
    expect(csrfOk('POST', headers(good))).toBe(true);
    expect(csrfOk('DELETE', headers({ ...good, 'sec-fetch-site': 'same-origin' }))).toBe(true);
    expect(csrfOk('POST', headers({ origin: 'https://ops.example.com' }))).toBe(false);
    expect(csrfOk('POST', headers({ 'x-ops-csrf': '1' }))).toBe(false);
    expect(csrfOk('POST', headers({ 'x-ops-csrf': '1', origin: 'https://evil.example' }))).toBe(false);
    expect(csrfOk('POST', headers({ 'x-ops-csrf': '1', origin: 'https://ops.example.com.evil.example' }))).toBe(false);
    expect(csrfOk('POST', headers({ ...good, 'sec-fetch-site': 'cross-site' }))).toBe(false);
    expect(csrfOk('POST', headers({ ...good, 'sec-fetch-site': 'same-site' }))).toBe(false);
    expect(csrfOk('POST', headers({ 'x-ops-csrf': '0', origin: 'https://ops.example.com' }))).toBe(false);
  });

  it('WEB_ORIGIN fija el origen aunque el proxy reescriba el Host', () => {
    process.env.WEB_ORIGIN = 'https://panel.example.com/';
    expect(csrfOk('POST', new Headers({ host: 'interno:3100', 'x-ops-csrf': '1', origin: 'https://panel.example.com' }))).toBe(true);
    expect(csrfOk('POST', new Headers({ host: 'interno:3100', 'x-ops-csrf': '1', origin: 'https://interno:3100' }))).toBe(false);
  });
});

describe('IP real del cliente', () => {
  afterEach(() => { delete process.env.WEB_TRUST_PROXY_HOPS; });
  const h = (xff?: string) => new Headers(xff ? { 'x-forwarded-for': xff } : {});

  it('con 1 proxy de confianza se toma el último salto, no lo que escribió el cliente al principio', () => {
    expect(clientIp(h('203.0.113.9'))).toBe('203.0.113.9');
    expect(clientIp(h('1.1.1.1, 203.0.113.9'))).toBe('203.0.113.9');
    expect(clientIp(h('6.6.6.6, 7.7.7.7, 203.0.113.9'))).toBe('203.0.113.9');
  });

  it('con 2 proxies, el penúltimo; con 0 se ignora la cabecera', () => {
    process.env.WEB_TRUST_PROXY_HOPS = '2';
    expect(clientIp(h('1.1.1.1, 203.0.113.9, 10.0.0.1'))).toBe('203.0.113.9');
    process.env.WEB_TRUST_PROXY_HOPS = '0';
    expect(clientIp(h('203.0.113.9'))).toBeNull();
  });

  it('valores que no son IP se descartan (no se reenvía basura al API)', () => {
    for (const bad of ['no-es-ip', '1.2.3.4; drop', '<script>', 'a'.repeat(100)]) expect(clientIp(h(bad))).toBeNull();
    expect(clientIp(h())).toBeNull();
    expect(clientIp(h('2001:db8::1'))).toBe('2001:db8::1');
  });
});
