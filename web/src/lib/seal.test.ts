import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { seal, unseal } from './seal';

const SECRET = 'a'.repeat(16) + 'b'.repeat(16);

describe('seal', () => {
  beforeEach(() => { process.env.WEB_SESSION_SECRET = SECRET; delete process.env.WEB_SESSION_SECRET_PREVIOUS; });
  afterEach(() => { vi.useRealTimers(); });

  it('ida y vuelta, y el valor no contiene el texto claro', () => {
    const value = seal({ token: 'secreto-muy-secreto', n: 1 }, 'session', 60_000);
    expect(value).not.toContain('secreto');
    expect(Buffer.from(value.split('.')[3] as string, 'base64url').toString('utf8')).not.toContain('secreto');
    expect(unseal<{ token: string }>(value, 'session')).toEqual({ token: 'secreto-muy-secreto', n: 1 });
  });

  it('dos cifrados del mismo contenido difieren (IV aleatorio)', () => {
    expect(seal({ a: 1 }, 'session', 1000)).not.toBe(seal({ a: 1 }, 'session', 1000));
  });

  it('cualquier alteración se rechaza', () => {
    const value = seal({ a: 1 }, 'session', 60_000);
    const parts = value.split('.');
    for (let i = 1; i <= 3; i++) {
      const copy = [...parts];
      const raw = Buffer.from(copy[i] as string, 'base64url');
      raw[0] = (raw[0] as number) ^ 1;
      copy[i] = raw.toString('base64url');
      expect(unseal(copy.join('.'), 'session')).toBeNull();
    }
    expect(unseal(value.replace('v1.', 'v2.'), 'session')).toBeNull();
    expect(unseal(`${value}.x`, 'session')).toBeNull();
    expect(unseal('', 'session')).toBeNull();
    expect(unseal(undefined, 'session')).toBeNull();
    expect(unseal('x'.repeat(9000), 'session')).toBeNull();
  });

  it('una cookie de un propósito no vale para otro', () => {
    expect(unseal(seal({ a: 1 }, 'mfa', 60_000), 'session')).toBeNull();
  });

  it('caduca', () => {
    vi.useFakeTimers();
    const value = seal({ a: 1 }, 'session', 1000);
    expect(unseal(value, 'session')).toEqual({ a: 1 });
    vi.advanceTimersByTime(1500);
    expect(unseal(value, 'session')).toBeNull();
  });

  it('con otra clave no se abre; la clave anterior permite rotar sin cerrar sesiones', () => {
    const old = seal({ a: 1 }, 'session', 60_000);
    process.env.WEB_SESSION_SECRET = 'c'.repeat(40);
    expect(unseal(old, 'session')).toBeNull();
    process.env.WEB_SESSION_SECRET_PREVIOUS = SECRET;
    expect(unseal(old, 'session')).toEqual({ a: 1 });
    // y lo nuevo se cifra con la actual: solo vale mientras esa clave esté
    const fresh = seal({ b: 2 }, 'session', 60_000);
    delete process.env.WEB_SESSION_SECRET_PREVIOUS;
    expect(unseal(fresh, 'session')).toEqual({ b: 2 });
  });

  it('exige un secreto largo y presente', () => {
    process.env.WEB_SESSION_SECRET = 'corto';
    expect(() => seal({}, 'session', 1000)).toThrow(/32/);
    expect(unseal('v1.a.b.c', 'session')).toBeNull();
    delete process.env.WEB_SESSION_SECRET;
    expect(() => seal({}, 'session', 1000)).toThrow(/WEB_SESSION_SECRET/);
  });
});
