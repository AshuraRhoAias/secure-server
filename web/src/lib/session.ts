import { mfaCookieName, cookieSecure, sessionCookieName } from './config';
import { seal, unseal } from './seal';

// Lo que guarda la cookie de sesión (cifrada): los tokens del API y cuándo caducan.
export interface Session {
  at: string;   // JWT de acceso (15 min)
  rt: string;   // refresh token (rota en cada uso)
  ae: number;   // caducidad del JWT de acceso (ms)
  se: number;   // caducidad absoluta de la sesión (ms)
  u: string;    // nombre de usuario (solo para mostrar)
  uid: number;  // id de usuario
}

export interface MfaChallenge { token: string; u: string }

const SESSION = 'session';
const MFA = 'mfa';
export const MFA_TTL_MS = 5 * 60_000;

export interface CookieSpec {
  name: string;
  value: string;
  options: { httpOnly: true; secure: boolean; sameSite: 'strict'; path: '/'; maxAge: number };
}

const options = (maxAgeSeconds: number): CookieSpec['options'] => ({ httpOnly: true, secure: cookieSecure(), sameSite: 'strict', path: '/', maxAge: maxAgeSeconds });

export function sessionCookie(session: Session): CookieSpec {
  const ttl = Math.max(1000, session.se - Date.now());
  return { name: sessionCookieName(), value: seal(session, SESSION, ttl), options: options(Math.floor(ttl / 1000)) };
}

export const clearSessionCookie = (): CookieSpec => ({ name: sessionCookieName(), value: '', options: options(0) });
export const clearMfaCookie = (): CookieSpec => ({ name: mfaCookieName(), value: '', options: options(0) });

export function mfaCookie(challenge: MfaChallenge): CookieSpec {
  return { name: mfaCookieName(), value: seal(challenge, MFA, MFA_TTL_MS), options: options(MFA_TTL_MS / 1000) };
}

export function readSession(value: string | undefined | null): Session | null {
  const session = unseal<Session>(value, SESSION);
  if (!session || typeof session.at !== 'string' || typeof session.rt !== 'string' || typeof session.se !== 'number') return null;
  return session.se > Date.now() ? session : null;
}

export const readMfaChallenge = (value: string | undefined | null): MfaChallenge | null => unseal<MfaChallenge>(value, MFA);

const toMs = (value: unknown, fallback: number): number => {
  const ms = typeof value === 'string' ? Date.parse(value) : NaN;
  return Number.isFinite(ms) ? ms : fallback;
};

// Campos de token de /api/auth/login, /login/mfa y /refresh → Session
export function sessionFromTokens(body: Record<string, unknown>, who: { u: string; uid: number }, now = Date.now()): Session | null {
  if (typeof body.token !== 'string' || typeof body.refreshToken !== 'string') return null;
  const expiresIn = typeof body.expiresIn === 'number' ? body.expiresIn : 900;
  return {
    at: body.token,
    rt: body.refreshToken,
    ae: toMs(body.expiresAt, now + expiresIn * 1000),
    se: toMs(body.sessionExpiresAt, now + 30 * 86_400_000),
    u: who.u,
    uid: who.uid
  };
}
