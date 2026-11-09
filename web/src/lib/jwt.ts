// Lee (SIN verificar) el contenido de un JWT que acaba de entregar el propio API por HTTPS: solo para mostrar el nombre y saber qué
// usuario es. La autorización la decide siempre el API.
export interface AccessClaims { userId: number; username: string; amr: string[] }

export function decodeAccessToken(token: string): AccessClaims | null {
  try {
    const part = token.split('.')[1];
    if (!part) return null;
    const claims = JSON.parse(Buffer.from(part, 'base64url').toString('utf8')) as Record<string, unknown>;
    if (typeof claims.userId !== 'number' || typeof claims.username !== 'string') return null;
    return { userId: claims.userId, username: claims.username, amr: Array.isArray(claims.amr) ? claims.amr.filter((m): m is string => typeof m === 'string') : [] };
  } catch {
    return null;
  }
}
