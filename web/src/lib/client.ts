'use client';

// Cliente del navegador: SOLO habla con esta misma aplicación (/bff y /session). Nunca ve tokens.
export interface ApiResult<T> { ok: boolean; status: number; data: T | null; message: string; code: string | null; text: string | null }

const sleep = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

export async function apiCall<T = unknown>(method: 'GET' | 'POST' | 'DELETE', path: string, body?: unknown, options: { text?: boolean } = {}): Promise<ApiResult<T>> {
  const url = path.startsWith('/session/') ? path : `/bff${path}`;
  for (let attempt = 0; attempt < 2; attempt++) {
    let response: Response;
    try {
      response = await fetch(url, {
        method,
        headers: { 'x-ops-csrf': '1', ...(body !== undefined && { 'Content-Type': 'application/json' }) },
        body: body !== undefined ? JSON.stringify(body) : undefined,
        credentials: 'same-origin',
        cache: 'no-store'
      });
    } catch {
      return { ok: false, status: 0, data: null, message: 'Sin conexión con el servidor', code: 'NETWORK', text: null };
    }

    // Otra pestaña renovó la sesión a la vez: la cookie nueva ya viene en camino, se reintenta una vez
    if (response.status === 409 && attempt === 0) { await sleep(400); continue; }

    if (response.status === 401 && !path.startsWith('/session/')) {
      if (typeof window !== 'undefined') window.location.assign('/login?expired=1');
      return { ok: false, status: 401, data: null, message: 'La sesión terminó', code: 'NO_SESSION', text: null };
    }

    const raw = await response.text();
    if (options.text && response.ok) return { ok: true, status: response.status, data: null, message: '', code: null, text: raw };
    let parsed: unknown = null;
    try { parsed = JSON.parse(raw); } catch { /* texto */ }
    const record = parsed && typeof parsed === 'object' ? (parsed as Record<string, unknown>) : null;
    return {
      ok: response.ok && (record?.success !== false),
      status: response.status,
      data: (record as T | null),
      message: typeof record?.message === 'string' ? record.message : response.ok ? '' : `Error ${response.status}`,
      code: typeof record?.code === 'string' ? record.code : null,
      text: null
    };
  }
  return { ok: false, status: 409, data: null, message: 'La sesión se está renovando: reintenta', code: 'REFRESH_CONFLICT', text: null };
}
