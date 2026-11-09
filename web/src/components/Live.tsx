'use client';

import { createContext, useContext, useEffect, useRef, useState, type ReactNode } from 'react';
import type { Severity } from '@/lib/types';

// Novedades en vivo: UNA conexión Server-Sent Events por pestaña (/bff/stream) compartida por todas las páginas.
//
//   - Las páginas se suscriben a tipos de mensaje y recargan sus datos al recibirlos (useLiveRefresh); el sondeo periódico se queda
//     como red de seguridad con un intervalo largo.
//   - Reconexión: EventSource reintenta solo (el API manda `retry: 5000` y el último id para no perder nada). Si el API cierra con
//     `reauth` (token caducado o sesión revisada), se reabre enseguida: el BFF renueva la sesión en esa reconexión.
//   - Si la sesión ya no existe, /session/me lo dice y se manda a /login.

export type LiveKind = 'security-event' | 'alert' | 'alerts-summary';
export type LiveState = 'connecting' | 'live' | 'offline';
export interface LiveMessage { kind: LiveKind; data: Record<string, unknown> }
export interface LiveAlert { id: number; severity: Severity; title: string; rule: string; status: string }

interface LiveApi { state: LiveState; subscribe: (kinds: LiveKind[], fn: (message: LiveMessage) => void) => () => void }

const Context = createContext<LiveApi>({ state: 'offline', subscribe: () => () => undefined });
export const useLive = (): LiveApi => useContext(Context);

const KINDS: LiveKind[] = ['security-event', 'alert', 'alerts-summary'];

export function LiveProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<LiveState>('connecting');
  const listeners = useRef(new Set<{ kinds: LiveKind[]; fn: (m: LiveMessage) => void }>());

  useEffect(() => {
    if (typeof window.EventSource !== 'function') { setState('offline'); return undefined; }
    let source: EventSource | null = null;
    let reopen: number | undefined;
    let stopped = false;

    const dispatch = (kind: LiveKind, raw: string) => {
      let data: Record<string, unknown>;
      try { data = JSON.parse(raw) as Record<string, unknown>; } catch { return; }
      for (const listener of listeners.current) if (listener.kinds.includes(kind)) listener.fn({ kind, data });
    };

    const open = () => {
      if (stopped) return;
      setState('connecting');
      source = new EventSource('/bff/stream');
      source.addEventListener('hello', () => setState('live'));
      for (const kind of KINDS) source.addEventListener(kind, (event) => dispatch(kind, (event as MessageEvent<string>).data));
      // El API pide reconectar (reauth: token caducado → el BFF renueva en la siguiente conexión, sin esperar los 5 s de retry;
      // bye: el servidor se reinicia; stream-error: sin acceso a la BD)
      for (const name of ['reauth', 'bye', 'stream-error']) {
        source.addEventListener(name, () => {
          source?.close();
          window.clearTimeout(reopen);
          reopen = window.setTimeout(open, name === 'reauth' ? 300 : 5000);
        });
      }
      source.onerror = () => {
        setState('connecting');
        if (source?.readyState === EventSource.CLOSED) {
          // Cerrado definitivo (respuesta no SSE: 401, 429…): ¿sigue la sesión?
          void fetch('/session/me', { credentials: 'same-origin', cache: 'no-store' }).then((r) => {
            if (r.status === 401) { window.location.assign('/login?expired=1'); return; }
            setState('offline');
            window.clearTimeout(reopen);
            reopen = window.setTimeout(open, 15_000);
          }).catch(() => { setState('offline'); reopen = window.setTimeout(open, 15_000); });
        }
      };
    };

    open();
    return () => { stopped = true; window.clearTimeout(reopen); source?.close(); };
  }, []);

  const api = useRef<LiveApi>({
    state: 'connecting',
    subscribe: (kinds, fn) => {
      const entry = { kinds, fn };
      listeners.current.add(entry);
      return () => { listeners.current.delete(entry); };
    }
  });
  api.current = { ...api.current, state };

  return <Context.Provider value={api.current}>{children}</Context.Provider>;
}

// Recarga `reload` cuando llega alguno de esos mensajes (agrupando ráfagas: como mucho una recarga cada `minGapMs`)
export function useLiveRefresh(kinds: LiveKind[], reload: () => unknown, minGapMs = 1500) {
  const { subscribe } = useLive();
  const reloadRef = useRef(reload);
  reloadRef.current = reload;
  const key = kinds.join(',');
  useEffect(() => {
    let timer: number | undefined;
    let last = 0;
    const unsubscribe = subscribe(key.split(',') as LiveKind[], () => {
      if (timer) return;
      const wait = Math.max(0, last + minGapMs - Date.now());
      timer = window.setTimeout(() => { timer = undefined; last = Date.now(); void reloadRef.current(); }, wait);
    });
    return () => { unsubscribe(); window.clearTimeout(timer); };
  }, [subscribe, key, minGapMs]);
}

export function LiveIndicator() {
  const { state } = useLive();
  const label = state === 'live' ? 'En vivo' : state === 'connecting' ? 'Conectando…' : 'Sin conexión en vivo';
  return <span className="live" data-state={state} role="status" aria-live="polite"><span className="live-dot" aria-hidden="true" />{label}</span>;
}
