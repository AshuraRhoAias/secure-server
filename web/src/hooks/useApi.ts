'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import { apiCall, type ApiResult } from '@/lib/client';

// Carga de datos con refresco periódico. Se pausa con la pestaña oculta y descarta respuestas de peticiones antiguas.
export function useApi<T>(path: string | null, { refreshMs = 0 }: { refreshMs?: number } = {}) {
  const [result, setResult] = useState<ApiResult<T> | null>(null);
  const [loading, setLoading] = useState(true);
  const generation = useRef(0);

  const load = useCallback(async () => {
    if (!path) return;
    const mine = ++generation.current;
    const response = await apiCall<T>('GET', path);
    if (mine === generation.current) { setResult(response); setLoading(false); }
  }, [path]);

  useEffect(() => {
    setLoading(true);
    void load();
    if (!refreshMs) return undefined;
    const timer = window.setInterval(() => { if (document.visibilityState === 'visible') void load(); }, refreshMs);
    return () => { window.clearInterval(timer); generation.current++; };
  }, [load, refreshMs]);

  return { data: result?.ok ? result.data : null, error: result && !result.ok ? result : null, loading, reload: load, raw: result };
}
