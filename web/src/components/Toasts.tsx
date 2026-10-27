'use client';

import { createContext, useCallback, useContext, useMemo, useState, type ReactNode } from 'react';

type Tone = 'ok' | 'error' | 'info';
interface Toast { id: number; tone: Tone; text: string }
interface ToastApi { toast: (text: string, tone?: Tone) => void }

const Context = createContext<ToastApi>({ toast: () => undefined });
export const useToast = (): ToastApi => useContext(Context);

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const toast = useCallback((text: string, tone: Tone = 'info') => {
    const id = Date.now() + Math.random();
    setToasts(current => [...current.slice(-3), { id, tone, text }]);
    window.setTimeout(() => setToasts(current => current.filter(t => t.id !== id)), tone === 'error' ? 8000 : 4500);
  }, []);
  const api = useMemo(() => ({ toast }), [toast]);
  return (
    <Context.Provider value={api}>
      {children}
      <div className="toasts" aria-live="polite" aria-atomic="false">
        {toasts.map(t => <div key={t.id} className="toast" data-tone={t.tone} role={t.tone === 'error' ? 'alert' : 'status'}>{t.text}</div>)}
      </div>
    </Context.Provider>
  );
}
