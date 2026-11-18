'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { useEffect, useState, type ReactNode } from 'react';
import { apiCall, beginLeave } from '@/lib/client';
import { applyStoredMotion, storeMotion, type MotionPref } from './Backdrop3D';
import { dateTime } from '@/lib/format';
import type { Dashboard } from '@/lib/types';
import { useApi } from '@/hooks/useApi';
import { LiveIndicator, LiveProvider, useLive, useLiveRefresh } from './Live';
import { ToastProvider, useToast } from './Toasts';

// Aviso inmediato de las alertas nuevas graves (high/critical) que llegan por el canal en vivo
function LiveAlertToasts() {
  const { subscribe } = useLive();
  const { toast } = useToast();
  useEffect(() => subscribe(['alert'], ({ data }) => {
    if (data.severity === 'critical' || data.severity === 'high') toast(`Alerta ${String(data.severity)}: ${String(data.title ?? data.rule ?? '')}`, 'error');
  }), [subscribe, toast]);
  return null;
}

const NAV = [
  { href: '/', label: 'Panel', icon: '▦' },
  { href: '/alerts', label: 'Alertas', icon: '⚠', badge: 'alerts' },
  { href: '/approvals', label: 'Aprobaciones', icon: '✔', badge: 'approvals' },
  { href: '/events', label: 'Eventos', icon: '☰' },
  { href: '/network', label: 'IP y cuentas', icon: '⛨' },
  { href: '/users', label: 'Usuarios y sesiones', icon: '☺' },
  { href: '/metrics', label: 'Métricas', icon: '∿' },
  { href: '/settings', label: 'Configuración', icon: '☷' },
  { href: '/system', label: 'Sistema', icon: '⚙' }
] as const;

type Theme = 'auto' | 'light' | 'dark';

function useTheme() {
  const [theme, setTheme] = useState<Theme>('auto');
  useEffect(() => {
    try { const saved = window.localStorage.getItem('ops-theme'); if (saved === 'light' || saved === 'dark') setTheme(saved); } catch { /* sin almacenamiento */ }
  }, []);
  useEffect(() => {
    if (theme === 'auto') document.documentElement.removeAttribute('data-theme'); else document.documentElement.setAttribute('data-theme', theme);
    try { if (theme === 'auto') window.localStorage.removeItem('ops-theme'); else window.localStorage.setItem('ops-theme', theme); } catch { /* sin almacenamiento */ }
  }, [theme]);
  return [theme, () => setTheme(t => (t === 'auto' ? 'dark' : t === 'dark' ? 'light' : 'auto'))] as const;
}

// Movimiento: auto (sigue al sistema; el fondo 3D va lento si pide reducir) → activado (todo animado) → reducido (sin animaciones)
function useMotion() {
  const [motion, setMotion] = useState<MotionPref>('auto');
  useEffect(() => { setMotion(applyStoredMotion()); }, []);
  const cycle = () => setMotion(m => { const next: MotionPref = m === 'auto' ? 'on' : m === 'on' ? 'off' : 'auto'; storeMotion(next); return next; });
  return [motion, cycle] as const;
}

export function Shell({ user, children }: { user: string; children: ReactNode }) {
  return (
    <ToastProvider>
      <LiveProvider>
        <LiveAlertToasts />
        <ShellFrame user={user}>{children}</ShellFrame>
      </LiveProvider>
    </ToastProvider>
  );
}

function ShellFrame({ user, children }: { user: string; children: ReactNode }) {
  const pathname = usePathname();
  const [open, setOpen] = useState(false);
  const [theme, cycleTheme] = useTheme();
  const [motion, cycleMotion] = useMotion();
  const [session, setSession] = useState<string | null>(null);
  // Contadores del menú: se actualizan al momento con el canal en vivo; el sondeo queda como respaldo
  const summary = useApi<{ dashboard: Dashboard }>('/api/system/dashboard?hours=1', { refreshMs: 120_000 });
  useLiveRefresh(['alerts-summary', 'alert'], summary.reload, 3000);

  useEffect(() => { setOpen(false); }, [pathname]);
  useEffect(() => {
    void apiCall<{ sessionExpiresAt: string }>('GET', '/session/me').then(r => { if (r.ok && r.data) setSession(r.data.sessionExpiresAt); });
  }, []);

  const dashboard = summary.data?.dashboard;
  const open_alerts = dashboard ? Object.values(dashboard.alerts.open).reduce((a, b) => a + b, 0) : 0;
  const badges: Record<string, number> = { alerts: open_alerts, approvals: dashboard?.approvals.pending ?? 0 };

  const logout = async () => { beginLeave(); await apiCall('POST', '/session/logout', {}); window.location.assign('/login'); };

  return (
    <>
      <a className="skip-link" href="#contenido">Saltar al contenido</a>
      <div className="shell">
        <aside className="sidebar" data-open={open} aria-label="Navegación">
          <div className="brand"><span className="brand-mark" aria-hidden="true">⛨</span><span>secure-server<br /><span className="muted">Operación</span></span></div>
          <nav className="nav">
            {NAV.map(item => {
              const active = item.href === '/' ? pathname === '/' : pathname.startsWith(item.href);
              const count = 'badge' in item ? badges[item.badge] ?? 0 : 0;
              return (
                <Link key={item.href} href={item.href} aria-current={active ? 'page' : undefined}>
                  <span aria-hidden="true">{item.icon}</span>{item.label}
                  {count > 0 ? <span className="count" aria-label={`${count} pendientes`}>{count}</span> : null}
                </Link>
              );
            })}
          </nav>
          <div className="sidebar-foot">
            <div>Sesión de <strong>{user}</strong></div>
            {session ? <div>Hasta {dateTime(session)}</div> : null}
          </div>
        </aside>
        <div className="main">
          <div className="topbar">
            <button type="button" className="menu-button" onClick={() => setOpen(o => !o)} aria-label="Abrir menú" aria-expanded={open}>☰</button>
            <span className="spacer" />
            <LiveIndicator />
            <button type="button" className="ghost" onClick={cycleMotion} title="Cambiar animaciones">{motion === 'auto' ? 'Movimiento: auto' : motion === 'on' ? 'Movimiento: activado' : 'Movimiento: reducido'}</button>
            <button type="button" className="ghost" onClick={cycleTheme} title="Cambiar tema">{theme === 'auto' ? 'Tema: auto' : theme === 'dark' ? 'Tema: oscuro' : 'Tema: claro'}</button>
            <button type="button" onClick={logout}>Cerrar sesión</button>
          </div>
          <main id="contenido" tabIndex={-1}>{children}</main>
        </div>
      </div>
    </>
  );
}
