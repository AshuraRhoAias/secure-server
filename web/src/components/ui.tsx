'use client';

import type { ReactNode } from 'react';
import type { Severity } from '@/lib/types';

export type Tone = 'critical' | 'high' | 'medium' | 'low' | 'info' | 'ok' | 'neutral';

export const Badge = ({ tone = 'neutral', children }: { tone?: Tone; children: ReactNode }) => <span className="badge" data-tone={tone}>{children}</span>;

const SEVERITY_LABEL: Record<string, string> = { critical: 'Crítica', high: 'Alta', medium: 'Media', low: 'Baja', info: 'Info' };
export const SeverityBadge = ({ severity }: { severity: Severity | string }) => (
  <Badge tone={(['critical', 'high', 'medium', 'low', 'info'] as const).includes(severity as Severity) ? (severity as Tone) : 'neutral'}>{SEVERITY_LABEL[severity] ?? severity}</Badge>
);

const STATUS: Record<string, { label: string; tone: Tone }> = {
  open: { label: 'Abierta', tone: 'high' }, acknowledged: { label: 'Reconocida', tone: 'medium' }, resolved: { label: 'Resuelta', tone: 'ok' },
  pending: { label: 'Pendiente', tone: 'medium' }, approved: { label: 'Aprobada', tone: 'low' }, executed: { label: 'Ejecutada', tone: 'ok' },
  failed: { label: 'Fallida', tone: 'critical' }, rejected: { label: 'Rechazada', tone: 'neutral' }, cancelled: { label: 'Cancelada', tone: 'neutral' }, expired: { label: 'Caducada', tone: 'neutral' }
};
export const StatusBadge = ({ status }: { status: string }) => <Badge tone={STATUS[status]?.tone ?? 'neutral'}>{STATUS[status]?.label ?? status}</Badge>;

export function Stat({ label, value, hint, tone }: { label: string; value: ReactNode; hint?: ReactNode; tone?: 'critical' | 'high' | 'ok' }) {
  return (
    <div className="card stat" data-tone={tone}>
      <span className="label">{label}</span>
      <span className="value">{value}</span>
      {hint ? <span className="hint">{hint}</span> : null}
    </div>
  );
}

export const Card = ({ title, actions, children }: { title?: ReactNode; actions?: ReactNode; children: ReactNode }) => (
  <section className="card">
    {(title || actions) && (
      <div className="row">
        {title ? <h2 className="grow-title">{title}</h2> : null}
        {actions}
      </div>
    )}
    {children}
  </section>
);

export const Banner = ({ tone, children }: { tone?: 'error' | 'ok' | 'warn'; children: ReactNode }) => <div className="banner" data-tone={tone} role={tone === 'error' ? 'alert' : 'status'}>{children}</div>;
export const Empty = ({ children }: { children: ReactNode }) => <div className="empty">{children}</div>;

export function JsonView({ value }: { value: unknown }) {
  return <pre className="json">{JSON.stringify(value, null, 2)}</pre>;
}

export function Segmented<T extends string | number>({ value, onChange, options, label }: { value: T; onChange: (value: T) => void; options: { value: T; label: string }[]; label: string }) {
  return (
    <div className="segmented" role="group" aria-label={label}>
      {options.map(option => (
        <button key={String(option.value)} type="button" aria-pressed={option.value === value} onClick={() => onChange(option.value)}>{option.label}</button>
      ))}
    </div>
  );
}

export const Loading = () => <div className="empty" role="status">Cargando…</div>;
