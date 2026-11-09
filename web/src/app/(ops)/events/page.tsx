'use client';

import { useCallback, useEffect, useState, type FormEvent } from 'react';
import { useToast } from '@/components/Toasts';
import { Banner, Empty, JsonView, Loading, SeverityBadge } from '@/components/ui';
import { apiCall } from '@/lib/client';
import { dateTime } from '@/lib/format';
import type { EventItem } from '@/lib/types';

interface Filters { type: string; rule: string; severity: string; ip: string; userId: string; hours: string }
const EMPTY: Filters = { type: '', rule: '', severity: '', ip: '', userId: '', hours: '24' };
const PAGE = 100;

const toQuery = (filters: Filters, before?: number): string => {
  const params = new URLSearchParams({ limit: String(PAGE) });
  for (const [key, value] of Object.entries(filters)) if (value.trim()) params.set(key, value.trim());
  if (before) params.set('before', String(before));
  return params.toString();
};

function csv(rows: EventItem[]): string {
  const escape = (value: unknown) => { const text = value === null || value === undefined ? '' : typeof value === 'object' ? JSON.stringify(value) : String(value); return /[",\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text; };
  const header = ['id', 'fecha', 'tipo', 'regla', 'severidad', 'riesgo', 'accion', 'ip', 'usuario', 'metodo', 'ruta', 'estado', 'pais', 'detalles'];
  return [header.join(','), ...rows.map(r => [r.id, r.created_at, r.event_type, r.rule, r.severity, r.risk_score, r.action_taken, r.ip_address, r.user_id, r.method, r.path, r.status_code, r.country, r.details].map(escape).join(','))].join('\n');
}

export default function EventsPage() {
  const { toast } = useToast();
  const [draft, setDraft] = useState<Filters>(EMPTY);
  const [applied, setApplied] = useState<Filters>(EMPTY);
  const [rows, setRows] = useState<EventItem[]>([]);
  const [more, setMore] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [open, setOpen] = useState<number | null>(null);

  const load = useCallback(async (filters: Filters, before?: number) => {
    setLoading(true); setError(null);
    const result = await apiCall<{ events: EventItem[] }>('GET', `/api/system/security-events?${toQuery(filters, before)}`);
    setLoading(false);
    if (!result.ok) { setError(result.message); return; }
    const list = result.data?.events ?? [];
    setRows(current => (before ? [...current, ...list] : list));
    setMore(list.length === PAGE);
  }, []);

  useEffect(() => { void load(applied); }, [applied, load]);

  const submit = (event: FormEvent) => { event.preventDefault(); setApplied({ ...draft }); };
  const field = (key: keyof Filters, label: string, props: { placeholder?: string; inputMode?: 'numeric' } = {}) => (
    <label>{label}<input value={draft[key]} onChange={e => setDraft({ ...draft, [key]: e.target.value })} maxLength={64} {...props} /></label>
  );

  const download = () => {
    const url = URL.createObjectURL(new Blob([csv(rows)], { type: 'text/csv;charset=utf-8' }));
    const link = document.createElement('a');
    link.href = url; link.download = `eventos-${new Date().toISOString().slice(0, 19)}.csv`;
    document.body.appendChild(link); link.click(); link.remove(); URL.revokeObjectURL(url);
    toast(`Exportadas ${rows.length} filas`, 'ok');
  };

  return (
    <div className="stack">
      <h1>Eventos de seguridad</h1>
      <form className="card field-row" onSubmit={submit} aria-label="Filtros">
        {field('type', 'Tipo', { placeholder: 'LOGIN_FAILED…' })}
        {field('rule', 'Regla')}
        <label>Severidad
          <select value={draft.severity} onChange={e => setDraft({ ...draft, severity: e.target.value })}>
            <option value="">Cualquiera</option>{['critical', 'high', 'medium', 'low', 'info'].map(s => <option key={s} value={s}>{s}</option>)}
          </select>
        </label>
        {field('ip', 'IP')}
        {field('userId', 'Id de usuario', { inputMode: 'numeric' })}
        <label>Ventana
          <select value={draft.hours} onChange={e => setDraft({ ...draft, hours: e.target.value })}>
            {[['1', '1 hora'], ['6', '6 horas'], ['24', '24 horas'], ['168', '7 días'], ['720', '30 días'], ['2160', '90 días']].map(([v, l]) => <option key={v} value={v}>{l}</option>)}
          </select>
        </label>
        <button type="submit" className="primary">Filtrar</button>
        <button type="button" onClick={() => { setDraft(EMPTY); setApplied(EMPTY); }}>Limpiar</button>
        <button type="button" onClick={download} disabled={rows.length === 0}>Exportar CSV</button>
      </form>

      {error ? <Banner tone="error">{error}</Banner> : null}
      {loading && rows.length === 0 ? <Loading /> : null}
      {!loading && rows.length === 0 && !error ? <div className="card"><Empty>Ningún evento con estos filtros.</Empty></div> : null}
      {rows.length > 0 ? (
        <div className="table-wrap"><table>
          <thead><tr><th>Fecha</th><th>Severidad</th><th>Tipo / regla</th><th>IP</th><th>Usuario</th><th>Petición</th><th className="num">Riesgo</th></tr></thead>
          <tbody>{rows.map(row => (
            <FragmentRow key={row.id} row={row} open={open === row.id} toggle={() => setOpen(open === row.id ? null : row.id)} />
          ))}</tbody>
        </table></div>
      ) : null}
      <div className="row">
        <span className="muted">{rows.length} eventos cargados</span>
        {more ? <button type="button" onClick={() => { const last = rows.at(-1); if (last) void load(applied, last.id); }} disabled={loading}>Cargar más</button> : null}
      </div>
    </div>
  );
}

function FragmentRow({ row, open, toggle }: { row: EventItem; open: boolean; toggle: () => void }) {
  return (
    <>
      <tr>
        <td title={row.created_at}>{dateTime(row.created_at)}</td>
        <td><SeverityBadge severity={row.severity} /></td>
        <td><button type="button" className="ghost small" onClick={toggle} aria-expanded={open}>{row.event_type}</button>{row.rule ? <div className="muted mono">{row.rule}</div> : null}</td>
        <td className="mono">{row.ip_address ?? '—'}{row.country ? <span className="muted"> {row.country}</span> : null}</td>
        <td className="mono">{row.user_id ?? '—'}</td>
        <td className="truncate mono" title={`${row.method ?? ''} ${row.path ?? ''}`}>{row.method ? `${row.method} ${row.path ?? ''}` : '—'}{row.status_code ? <span className="muted"> → {row.status_code}</span> : null}</td>
        <td className="num">{row.risk_score}</td>
      </tr>
      {open ? <tr><td colSpan={7}><JsonView value={{ accion: row.action_taken, detalles: row.details }} /></td></tr> : null}
    </>
  );
}
