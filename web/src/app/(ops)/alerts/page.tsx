'use client';

import { useCallback, useState } from 'react';
import { ConfirmDialog } from '@/components/ConfirmDialog';
import { useToast } from '@/components/Toasts';
import { Banner, Empty, JsonView, Loading, Segmented, SeverityBadge, StatusBadge } from '@/components/ui';
import { useApi } from '@/hooks/useApi';
import { apiCall } from '@/lib/client';
import { dateTime, relativeTime } from '@/lib/format';
import type { AlertItem, Severity } from '@/lib/types';

const STATUSES = [{ value: '', label: 'Todas' }, { value: 'open', label: 'Abiertas' }, { value: 'acknowledged', label: 'Reconocidas' }, { value: 'resolved', label: 'Resueltas' }];
const SEVERITIES = [{ value: '', label: 'Cualquiera' }, { value: 'critical', label: 'Crítica' }, { value: 'high', label: 'Alta' }, { value: 'medium', label: 'Media' }, { value: 'low', label: 'Baja' }];

export default function AlertsPage() {
  const { toast } = useToast();
  const [status, setStatus] = useState('open');
  const [severity, setSeverity] = useState('');
  const [selected, setSelected] = useState<AlertItem | null>(null);
  const [confirm, setConfirm] = useState<{ alert: AlertItem; action: 'ack' | 'resolve' } | null>(null);
  const [busy, setBusy] = useState(false);

  const query = new URLSearchParams({ limit: '200', ...(status && { status }), ...(severity && { severity }) }).toString();
  const { data, error, loading, reload } = useApi<{ alerts: AlertItem[] }>(`/api/system/alerts?${query}`, { refreshMs: 15_000 });

  const act = useCallback(async (alert: AlertItem, action: 'ack' | 'resolve') => {
    setBusy(true);
    const result = await apiCall('POST', `/api/system/alerts/${alert.id}/${action}`, {});
    setBusy(false);
    setConfirm(null);
    if (result.ok) { toast(action === 'ack' ? 'Alerta reconocida' : 'Alerta resuelta', 'ok'); void reload(); }
    else toast(result.message, 'error');
  }, [reload, toast]);

  const evaluate = async () => {
    const result = await apiCall<{ result: { created: number; updated: number; errors: string[] } }>('POST', '/api/system/alerts/evaluate', {});
    if (result.ok) { toast(`Evaluación hecha: ${result.data?.result.created ?? 0} nuevas, ${result.data?.result.updated ?? 0} actualizadas`, 'ok'); void reload(); }
    else toast(result.message, 'error');
  };

  const alerts = data?.alerts ?? [];
  return (
    <div className="stack">
      <div className="row">
        <h1 className="grow-title">Alertas</h1>
        <button type="button" onClick={evaluate}>Evaluar ahora</button>
      </div>
      <div className="row">
        <Segmented label="Estado" value={status} onChange={setStatus} options={STATUSES} />
        <Segmented label="Severidad" value={severity} onChange={setSeverity} options={SEVERITIES} />
      </div>
      {error ? <Banner tone="error">{error.message}</Banner> : null}
      {loading && !data ? <Loading /> : null}
      {data && alerts.length === 0 ? <div className="card"><Empty>No hay alertas con este filtro.</Empty></div> : null}
      {alerts.length > 0 ? (
        <div className="table-wrap"><table>
          <thead><tr><th>Severidad</th><th>Alerta</th><th>Sujeto</th><th className="num">Veces</th><th>Estado</th><th>Última vez</th><th>Acciones</th></tr></thead>
          <tbody>{alerts.map(a => (
            <tr key={a.id}>
              <td><SeverityBadge severity={a.severity as Severity} /></td>
              <td><button type="button" className="ghost small" onClick={() => setSelected(a)}>{a.title}</button><div className="muted mono">{a.rule}</div></td>
              <td className="truncate mono" title={a.subject ?? ''}>{a.subject ?? '—'}</td>
              <td className="num">{a.count}</td>
              <td><StatusBadge status={a.status} />{a.notifyError ? <div className="muted" title={a.notifyError}>aviso externo falló</div> : null}</td>
              <td title={dateTime(a.lastSeen)}>{relativeTime(a.lastSeen)}</td>
              <td><div className="page-actions">
                {a.status === 'open' ? <button type="button" className="small" onClick={() => setConfirm({ alert: a, action: 'ack' })}>Reconocer</button> : null}
                {a.status !== 'resolved' ? <button type="button" className="small primary" onClick={() => setConfirm({ alert: a, action: 'resolve' })}>Resolver</button> : null}
              </div></td>
            </tr>
          ))}</tbody>
        </table></div>
      ) : null}

      <dialog open={Boolean(selected)} className="wide" aria-label="Detalle de la alerta" ref={node => { if (node) { if (selected && !node.open) node.showModal(); if (!selected && node.open) node.close(); } }} onCancel={e => { e.preventDefault(); setSelected(null); }}>
        {selected ? (
          <div className="stack">
            <h2>{selected.title}</h2>
            <div className="row"><SeverityBadge severity={selected.severity} /><StatusBadge status={selected.status} /><span className="mono muted">{selected.rule}</span></div>
            <dl className="kv"><dt>Sujeto</dt><dd className="mono">{selected.subject ?? '—'}</dd><dt>Primera vez</dt><dd>{dateTime(selected.firstSeen)}</dd><dt>Última vez</dt><dd>{dateTime(selected.lastSeen)}</dd><dt>Eventos</dt><dd>{selected.count}</dd></dl>
            <JsonView value={selected.details ?? {}} />
            <div className="row"><button type="button" onClick={() => setSelected(null)}>Cerrar</button></div>
          </div>
        ) : null}
      </dialog>

      <ConfirmDialog open={Boolean(confirm)} busy={busy} title={confirm?.action === 'ack' ? 'Reconocer alerta' : 'Resolver alerta'}
        confirmLabel={confirm?.action === 'ack' ? 'Reconocer' : 'Resolver'} onCancel={() => setConfirm(null)} onConfirm={() => { if (confirm) void act(confirm.alert, confirm.action); }}>
        <p>{confirm?.alert.title}</p>
        <p className="muted">{confirm?.action === 'ack' ? 'Indica que alguien la está mirando. Una alerta reconocida sin recurrencia se resuelve sola; una abierta, no.' : 'Se cierra. Si la condición vuelve a darse, se creará otra.'}</p>
      </ConfirmDialog>
    </div>
  );
}
