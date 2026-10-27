'use client';

import { useEffect, useState } from 'react';
import { ConfirmDialog } from '@/components/ConfirmDialog';
import { useToast } from '@/components/Toasts';
import { Banner, Empty, Loading, Segmented, StatusBadge } from '@/components/ui';
import { useApi } from '@/hooks/useApi';
import { apiCall } from '@/lib/client';
import { dateTime, relativeTime } from '@/lib/format';
import type { ApprovalItem } from '@/lib/types';

const ACTIONS: Record<string, string> = { mfa_reset: 'Reset de MFA', user_erase: 'Borrado de datos de un usuario' };
const STATUSES = [{ value: '', label: 'Todas' }, { value: 'pending', label: 'Pendientes' }, { value: 'executed', label: 'Ejecutadas' }, { value: 'rejected', label: 'Rechazadas' }, { value: 'failed', label: 'Fallidas' }];

export default function ApprovalsPage() {
  const { toast } = useToast();
  const [status, setStatus] = useState('pending');
  const [me, setMe] = useState<number | null>(null);
  const [confirm, setConfirm] = useState<{ item: ApprovalItem; decision: 'approve' | 'reject' } | null>(null);
  const [busy, setBusy] = useState(false);
  const { data, error, loading, reload } = useApi<{ approvals: ApprovalItem[] }>(`/api/system/approvals${status ? `?status=${status}` : ''}`, { refreshMs: 15_000 });

  useEffect(() => { void apiCall<{ userId: number }>('GET', '/session/me').then(r => { if (r.ok && r.data) setMe(r.data.userId); }); }, []);

  async function decide(item: ApprovalItem, decision: 'approve' | 'reject') {
    setBusy(true);
    const result = await apiCall<{ status?: string }>('POST', `/api/system/approvals/${item.id}/${decision}`, {});
    setBusy(false); setConfirm(null);
    if (result.ok) { toast(decision === 'approve' ? `Aprobada (${result.data?.status ?? 'ejecutada'})` : 'Rechazada', 'ok'); void reload(); }
    else toast(result.message, 'error');
  }

  const items = data?.approvals ?? [];
  return (
    <div className="stack">
      <h1>Aprobaciones de dos administradores</h1>
      <p className="muted">Las acciones más peligrosas (resetear el MFA de alguien, borrar sus datos) no se ejecutan al pedirlas: las aprueba <strong>otro</strong> administrador. Quien las solicita no puede aprobar la suya.</p>
      <Segmented label="Estado" value={status} onChange={setStatus} options={STATUSES} />
      {error ? <Banner tone="error">{error.message}</Banner> : null}
      {loading && !data ? <Loading /> : null}
      {data && items.length === 0 ? <div className="card"><Empty>No hay solicitudes con este filtro.</Empty></div> : null}
      {items.length > 0 ? (
        <div className="table-wrap"><table>
          <thead><tr><th>#</th><th>Acción</th><th>Usuario afectado</th><th>Motivo</th><th>Pidió</th><th>Estado</th><th>Caduca</th><th>Decisión</th></tr></thead>
          <tbody>{items.map(item => {
            const own = me !== null && item.requestedBy.id === me;
            const pending = item.status === 'pending';
            return (
              <tr key={item.id}>
                <td className="mono">{item.id}</td>
                <td>{ACTIONS[item.action] ?? item.action}</td>
                <td>{item.target ? `${item.target.username ?? '(sin nombre)'} (#${item.target.id})` : '—'}</td>
                <td className="pre-wrap">{item.reason}</td>
                <td>{item.requestedBy.username ?? `#${item.requestedBy.id}`}{own ? <span className="muted"> (tú)</span> : null}<div className="muted" title={dateTime(item.requestedAt)}>{relativeTime(item.requestedAt)}</div></td>
                <td><StatusBadge status={item.status} /></td>
                <td title={dateTime(item.expiresAt)}>{pending ? relativeTime(item.expiresAt) : '—'}</td>
                <td>{pending ? (
                  <div className="page-actions">
                    <button type="button" className="small primary" disabled={own} title={own ? 'No puedes aprobar tu propia solicitud' : undefined} onClick={() => setConfirm({ item, decision: 'approve' })}>Aprobar</button>
                    <button type="button" className="small" onClick={() => setConfirm({ item, decision: 'reject' })}>Rechazar</button>
                  </div>
                ) : '—'}</td>
              </tr>
            );
          })}</tbody>
        </table></div>
      ) : null}
      <ConfirmDialog open={Boolean(confirm)} busy={busy} danger={confirm?.decision === 'approve'}
        title={confirm?.decision === 'approve' ? 'Aprobar y ejecutar' : 'Rechazar solicitud'} confirmLabel={confirm?.decision === 'approve' ? 'Aprobar y ejecutar' : 'Rechazar'}
        onCancel={() => setConfirm(null)} onConfirm={() => { if (confirm) void decide(confirm.item, confirm.decision); }}>
        {confirm ? <>
          <p><strong>{ACTIONS[confirm.item.action] ?? confirm.item.action}</strong> sobre {confirm.item.target?.username ?? 'el usuario indicado'}.</p>
          <p className="pre-wrap muted">Motivo: {confirm.item.reason}</p>
          {confirm.decision === 'approve' ? <Banner tone="warn">Se ejecuta al instante y no se puede deshacer.</Banner> : null}
        </> : null}
      </ConfirmDialog>
    </div>
  );
}
