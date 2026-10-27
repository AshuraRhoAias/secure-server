'use client';

import { useState, type FormEvent } from 'react';
import { ConfirmDialog } from '@/components/ConfirmDialog';
import { useToast } from '@/components/Toasts';
import { Banner, Empty, Loading } from '@/components/ui';
import { useApi } from '@/hooks/useApi';
import { apiCall } from '@/lib/client';
import { dateTime, relativeTime } from '@/lib/format';
import type { BlockedIp } from '@/lib/types';

export default function NetworkPage() {
  const { toast } = useToast();
  const { data, error, loading, reload } = useApi<{ blockedIPs: BlockedIp[] }>('/api/system/blocked-ips', { refreshMs: 20_000 });
  const [unblock, setUnblock] = useState<BlockedIp | null>(null);
  const [busy, setBusy] = useState(false);
  const [username, setUsername] = useState('');

  async function doUnblock(ip: BlockedIp) {
    setBusy(true);
    const result = await apiCall('DELETE', `/api/system/blocked-ips/${encodeURIComponent(ip.ip_address)}`);
    setBusy(false); setUnblock(null);
    if (result.ok) { toast(`IP ${ip.ip_address} desbloqueada`, 'ok'); void reload(); } else toast(result.message, 'error');
  }

  async function unlock(event: FormEvent) {
    event.preventDefault();
    const result = await apiCall('POST', '/api/system/accounts/unlock', { username: username.trim() });
    if (result.ok) { toast(`Cuenta «${username.trim()}» liberada`, 'ok'); setUsername(''); } else toast(result.message, 'error');
  }

  const ips = data?.blockedIPs ?? [];
  return (
    <div className="stack">
      <h1>IP bloqueadas y cuentas</h1>
      {error ? <Banner tone="error">{error.message}</Banner> : null}
      {loading && !data ? <Loading /> : null}
      <section className="stack">
        <h2>IP bloqueadas</h2>
        <p className="muted">Los bloqueos son progresivos (1 h, 2 h, 4 h… hasta 7 días) y viven en la base de datos: sobreviven a reinicios y valen para todas las instancias (hasta 1 s de retraso entre instancias por la caché de bloqueos).</p>
        {data && ips.length === 0 ? <div className="card"><Empty>No hay IP bloqueadas.</Empty></div> : null}
        {ips.length > 0 ? (
          <div className="table-wrap"><table>
            <thead><tr><th>IP</th><th>Motivo</th><th>Hasta</th><th className="num">Veces</th><th>Desde</th><th /></tr></thead>
            <tbody>{ips.map(ip => (
              <tr key={ip.ip_address}>
                <td className="mono">{ip.ip_address}</td><td>{ip.reason}</td>
                <td title={dateTime(ip.blocked_until)}>{new Date(ip.blocked_until).getTime() > Date.now() ? relativeTime(ip.blocked_until) : 'caducado'}</td>
                <td className="num">{ip.block_count}</td><td title={dateTime(ip.created_at)}>{relativeTime(ip.created_at)}</td>
                <td><button type="button" className="small" onClick={() => setUnblock(ip)}>Desbloquear</button></td>
              </tr>
            ))}</tbody>
          </table></div>
        ) : null}
      </section>

      <section className="card stack">
        <h2>Liberar una cuenta bloqueada por intentos fallidos</h2>
        <form className="field-row" onSubmit={unlock}>
          <label>Nombre de usuario<input value={username} onChange={e => setUsername(e.target.value)} required maxLength={64} autoComplete="off" /></label>
          <button type="submit" className="primary" disabled={!username.trim()}>Liberar</button>
        </form>
      </section>

      <ConfirmDialog open={Boolean(unblock)} busy={busy} title="Desbloquear IP" confirmLabel="Desbloquear" onCancel={() => setUnblock(null)} onConfirm={() => { if (unblock) void doUnblock(unblock); }}>
        <p>Se permitirá de nuevo el acceso desde <code>{unblock?.ip_address}</code>. Si sigue abusando, se volverá a bloquear con una duración mayor.</p>
      </ConfirmDialog>
    </div>
  );
}
