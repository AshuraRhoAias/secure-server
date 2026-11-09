'use client';

import { useState } from 'react';
import { ConfirmDialog } from '@/components/ConfirmDialog';
import { useToast } from '@/components/Toasts';
import { Badge, Banner, Card, JsonView, Loading } from '@/components/ui';
import { useApi } from '@/hooks/useApi';
import { apiCall } from '@/lib/client';
import { dateTime, duration } from '@/lib/format';

interface Worker { pid: number; slot: number | null; uptimeSeconds?: number; rssMb?: number; heapUsedMb?: number; leader?: boolean; shuttingDown?: boolean; open?: boolean; streams?: number; unresponsive?: boolean }
interface ClusterInfo { mode: 'single' | 'cluster'; primaryPid?: number; workers: Worker[]; missing: number | null; error?: string }
interface Status { server: { uptime: number; nodeVersion: string; platform: string; environment: string }; security: Record<string, unknown>; encryption: unknown; protection: unknown; cluster?: ClusterInfo; timestamp: string }

function WorkerState({ w }: { w: Worker }) {
  if (w.unresponsive) return <Badge tone="high">sin respuesta</Badge>;
  if (w.shuttingDown) return <Badge tone="medium">cerrándose</Badge>;
  if (w.open === false) return <Badge tone="medium">mantenimiento</Badge>;
  return <Badge tone="ok">atendiendo</Badge>;
}
interface Rotation { keys: Record<string, unknown>; guard: { maintenance?: boolean; outOfSync?: boolean } & Record<string, unknown>; lastRotation: Record<string, unknown> | null; backups: { name: string; epoch: string; createdAt: string; bytes: number }[] }

export default function SystemPage() {
  const { toast } = useToast();
  const status = useApi<{ status: Status }>('/api/system/status', { refreshMs: 30_000 });
  const rotation = useApi<{ rotation: Rotation }>('/api/system/rotation', { refreshMs: 60_000 });
  const [confirm, setConfirm] = useState<'integrity' | 'comms' | null>(null);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<unknown>(null);

  async function run(kind: 'integrity' | 'comms') {
    setBusy(true);
    const r = await apiCall<Record<string, unknown>>('POST', kind === 'integrity' ? '/api/system/integrity-check' : '/api/system/test-communications', {});
    setBusy(false); setConfirm(null);
    if (r.ok) { setResult(r.data); toast(kind === 'integrity' ? 'Verificación de integridad completada' : 'Prueba de comunicaciones completada', 'ok'); } else toast(r.message, 'error');
  }

  const s = status.data?.status, rot = rotation.data?.rotation;
  return (
    <div className="stack">
      <h1>Sistema</h1>
      {status.error ? <Banner tone="error">{status.error.message}</Banner> : null}
      {rot?.guard.maintenance ? <Banner tone="warn">El servidor está en <strong>mantenimiento</strong> (rotación o migración en curso): responde 503 a todo.</Banner> : null}
      {rot?.guard.outOfSync ? <Banner tone="error">Las claves del entorno <strong>no coinciden</strong> con la base de datos: el servidor se niega a atender.</Banner> : null}
      {status.loading && !s ? <Loading /> : null}
      {s ? (
        <div className="grid two">
          <Card title="Servidor">
            <dl className="kv"><dt>Entorno</dt><dd><Badge tone={s.server.environment === 'production' ? 'ok' : 'medium'}>{s.server.environment}</Badge></dd><dt>Activo</dt><dd>{duration(s.server.uptime)}</dd><dt>Node</dt><dd>{s.server.nodeVersion} · {s.server.platform}</dd><dt>Leído</dt><dd>{dateTime(s.timestamp)}</dd></dl>
            <p className="muted">Entorno, versión y tiempo activo del proceso que atendió esta petición; todos los procesos, abajo.</p>
          </Card>
          <Card title="Operaciones" >
            <div className="stack">
              <div className="row"><button type="button" onClick={() => setConfirm('integrity')}>Comprobar integridad</button><span className="muted">Verifica los archivos críticos del servidor.</span></div>
              <div className="row"><button type="button" onClick={() => setConfirm('comms')}>Probar canales de aviso</button><span className="muted">Envía un aviso de prueba (email, Telegram…).</span></div>
              <p className="muted">La rotación de claves no se lanza desde aquí: <code>npm run rotate-keys</code> en el servidor, con confirmación.</p>
            </div>
          </Card>
          {s.cluster ? (
            <Card title={s.cluster.mode === 'cluster' ? `Procesos del cluster (${s.cluster.workers.length})` : 'Proceso (sin cluster)'}>
              {s.cluster.error ? <Banner tone="warn">{s.cluster.error}</Banner> : null}
              {s.cluster.missing ? <Banner tone="warn">{s.cluster.missing} proceso(s) no respondieron a tiempo.</Banner> : null}
              <div className="table-wrap"><table>
                <caption className="visually-hidden">Estado de cada proceso del servidor</caption>
                <thead><tr><th scope="col">Hueco</th><th scope="col">PID</th><th scope="col">Estado</th><th scope="col">Líder</th><th scope="col" className="num">Activo</th><th scope="col" className="num">Memoria</th><th scope="col" className="num">En vivo</th></tr></thead>
                <tbody>{s.cluster.workers.map(w => (
                  <tr key={w.pid}>
                    <td>{w.slot ?? '—'}</td><td className="mono">{w.pid}</td><td><WorkerState w={w} /></td>
                    <td>{w.leader ? <Badge tone="ok">líder</Badge> : '—'}</td>
                    <td className="num">{w.uptimeSeconds != null ? duration(w.uptimeSeconds) : '—'}</td>
                    <td className="num">{w.rssMb != null ? `${w.rssMb} MB` : '—'}</td>
                    <td className="num">{w.streams ?? '—'}</td>
                  </tr>
                ))}</tbody>
              </table></div>
              <p className="muted">«Líder»: el único proceso que ejecuta las tareas periódicas (limpieza, alertas, rotación programada). «En vivo»: conexiones abiertas del panel.</p>
            </Card>
          ) : null}
          <Card title="Seguridad"><JsonView value={s.security} /></Card>
          <Card title="Protección y cifrado"><JsonView value={{ proteccion: s.protection, cifrado: s.encryption }} /></Card>
        </div>
      ) : null}
      {rot ? (
        <div className="grid two">
          <Card title="Claves y rotación"><JsonView value={{ claves: rot.keys, guardian: rot.guard, ultimaRotacion: rot.lastRotation }} /></Card>
          <Card title={`Copias previas a la rotación (${rot.backups.length})`}>
            {rot.backups.length === 0 ? <p className="muted">No hay copias.</p> : (
              <div className="table-wrap"><table><thead><tr><th>Archivo</th><th>Época</th><th>Creada</th></tr></thead>
                <tbody>{rot.backups.map(b => <tr key={b.name}><td className="mono truncate">{b.name}</td><td>{b.epoch}</td><td>{dateTime(b.createdAt)}</td></tr>)}</tbody></table></div>
            )}
          </Card>
        </div>
      ) : null}
      {result ? <Card title="Resultado de la última operación"><JsonView value={result} /></Card> : null}
      <ConfirmDialog open={confirm !== null} busy={busy} title={confirm === 'integrity' ? 'Comprobar integridad' : 'Probar canales de aviso'} confirmLabel="Ejecutar" onCancel={() => setConfirm(null)} onConfirm={() => { if (confirm) void run(confirm); }}>
        <p>{confirm === 'integrity' ? 'Se recalcula la huella de los archivos críticos del servidor y se compara con la guardada.' : 'Se enviará un mensaje de prueba por los canales configurados.'}</p>
      </ConfirmDialog>
    </div>
  );
}
