'use client';

import { useState } from 'react';
import { ConfirmDialog } from '@/components/ConfirmDialog';
import { useToast } from '@/components/Toasts';
import { Badge, Banner, Card, JsonView, Loading } from '@/components/ui';
import { useApi } from '@/hooks/useApi';
import { apiCall } from '@/lib/client';
import { dateTime, duration } from '@/lib/format';

interface Status { server: { uptime: number; nodeVersion: string; platform: string; environment: string }; security: Record<string, unknown>; encryption: unknown; protection: unknown; timestamp: string }
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
            <p className="muted">Con varios procesos esta lectura es de UNO de ellos (el que atendió la petición).</p>
          </Card>
          <Card title="Operaciones" >
            <div className="stack">
              <div className="row"><button type="button" onClick={() => setConfirm('integrity')}>Comprobar integridad</button><span className="muted">Verifica los archivos críticos del servidor.</span></div>
              <div className="row"><button type="button" onClick={() => setConfirm('comms')}>Probar canales de aviso</button><span className="muted">Envía un aviso de prueba (email, Telegram…).</span></div>
              <p className="muted">La rotación de claves no se lanza desde aquí: <code>npm run rotate-keys</code> en el servidor, con confirmación.</p>
            </div>
          </Card>
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
