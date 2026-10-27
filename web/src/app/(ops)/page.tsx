'use client';

import Link from 'next/link';
import { useState } from 'react';
import { BarChart, HBars } from '@/components/Charts';
import { Badge, Banner, Card, Empty, Loading, Segmented, SeverityBadge, Stat, StatusBadge } from '@/components/ui';
import { useApi } from '@/hooks/useApi';
import { bytes, duration, number, relativeTime } from '@/lib/format';
import type { Dashboard } from '@/lib/types';

const WINDOWS = [{ value: 1, label: '1 h' }, { value: 6, label: '6 h' }, { value: 24, label: '24 h' }, { value: 168, label: '7 d' }, { value: 720, label: '30 d' }];
const sumValues = (o: Record<string, number>) => Object.values(o).reduce((a, b) => a + b, 0);

export default function DashboardPage() {
  const [hours, setHours] = useState(24);
  const { data, error, loading, reload } = useApi<{ dashboard: Dashboard }>(`/api/system/dashboard?hours=${hours}`, { refreshMs: 15_000 });
  const d = data?.dashboard;

  return (
    <div className="stack">
      <div className="row">
        <h1 className="grow-title">Panel de seguridad</h1>
        <Segmented label="Ventana de tiempo" value={hours} onChange={setHours} options={WINDOWS} />
        <button type="button" onClick={() => void reload()}>Actualizar</button>
      </div>
      {error ? <Banner tone="error">No se pudo cargar el panel: {error.message}</Banner> : null}
      {loading && !d ? <Loading /> : null}

      {d ? (
        <>
          <p className="muted">Actualizado {relativeTime(d.generatedAt)} · ventana de {d.windowHours} h · se refresca cada 15 s</p>
          <div className="grid kpis">
            <Stat label="Alertas abiertas" value={number(sumValues(d.alerts.open))} tone={(d.alerts.open.critical ?? 0) > 0 ? 'critical' : (d.alerts.open.high ?? 0) > 0 ? 'high' : 'ok'}
              hint={`${d.alerts.open.critical ?? 0} críticas · ${d.alerts.open.high ?? 0} altas`} />
            <Stat label="Aprobaciones pendientes" value={number(d.approvals.pending)} tone={d.approvals.pending > 0 ? 'high' : undefined} hint="Segunda firma de otro admin" />
            <Stat label="Sesiones activas" value={number(d.auth.activeSessions)} />
            <Stat label="IP bloqueadas" value={number(d.blockedIps.active)} />
            <Stat label="Inicios de sesión" value={`${number(d.auth.logins.success)} / ${number(d.auth.logins.failed)}`} hint="correctos / fallidos" tone={d.auth.logins.failed > d.auth.logins.success ? 'high' : undefined} />
            <Stat label="Cuentas cerca del bloqueo" value={number(d.auth.accountsAtLockThreshold)} />
            <Stat label="Refresh token reutilizado" value={number(d.auth.refreshTokenReuse)} tone={d.auth.refreshTokenReuse > 0 ? 'critical' : 'ok'} hint="Posible robo de sesión" />
            <Stat label="Subidas rechazadas" value={number(d.files.rejectedInWindow)} hint={`${number(d.files.total)} archivos · ${bytes(d.files.bytes)}`} />
          </div>

          <div className="grid two">
            <Card title={`Eventos de seguridad (${number(d.events.total)})`}>
              <BarChart data={d.events.timeline.map(t => ({ label: t.hour, value: Number(t.total) }))} />
              <div className="chips">
                {(['critical', 'high', 'medium', 'low', 'info'] as const).map(s => <span key={s} className="row"><SeverityBadge severity={s} /><span className="mono">{d.events.bySeverity[s] ?? 0}</span></span>)}
              </div>
            </Card>
            <Card title="Alertas abiertas" actions={<Link href="/alerts">Ver todas</Link>}>
              {d.alerts.latest.length === 0 ? <Empty>Sin alertas abiertas 🎉</Empty> : (
                <div className="table-wrap"><table>
                  <thead><tr><th>Severidad</th><th>Alerta</th><th>Estado</th><th>Última vez</th></tr></thead>
                  <tbody>{d.alerts.latest.slice(0, 8).map(a => (
                    <tr key={a.id}><td><SeverityBadge severity={a.severity} /></td><td className="truncate" title={a.title}>{a.title}</td><td><StatusBadge status={a.status} /></td><td>{relativeTime(a.lastSeen)}</td></tr>
                  ))}</tbody>
                </table></div>
              )}
            </Card>
          </div>

          <div className="grid three">
            <Card title="IP con más eventos"><HBars items={d.events.topIps.map(i => ({ label: i.ip_address, value: Number(i.total), hint: i.country ?? undefined }))} /></Card>
            <Card title="Reglas más activas"><HBars items={d.events.topRules.map(r => ({ label: r.rule, value: Number(r.total) }))} /></Card>
            <Card title="Tipos de evento"><HBars items={d.events.topTypes.map(t => ({ label: t.event_type, value: Number(t.total) }))} /></Card>
          </div>

          <div className="grid two">
            <Card title="Archivos">
              <dl className="kv">
                <dt>Antivirus</dt><dd>{Object.entries(d.files.byScanStatus).map(([k, v]) => <Badge key={k} tone={k === 'infected' ? 'critical' : k === 'clean' ? 'ok' : 'neutral'}>{k}: {v}</Badge>)}</dd>
                <dt>Saneado</dt><dd>{Object.entries(d.files.bySanitizeStatus).map(([k, v]) => <Badge key={k}>{k}: {v}</Badge>)}</dd>
              </dl>
            </Card>
            <Card title="Salud y configuración" actions={<Link href="/system">Detalle</Link>}>
              <div className="chips">
                <Badge tone={d.system.database === 'ok' ? 'ok' : 'critical'}>Base de datos: {d.system.database}</Badge>
                <Badge>Activo {duration(d.system.uptimeSeconds)}</Badge>
                <Badge>Node {d.system.node}</Badge>
                {Object.entries(d.system.config).map(([key, value]) => (
                  <Badge key={key} tone={value === false || value === null ? 'medium' : 'ok'}>{key}: {String(value)}</Badge>
                ))}
              </div>
            </Card>
          </div>
        </>
      ) : null}
    </div>
  );
}
