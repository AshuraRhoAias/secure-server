'use client';

import { useEffect, useMemo, useRef, useState } from 'react';
import { HBars } from '@/components/Charts';
import { Banner, Card, Loading, Stat } from '@/components/ui';
import { apiCall } from '@/lib/client';
import { bytes, duration, number } from '@/lib/format';
import { histogramQuantile, parseMetrics, sum, type MetricFamily } from '@/lib/prometheus';

const REFRESH_MS = 10_000;
const ms = (seconds: number | null) => (seconds === null ? '—' : seconds < 1 ? `${Math.round(seconds * 1000)} ms` : `${seconds.toFixed(2)} s`);

export default function MetricsPage() {
  const [text, setText] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [raw, setRaw] = useState(false);
  const [rate, setRate] = useState<number | null>(null);
  const last = useRef<{ at: number; total: number } | null>(null);

  useEffect(() => {
    let alive = true;
    const load = async () => {
      const result = await apiCall('GET', '/api/metrics', undefined, { text: true });
      if (!alive) return;
      if (!result.ok) { setError(result.message); return; }
      setError(null);
      setText(result.text ?? '');
    };
    void load();
    const timer = window.setInterval(() => { if (document.visibilityState === 'visible') void load(); }, REFRESH_MS);
    return () => { alive = false; window.clearInterval(timer); };
  }, []);

  const families = useMemo<MetricFamily[]>(() => (text ? parseMetrics(text) : []), [text]);
  const get = (name: string) => families.find(f => f.name === `secure_server_${name}`)?.samples ?? [];

  const requests = get('http_requests_total');
  const total = sum(requests);
  const errors5xx = sum(requests, s => s.labels.status?.startsWith('5') ?? false);
  const errors4xx = sum(requests, s => s.labels.status?.startsWith('4') ?? false);
  const duration_ = get('http_request_duration_seconds');

  useEffect(() => {
    if (!text) return;
    const now = Date.now();
    if (last.current && now > last.current.at && total >= last.current.total) setRate((total - last.current.total) / ((now - last.current.at) / 1000));
    last.current = { at: now, total };
  }, [text, total]);

  const byRoute = useMemo(() => {
    const map = new Map<string, number>();
    for (const s of requests) { const key = `${s.labels.method} ${s.labels.route}`; map.set(key, (map.get(key) ?? 0) + s.value); }
    return [...map.entries()].sort((a, b) => b[1] - a[1]).slice(0, 10).map(([label, value]) => ({ label, value }));
  }, [requests]);
  const byStatus = useMemo(() => {
    const map = new Map<string, number>();
    for (const s of requests) map.set(s.labels.status ?? '?', (map.get(s.labels.status ?? '?') ?? 0) + s.value);
    return [...map.entries()].sort((a, b) => a[0].localeCompare(b[0])).map(([label, value]) => ({ label, value }));
  }, [requests]);
  const events = useMemo(() => {
    const map = new Map<string, number>();
    for (const s of get('security_events_total')) map.set(s.labels.type ?? '?', (map.get(s.labels.type ?? '?') ?? 0) + s.value);
    return [...map.entries()].sort((a, b) => b[1] - a[1]).slice(0, 10).map(([label, value]) => ({ label, value }));
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [families]);

  const pool = Object.fromEntries(get('db_pool_connections').map(s => [s.labels.state ?? '', s.value]));
  const memory = families.find(f => f.name === 'secure_server_process_resident_memory_bytes')?.samples[0]?.value;
  const uptime = families.find(f => f.name === 'secure_server_process_start_time_seconds')?.samples[0]?.value;
  const dbDuration = get('db_query_duration_seconds');

  const download = () => {
    const url = URL.createObjectURL(new Blob([text ?? ''], { type: 'text/plain' }));
    const link = document.createElement('a');
    link.href = url; link.download = `metricas-${new Date().toISOString().slice(0, 19)}.txt`;
    document.body.appendChild(link); link.click(); link.remove(); URL.revokeObjectURL(url);
  };

  return (
    <div className="stack">
      <div className="row">
        <h1 className="grow-title">Métricas</h1>
        <button type="button" onClick={() => setRaw(r => !r)}>{raw ? 'Ver resumen' : 'Ver texto Prometheus'}</button>
        <button type="button" onClick={download} disabled={!text}>Descargar</button>
      </div>
      <p className="muted">Lectura de <code>/api/metrics</code> cada 10 s. Con varios procesos (cluster) son las métricas agregadas de todos. Para histórico y alertas de infraestructura usa Prometheus/Grafana con <code>METRICS_TOKEN</code>.</p>
      {error ? <Banner tone="error">{error}</Banner> : null}
      {!text && !error ? <Loading /> : null}

      {text && raw ? <pre className="json">{text}</pre> : null}
      {text && !raw ? (
        <>
          <div className="grid kpis">
            <Stat label="Peticiones por segundo" value={rate === null ? '…' : rate.toFixed(1)} hint="entre las dos últimas lecturas" />
            <Stat label="Peticiones totales" value={number(total)} hint={`${number(errors4xx)} con 4xx`} />
            <Stat label="Errores 5xx" value={number(errors5xx)} tone={errors5xx > 0 ? 'high' : 'ok'} hint={total ? `${((errors5xx / total) * 100).toFixed(2)} % del total` : undefined} />
            <Stat label="Latencia p50 / p95" value={`${ms(histogramQuantile(duration_, 0.5))} / ${ms(histogramQuantile(duration_, 0.95))}`} hint={`p99 ${ms(histogramQuantile(duration_, 0.99))}`} />
            <Stat label="SQL p95" value={ms(histogramQuantile(dbDuration, 0.95))} hint={`${number(sum(dbDuration.filter(s => s.name.endsWith('_count'))))} consultas`} />
            <Stat label="Pool de BD" value={`${pool.total ?? 0} / ${pool.free ?? 0} libres`} hint={`${pool.queued ?? 0} en cola`} tone={(pool.queued ?? 0) > 0 ? 'high' : undefined} />
            <Stat label="Memoria" value={memory === undefined ? '—' : bytes(memory)} hint="residente (suma de procesos si hay cluster)" />
            <Stat label="Sesiones activas" value={number(get('sessions_active')[0]?.value ?? 0)} hint={`${number(get('blocked_ips_active')[0]?.value ?? 0)} IP bloqueadas`} />
          </div>
          <div className="grid three">
            <Card title="Peticiones por ruta"><HBars items={byRoute} /></Card>
            <Card title="Por código de estado"><HBars items={byStatus} /></Card>
            <Card title="Eventos de seguridad por tipo"><HBars items={events} empty="Sin eventos desde el arranque" /></Card>
          </div>
          {uptime ? <p className="muted">Proceso iniciado hace {duration(Math.max(0, Date.now() / 1000 - uptime))} (el más reciente si hay varios).</p> : null}
        </>
      ) : null}
    </div>
  );
}
