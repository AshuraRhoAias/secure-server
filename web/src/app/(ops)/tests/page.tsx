'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import { useToast } from '@/components/Toasts';
import { Badge, Banner, Empty, Loading, type Tone } from '@/components/ui';
import { useApi } from '@/hooks/useApi';
import { apiCall } from '@/lib/client';
import { dateTime } from '@/lib/format';

type Kind = 'diagnostic' | 'attack_sim' | 'test_suite';
type Status = 'queued' | 'running' | 'passed' | 'failed' | 'cancelled' | 'error';
type Level = 'info' | 'pass' | 'fail' | 'warn' | 'error' | 'output';

interface Summary { done?: number; total?: number | null; pass?: number; fail?: number; warn?: number; blocked?: number; exitCode?: number | null }
interface Run { id: number; kind: Kind; target: string | null; status: Status; startedAt: string | null; finishedAt: string | null; summary: Summary | null }
interface RunEvent { seq: number; level: Level; step: string; message: string; at: string }
interface RunDetail { run: Run; events: RunEvent[]; lastSeq: number; hasMore: boolean }
interface Catalog {
  kinds: Array<{
    kind: Kind; title?: string; description?: string; enabled?: boolean; reason?: string | null; warning?: string;
    targets?: Array<{ value: string; label: string }>; suites?: Array<{ value: string; label: string; db: boolean }>;
  }>;
}

const POLL_MS = 700;
const ACTIVE: Status[] = ['queued', 'running'];
const KIND_LABEL: Record<Kind, string> = { diagnostic: 'Diagnóstico', attack_sim: 'Simulación de ataques', test_suite: 'Suite de pruebas' };
const STATUS_LABEL: Record<Status, string> = { queued: 'En cola', running: 'En curso', passed: 'Superada', failed: 'Con fallos', cancelled: 'Cancelada', error: 'Error' };
const STATUS_TONE: Record<Status, Tone> = { queued: 'info', running: 'low', passed: 'ok', failed: 'critical', cancelled: 'neutral', error: 'high' };
const MARK: Record<Level, string> = { info: '·', pass: '✓', fail: '✗', warn: '!', error: '✗', output: ' ' };
const LEVEL_NAME: Record<Level, string> = { info: 'info', pass: 'correcto', fail: 'fallo', warn: 'aviso', error: 'error', output: 'salida' };

const isActive = (status: Status | undefined): boolean => status !== undefined && ACTIVE.includes(status);
const clock = (iso: string): string => { const d = new Date(iso); return Number.isNaN(d.getTime()) ? '' : d.toLocaleTimeString('es', { hour12: false }); };
const elapsed = (run: Run): string => {
  if (!run.startedAt) return '—';
  const end = run.finishedAt ? new Date(run.finishedAt).getTime() : Date.now();
  const seconds = Math.max(0, Math.round((end - new Date(run.startedAt).getTime()) / 1000));
  return seconds < 60 ? `${seconds} s` : `${Math.floor(seconds / 60)} min ${seconds % 60} s`;
};

export default function TestsPage() {
  const { toast } = useToast();
  const catalog = useApi<Catalog>('/api/system/runs/catalog');
  const history = useApi<{ runs: Run[] }>('/api/system/runs?limit=15', { refreshMs: 10_000 });

  const [activeId, setActiveId] = useState<number | null>(null);
  const [run, setRun] = useState<Run | null>(null);
  const [events, setEvents] = useState<RunEvent[]>([]);
  const [busy, setBusy] = useState<Kind | 'cancel' | null>(null);
  const [notify, setNotify] = useState(false);
  const [suite, setSuite] = useState('test_api');
  const [follow, setFollow] = useState(true);
  const [announce, setAnnounce] = useState('');

  const afterSeq = useRef(0);
  const logRef = useRef<HTMLDivElement>(null);
  const adopted = useRef(false);
  const currentId = useRef<number | null>(null);

  const reloadHistory = history.reload;

  // Una sola petición de sondeo: trae los eventos nuevos (afterSeq) y actualiza la ejecución. Devuelve true si debe seguir sondeando.
  const poll = useCallback(async (id: number): Promise<boolean> => {
    const result = await apiCall<RunDetail & { success: boolean }>('GET', `/api/system/runs/${id}?afterSeq=${afterSeq.current}`);
    if (currentId.current !== id) return false; // el usuario abrió otra ejecución mientras tanto: se descarta
    if (!result.ok || !result.data) return true; // fallo transitorio: se reintenta
    const detail = result.data;
    if (detail.events.length) {
      afterSeq.current = detail.lastSeq;
      setEvents(prev => [...prev, ...detail.events]);
    }
    setRun(detail.run);
    return isActive(detail.run.status) || detail.hasMore;
  }, []);

  // Sondeo mientras la ejecución está activa; se pausa con la pestaña oculta y se detiene al terminar
  useEffect(() => {
    if (activeId === null) return undefined;
    let stopped = false;
    let timer: number | undefined;
    const tick = async () => {
      if (stopped) return;
      if (document.visibilityState === 'hidden') { timer = window.setTimeout(tick, POLL_MS * 2); return; }
      const again = await poll(activeId);
      if (stopped) return;
      if (again) timer = window.setTimeout(tick, POLL_MS);
      else void reloadHistory();
    };
    const onVisible = () => { if (document.visibilityState === 'visible') { window.clearTimeout(timer); void tick(); } };
    document.addEventListener('visibilitychange', onVisible);
    void tick();
    return () => { stopped = true; window.clearTimeout(timer); document.removeEventListener('visibilitychange', onVisible); };
  }, [activeId, poll, reloadHistory]);

  // Al entrar, si hay una ejecución viva (por ejemplo tras recargar la página) se retoma
  useEffect(() => {
    if (adopted.current || !history.data) return;
    adopted.current = true;
    const live = history.data.runs.find(r => isActive(r.status));
    if (live) open(live.id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [history.data]);

  // Auto-scroll al final salvo que el usuario haya subido
  useEffect(() => {
    const box = logRef.current;
    if (box && follow) box.scrollTop = box.scrollHeight;
  }, [events, follow]);

  // Resumen para lectores de pantalla: solo cuando cambia el estado o aparece un fallo (no una frase por línea)
  const counts = events.reduce((acc, e) => {
    if (e.level === 'pass') acc.pass++; else if (e.level === 'fail' || e.level === 'error') acc.fail++; else if (e.level === 'warn') acc.warn++;
    return acc;
  }, { pass: 0, fail: 0, warn: 0 });
  useEffect(() => {
    if (run) setAnnounce(`Ejecución ${run.id}: ${STATUS_LABEL[run.status]}. ${counts.pass} correctos, ${counts.fail} fallos, ${counts.warn} avisos.`);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [run?.status, run?.id, counts.fail]);

  function open(id: number) {
    afterSeq.current = 0;
    setEvents([]);
    setRun(null);
    setFollow(true);
    currentId.current = id;
    setActiveId(id);
  }

  async function start(kind: Kind, target?: string) {
    setBusy(kind);
    const result = await apiCall<{ run: Run }>('POST', '/api/system/runs', { kind, ...(target ? { target } : {}) });
    setBusy(null);
    if (!result.ok || !result.data) { toast(result.message || 'No se pudo lanzar la ejecución', 'error'); return; }
    open(result.data.run.id);
    void reloadHistory();
  }

  async function cancel() {
    if (!run) return;
    setBusy('cancel');
    const result = await apiCall('POST', `/api/system/runs/${run.id}/cancel`);
    setBusy(null);
    if (!result.ok) toast(result.message || 'No se pudo cancelar', 'error');
    void poll(run.id);
  }

  const info = (kind: Kind) => catalog.data?.kinds.find(k => k.kind === kind);
  const runs = history.data?.runs ?? [];
  const activeKinds = new Set(runs.filter(r => isActive(r.status)).map(r => r.kind));
  const suiteInfo = info('test_suite');
  const diagInfo = info('diagnostic');
  const total = run?.summary?.total ?? null;
  const done = run?.summary?.done ?? 0;
  const running = isActive(run?.status);

  return (
    <div className="stack">
      <h1>Pruebas</h1>
      <p className="muted">
        Lanza pruebas con un botón y mira lo que pasa en tiempo real. Solo hay una ejecución activa por tipo en todo el cluster; el progreso se guarda en la base de datos
        y se conserva unos días.
      </p>
      {catalog.loading && !catalog.data ? <Loading /> : null}
      {catalog.error ? <Banner tone="error">{catalog.error.message}</Banner> : null}

      <div className="grid three">
        <section className="card stack" aria-labelledby="t-diag">
          <h2 id="t-diag">Diagnóstico del sistema</h2>
          <p className="muted">{diagInfo?.description ?? 'Comprobaciones reales y no destructivas del propio servidor.'}</p>
          <label className="check-row">
            <input type="checkbox" checked={notify} onChange={e => setNotify(e.target.checked)} />
            <span>Enviar también un aviso de prueba REAL por los canales de alerta</span>
          </label>
          <button type="button" className="primary big" disabled={busy !== null || activeKinds.has('diagnostic')} onClick={() => void start('diagnostic', notify ? 'with-notifications' : undefined)}>
            Ejecutar diagnóstico
          </button>
        </section>

        <section className="card stack" aria-labelledby="t-attack">
          <h2 id="t-attack">Simulación de ataques</h2>
          <p className="muted">{info('attack_sim')?.description ?? 'Ataques controlados contra este mismo servidor.'}</p>
          <p className="muted">El destino es siempre este servidor; usa IP de documentación y un usuario temporal que se borra al terminar. Los eventos de seguridad de la simulación quedan registrados; las alertas que provoque se marcan como «[Posible simulación]» y sus avisos externos (webhook) salen igual, con esa marca: nunca se silencian. Si el servidor no confía en el proxy (TRUST_PROXY), no se ejecuta ningún ataque.</p>
          <button type="button" className="primary big" disabled={busy !== null || activeKinds.has('attack_sim')} onClick={() => void start('attack_sim')}>
            Simular ataques
          </button>
        </section>

        <section className="card stack" aria-labelledby="t-suite">
          <h2 id="t-suite">Suites de pruebas</h2>
          <p className="muted">{suiteInfo?.description ?? 'Ejecuta node --test sobre una lista cerrada de suites.'}</p>
          <label htmlFor="suite-select">
            Suite
            <select id="suite-select" value={suite} onChange={e => setSuite(e.target.value)} disabled={suiteInfo?.enabled === false}>
              {(suiteInfo?.suites ?? [{ value: 'test_api', label: 'API sin BD (test_api)', db: false }]).map(s => (
                <option key={s.value} value={s.value}>{s.label}{s.db ? ' · BD' : ''}</option>
              ))}
            </select>
          </label>
          {suiteInfo?.enabled === false
            ? <Banner tone="warn">{suiteInfo.reason}</Banner>
            : <p className="muted">{suiteInfo?.warning ?? 'Las suites con BD usan la base de datos de pruebas, no la de la aplicación.'}</p>}
          <button type="button" className="primary big" disabled={busy !== null || suiteInfo?.enabled === false || activeKinds.has('test_suite')} onClick={() => void start('test_suite', suite)}>
            Ejecutar suite
          </button>
        </section>
      </div>

      <section className="card stack" aria-labelledby="t-live">
        <div className="row">
          <h2 id="t-live" className="grow-title">Ejecución en vivo</h2>
          {running ? <button type="button" onClick={() => void cancel()} disabled={busy === 'cancel'}>Cancelar</button> : null}
        </div>
        <div className="sr-only" aria-live="polite" role="status">{announce}</div>

        {!run && activeId === null ? <Empty>Lanza una prueba o abre una del historial para ver su registro.</Empty> : null}
        {activeId !== null && !run ? <Loading /> : null}

        {run ? (
          <>
            <div className="run-head">
              <strong>#{run.id} · {KIND_LABEL[run.kind]}{run.target ? ` · ${run.target}` : ''}</strong>
              <span className="badge" data-tone={STATUS_TONE[run.status]} data-live={running ? 'on' : 'off'}>{STATUS_LABEL[run.status]}</span>
              <span className="muted">{dateTime(run.startedAt)} · {elapsed(run)}</span>
            </div>
            <div className="run-progress">
              {running && total === null
                ? <progress aria-label="Progreso de la ejecución" />
                : <progress aria-label="Progreso de la ejecución" max={total ?? Math.max(done, 1)} value={running ? done : (total ?? done)} />}
              <span className="muted">{total !== null ? `${Math.min(done, total)} de ${total} pasos` : `${done} pasos hechos`}</span>
            </div>
            <div className="run-counts">
              <Badge tone="ok">✓ {counts.pass} correctos</Badge>
              <Badge tone={counts.fail ? 'critical' : 'neutral'}>✗ {counts.fail} fallos</Badge>
              <Badge tone={counts.warn ? 'medium' : 'neutral'}>! {counts.warn} avisos</Badge>
              {!follow ? <button type="button" onClick={() => setFollow(true)}>Ir al final</button> : null}
            </div>
            <div
              className="runlog" ref={logRef} tabIndex={0} role="region" aria-label="Registro de la ejecución"
              onScroll={e => { const el = e.currentTarget; setFollow(el.scrollHeight - el.scrollTop - el.clientHeight < 24); }}
            >
              {events.map(e => (
                <div key={e.seq} className="ln" data-level={e.level}>
                  <span className="t">{clock(e.at)}</span>
                  <span className="m" aria-hidden="true">{MARK[e.level]}</span>
                  <span className="visually-hidden">{LEVEL_NAME[e.level]}: </span>
                  <span className="x">{e.level === 'output' ? e.message : `[${e.step}] ${e.message}`}</span>
                </div>
              ))}
              {events.length === 0 ? <div className="ln muted">Esperando el primer evento…</div> : null}
            </div>
          </>
        ) : null}
      </section>

      <section className="card stack" aria-labelledby="t-hist">
        <h2 id="t-hist">Historial reciente</h2>
        {history.error ? <Banner tone="error">{history.error.message}</Banner> : null}
        {!history.loading && runs.length === 0 ? <Empty>Todavía no hay ejecuciones.</Empty> : null}
        {runs.length ? (
          <div className="table-wrap">
            <table>
              <caption className="visually-hidden">Últimas ejecuciones de pruebas</caption>
              <thead><tr><th scope="col">#</th><th scope="col">Tipo</th><th scope="col">Destino</th><th scope="col">Estado</th><th scope="col">Inicio</th><th scope="col">Duración</th><th scope="col">Resultado</th><th scope="col">Registro</th></tr></thead>
              <tbody>
                {runs.map(r => (
                  <tr key={r.id}>
                    <td>{r.id}</td>
                    <td>{KIND_LABEL[r.kind]}</td>
                    <td>{r.target ?? '—'}</td>
                    <td><Badge tone={STATUS_TONE[r.status]}>{STATUS_LABEL[r.status]}</Badge></td>
                    <td>{dateTime(r.startedAt)}</td>
                    <td>{elapsed(r)}</td>
                    <td>{r.summary ? `✓ ${r.summary.pass ?? 0} · ✗ ${r.summary.fail ?? 0} · ! ${r.summary.warn ?? 0}` : '—'}</td>
                    <td><button type="button" onClick={() => open(r.id)} aria-label={`Ver el registro de la ejecución ${r.id}`}>Ver registro</button></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : null}
      </section>
    </div>
  );
}
