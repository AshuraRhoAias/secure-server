'use client';

// Gráficos SVG sin dependencias. Sin estilos en línea (la CSP los prohíbe): todo con atributos SVG y clases.
export function BarChart({ data, height = 140 }: { data: { label: string; value: number }[]; height?: number }) {
  const width = 640, padLeft = 34, padBottom = 20, padTop = 8;
  if (data.length === 0) return <div className="empty">Sin datos en esta ventana</div>;
  const max = Math.max(1, ...data.map(d => d.value));
  const plotW = width - padLeft - 4, plotH = height - padBottom - padTop;
  const slot = plotW / data.length, barW = Math.max(1, slot * 0.72);
  const ticks = [0, 0.5, 1].map(f => Math.round(max * f));
  const labelEvery = Math.max(1, Math.ceil(data.length / 8));
  return (
    <div className="chart">
      <svg viewBox={`0 0 ${width} ${height}`} role="img" aria-label={`Eventos por hora, máximo ${max}`}>
        {ticks.map(t => {
          const y = padTop + plotH - (t / max) * plotH;
          return (<g key={t}><line className="grid-line" x1={padLeft} x2={width - 4} y1={y} y2={y} /><text className="axis" x={padLeft - 6} y={y + 4} textAnchor="end">{t}</text></g>);
        })}
        {data.map((d, i) => {
          const h = (d.value / max) * plotH;
          return (
            <g key={`${d.label}-${i}`}>
              <rect className="bar" x={padLeft + i * slot + (slot - barW) / 2} y={padTop + plotH - h} width={barW} height={Math.max(h, d.value > 0 ? 1 : 0)} rx="2"><title>{`${d.label}: ${d.value}`}</title></rect>
              {i % labelEvery === 0 ? <text className="axis" x={padLeft + i * slot + slot / 2} y={height - 5} textAnchor="middle">{d.label.slice(-5)}</text> : null}
            </g>
          );
        })}
      </svg>
    </div>
  );
}

export function HBars({ items, empty = 'Sin datos' }: { items: { label: string; value: number; hint?: string }[]; empty?: string }) {
  if (items.length === 0) return <div className="empty">{empty}</div>;
  const max = Math.max(1, ...items.map(i => i.value));
  return (
    <div>
      {items.map(item => (
        <div className="hbar" key={item.label}>
          <span className="truncate" title={item.label}>{item.label}{item.hint ? <span className="muted"> · {item.hint}</span> : null}</span>
          <svg viewBox="0 0 100 10" preserveAspectRatio="none" aria-hidden="true">
            <rect className="track" x="0" y="0" width="100" height="10" rx="5" />
            <rect className="fill" x="0" y="0" width={Math.max(2, (item.value / max) * 100)} height="10" rx="5" />
          </svg>
          <span className="mono">{item.value}</span>
        </div>
      ))}
    </div>
  );
}
