// Lector mínimo del formato de texto de Prometheus (lo que devuelve /api/metrics). Solo lo que necesita la vista de métricas.
export interface Sample { name: string; labels: Record<string, string>; value: number }
export interface MetricFamily { name: string; help: string; type: string; samples: Sample[] }

const LINE = /^([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{(.*)\})?\s+([^\s]+)(?:\s+\d+)?$/;

function parseLabels(text: string): Record<string, string> {
  const labels: Record<string, string> = {};
  const pair = /([a-zA-Z_][a-zA-Z0-9_]*)="((?:[^"\\]|\\.)*)"/g;
  for (let match = pair.exec(text); match; match = pair.exec(text)) labels[match[1] as string] = (match[2] as string).replace(/\\(["\\n])/g, (_, c: string) => (c === 'n' ? '\n' : c));
  return labels;
}

export function parseMetrics(text: string): MetricFamily[] {
  const families = new Map<string, MetricFamily>();
  const get = (name: string): MetricFamily => {
    let family = families.get(name);
    if (!family) { family = { name, help: '', type: 'untyped', samples: [] }; families.set(name, family); }
    return family;
  };
  for (const raw of text.split('\n')) {
    const line = raw.trim();
    if (!line) continue;
    if (line.startsWith('# HELP ')) { const [name, ...help] = line.slice(7).split(' '); if (name) get(name).help = help.join(' '); continue; }
    if (line.startsWith('# TYPE ')) { const [name, type] = line.slice(7).split(' '); if (name) get(name).type = type ?? 'untyped'; continue; }
    if (line.startsWith('#')) continue;
    const match = LINE.exec(line);
    if (!match) continue;
    const value = match[3] === 'NaN' ? NaN : match[3] === '+Inf' ? Infinity : match[3] === '-Inf' ? -Infinity : Number(match[3]);
    const sampleName = match[1] as string;
    // histogramas/summaries: _bucket, _sum, _count pertenecen a la familia base
    const base = sampleName.replace(/_(bucket|sum|count)$/, '');
    const family = families.has(sampleName) ? get(sampleName) : families.has(base) ? get(base) : get(sampleName);
    family.samples.push({ name: sampleName, labels: match[2] ? parseLabels(match[2]) : {}, value });
  }
  return [...families.values()];
}

export const sum = (samples: Sample[], where: (s: Sample) => boolean = () => true): number =>
  samples.filter(where).reduce((total, s) => total + (Number.isFinite(s.value) ? s.value : 0), 0);

// Cuantil aproximado de un histograma (interpolación lineal entre cubos), agregando todas las series que cumplan el filtro
export function histogramQuantile(samples: Sample[], quantile: number, where: (s: Sample) => boolean = () => true): number | null {
  const buckets = new Map<number, number>();
  for (const s of samples) {
    if (!s.name.endsWith('_bucket') || !where(s)) continue;
    const le = s.labels.le === '+Inf' ? Infinity : Number(s.labels.le);
    if (Number.isNaN(le)) continue;
    buckets.set(le, (buckets.get(le) ?? 0) + s.value);
  }
  const sorted = [...buckets.entries()].sort((a, b) => a[0] - b[0]);
  const total = sorted.at(-1)?.[1] ?? 0;
  if (total === 0) return null;
  const target = quantile * total;
  let previousBound = 0, previousCount = 0;
  for (const [bound, count] of sorted) {
    if (count >= target) {
      if (!Number.isFinite(bound)) return previousBound;
      const span = count - previousCount;
      return span === 0 ? bound : previousBound + ((bound - previousBound) * (target - previousCount)) / span;
    }
    previousBound = bound;
    previousCount = count;
  }
  return null;
}
