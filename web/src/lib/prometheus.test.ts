import { describe, expect, it } from 'vitest';
import { histogramQuantile, parseMetrics, sum } from './prometheus';
import { bytes, duration, relativeTime } from './format';

const TEXT = `# HELP secure_server_http_requests_total Peticiones HTTP
# TYPE secure_server_http_requests_total counter
secure_server_http_requests_total{method="GET",route="/api/notes",status="200"} 120
secure_server_http_requests_total{method="GET",route="/api/notes",status="500"} 3
secure_server_http_requests_total{method="POST",route="/api/auth/login",status="401"} 7
# HELP secure_server_http_request_duration_seconds Duración
# TYPE secure_server_http_request_duration_seconds histogram
secure_server_http_request_duration_seconds_bucket{le="0.01",method="GET",route="/a"} 50
secure_server_http_request_duration_seconds_bucket{le="0.1",method="GET",route="/a"} 90
secure_server_http_request_duration_seconds_bucket{le="1",method="GET",route="/a"} 100
secure_server_http_request_duration_seconds_bucket{le="+Inf",method="GET",route="/a"} 100
secure_server_http_request_duration_seconds_sum{method="GET",route="/a"} 4.2
secure_server_http_request_duration_seconds_count{method="GET",route="/a"} 100
# TYPE secure_server_sessions_active gauge
secure_server_sessions_active 4
weird_label{a="x\\"y\\\\z"} 1.5
nan_metric NaN
`;

describe('prometheus', () => {
  const families = parseMetrics(TEXT);
  const find = (name: string) => families.find(f => f.name === name)!;

  it('lee familias, tipos, etiquetas y valores', () => {
    expect(find('secure_server_http_requests_total').type).toBe('counter');
    expect(find('secure_server_http_requests_total').samples).toHaveLength(3);
    expect(find('secure_server_sessions_active').samples[0]?.value).toBe(4);
    expect(find('weird_label').samples[0]?.labels.a).toBe('x"y\\z');
    expect(Number.isNaN(find('nan_metric').samples[0]?.value)).toBe(true);
  });

  it('suma con filtro y agrupa los cubos del histograma bajo su familia', () => {
    const requests = find('secure_server_http_requests_total').samples;
    expect(sum(requests)).toBe(130);
    expect(sum(requests, s => s.labels.status?.startsWith('5') ?? false)).toBe(3);
    expect(find('secure_server_http_request_duration_seconds').samples).toHaveLength(6);
  });

  it('cuantiles de histograma por interpolación', () => {
    const samples = find('secure_server_http_request_duration_seconds').samples;
    expect(histogramQuantile(samples, 0.5)).toBeCloseTo(0.01, 3);
    expect(histogramQuantile(samples, 0.9)).toBeCloseTo(0.1, 3);
    expect(histogramQuantile(samples, 0.95)).toBeGreaterThan(0.1);
    expect(histogramQuantile([], 0.5)).toBeNull();
  });

  it('ignora líneas rotas sin lanzar', () => {
    expect(() => parseMetrics('no es prometheus\n{{{\n# HELP\n')).not.toThrow();
  });
});

describe('formato', () => {
  it('bytes, duración y tiempo relativo', () => {
    expect(bytes(0)).toBe('0 B');
    expect(bytes(1536)).toBe('1.5 KB');
    expect(bytes(5 * 1024 ** 3)).toBe('5.0 GB');
    expect(duration(90)).toBe('1 min');
    expect(duration(3 * 3600 + 120)).toBe('3 h 2 min');
    expect(duration(2 * 86400 + 5 * 3600)).toBe('2 d 5 h');
    expect(relativeTime('2026-10-27T10:00:00Z', Date.parse('2026-10-27T10:05:00Z'))).toMatch(/5|cinco/);
    expect(relativeTime(null)).toBe('—');
    expect(relativeTime('basura')).toBe('—');
  });
});
