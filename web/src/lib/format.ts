const rtf = typeof Intl !== 'undefined' ? new Intl.RelativeTimeFormat('es', { numeric: 'auto' }) : null;

export function relativeTime(iso: string | null | undefined, now = Date.now()): string {
  if (!iso) return '—';
  const then = Date.parse(iso.includes('T') || iso.endsWith('Z') ? iso : iso.replace(' ', 'T') + 'Z');
  if (Number.isNaN(then)) return '—';
  const seconds = Math.round((then - now) / 1000);
  const abs = Math.abs(seconds);
  if (!rtf) return new Date(then).toLocaleString();
  if (abs < 60) return rtf.format(seconds, 'second');
  if (abs < 3600) return rtf.format(Math.round(seconds / 60), 'minute');
  if (abs < 86400) return rtf.format(Math.round(seconds / 3600), 'hour');
  return rtf.format(Math.round(seconds / 86400), 'day');
}

export const dateTime = (iso: string | null | undefined): string => {
  if (!iso) return '—';
  const date = new Date(iso.includes('T') || iso.endsWith('Z') ? iso : iso.replace(' ', 'T') + 'Z');
  return Number.isNaN(date.getTime()) ? '—' : date.toLocaleString('es');
};

export const bytes = (n: number): string => {
  if (!Number.isFinite(n)) return '—';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let value = n, unit = 0;
  while (value >= 1024 && unit < units.length - 1) { value /= 1024; unit++; }
  return `${value.toFixed(value >= 10 || unit === 0 ? 0 : 1)} ${units[unit]}`;
};

export const duration = (seconds: number): string => {
  const d = Math.floor(seconds / 86400), h = Math.floor((seconds % 86400) / 3600), m = Math.floor((seconds % 3600) / 60);
  return d > 0 ? `${d} d ${h} h` : h > 0 ? `${h} h ${m} min` : `${m} min`;
};

export const number = (n: number): string => new Intl.NumberFormat('es').format(n);
