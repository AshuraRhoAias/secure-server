'use client';

import { useState } from 'react';
import { ConfirmDialog } from '@/components/ConfirmDialog';
import { useToast } from '@/components/Toasts';
import { Badge, Banner, Loading } from '@/components/ui';
import { useApi } from '@/hooks/useApi';
import { apiCall } from '@/lib/client';
import { dateTime } from '@/lib/format';

type Value = number | boolean | string;
type Source = 'db' | 'env' | 'default';
interface Setting {
  key: string; label: string; description: string; group: string; type: 'int' | 'bool' | 'enum'; unit: string | null;
  min?: number; max?: number; values?: string[]; default: Value; value: Value; source: Source; envValue: Value;
  updatedBy: { id: number | null; username: string | null } | null; updatedAt: string | null;
}
interface Groups { groups: Array<{ group: string; settings: Setting[] }> }

const SOURCE_LABEL: Record<Source, string> = { db: 'Cambiado desde la web', env: 'Del entorno (.env)', default: 'Valor por defecto' };
const SOURCE_TONE: Record<Source, 'high' | 'info' | 'neutral'> = { db: 'high', env: 'info', default: 'neutral' };

const show = (setting: Setting, value: Value): string => {
  if (setting.type === 'bool') return value === true ? 'Activado' : 'Desactivado';
  return `${String(value)}${setting.unit ? ` ${setting.unit}` : ''}`;
};

type Pending = null | { setting: Setting; action: 'save' | 'reset'; value: Value };

export default function SettingsPage() {
  const { toast } = useToast();
  const list = useApi<Groups>('/api/system/settings');
  const [drafts, setDrafts] = useState<Record<string, string | boolean>>({});
  const [pending, setPending] = useState<Pending>(null);
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState<string | null>(null);
  const [errors, setErrors] = useState<Record<string, string>>({});

  const draftOf = (setting: Setting): string | boolean => drafts[setting.key] ?? (setting.type === 'bool' ? setting.value === true : String(setting.value));

  // Valor que se enviaría; null si el borrador no es válido (con el motivo en errors)
  function parse(setting: Setting): Value | null {
    const draft = draftOf(setting);
    if (setting.type === 'bool') return draft === true;
    if (setting.type === 'enum') return String(draft);
    const text = String(draft).trim();
    const n = Number(text);
    if (text === '' || !Number.isInteger(n)) { setErrors(prev => ({ ...prev, [setting.key]: 'Escribe un número entero' })); return null; }
    if (n < (setting.min ?? 0) || n > (setting.max ?? Number.MAX_SAFE_INTEGER)) { setErrors(prev => ({ ...prev, [setting.key]: `Debe estar entre ${setting.min} y ${setting.max}` })); return null; }
    return n;
  }

  function askSave(setting: Setting) {
    setErrors(prev => { const next = { ...prev }; delete next[setting.key]; return next; });
    const value = parse(setting);
    if (value === null) return;
    if (value === setting.value) { setErrors(prev => ({ ...prev, [setting.key]: 'No has cambiado el valor' })); return; }
    setPending({ setting, action: 'save', value });
  }

  async function confirm(reason: string) {
    if (!pending) return;
    const { setting, action, value } = pending;
    setBusy(true);
    const result = action === 'save'
      ? await apiCall<{ status?: string; approvalId?: number; message?: string }>('PUT', `/api/system/settings/${setting.key}`, { value, reason })
      : await apiCall<{ status?: string; approvalId?: number; message?: string }>('DELETE', `/api/system/settings/${setting.key}?reason=${encodeURIComponent(reason)}`);
    setBusy(false);
    setPending(null);
    if (!result.ok) { toast(result.message, 'error'); return; }
    setDrafts(prev => { const next = { ...prev }; delete next[setting.key]; return next; });
    if (result.status === 202) {
      setNote(`«${setting.label}»: reduce la seguridad, así que la solicitud #${result.data?.approvalId} queda pendiente. Otro administrador debe aprobarla en «Aprobaciones».`);
    } else {
      setNote(`«${setting.label}» actualizado. Las demás réplicas lo aplican en unos segundos.`);
      void list.reload();
    }
  }

  const groups = list.data?.groups ?? [];

  return (
    <div className="stack">
      <h1>Configuración</h1>
      <p className="muted">
        Ajustes operativos que se cambian en caliente y se guardan en la base de datos. Los secretos, las claves, TLS, CORS y el archivo <code>.env</code> no se tocan desde aquí.
        Los cambios que reducen la seguridad necesitan la aprobación de otro administrador.
      </p>
      <div aria-live="polite">{note ? <Banner tone="ok">{note}</Banner> : null}</div>
      {list.loading && !list.data ? <Loading /> : null}
      {list.error ? <Banner tone="error">{list.error.message}</Banner> : null}

      {groups.map(group => (
        <section key={group.group} className="card stack" aria-labelledby={`g-${group.group}`}>
          <h2 id={`g-${group.group}`}>{group.group}</h2>
          {group.settings.map(setting => {
            const draft = draftOf(setting);
            const inputId = `s-${setting.key}`;
            const error = errors[setting.key];
            return (
              <div key={setting.key} className="setting">
                <div className="setting-head">
                  <strong id={`${inputId}-label`}>{setting.label}</strong>
                  <Badge tone={SOURCE_TONE[setting.source]}>{SOURCE_LABEL[setting.source]}</Badge>
                </div>
                <div className="muted" id={`${inputId}-help`}>{setting.description}</div>
                <div className="setting-controls">
                  {setting.type === 'int' ? (
                    <label htmlFor={inputId}>
                      <span className="muted">Valor{setting.unit ? ` (${setting.unit})` : ''}, de {setting.min} a {setting.max} </span>
                      <input
                        id={inputId} type="number" inputMode="numeric" step={1} min={setting.min} max={setting.max} value={String(draft)}
                        aria-describedby={`${inputId}-help`} aria-invalid={error ? true : undefined}
                        onChange={e => setDrafts(prev => ({ ...prev, [setting.key]: e.target.value }))}
                      />
                    </label>
                  ) : null}
                  {setting.type === 'enum' ? (
                    <label htmlFor={inputId}>
                      <span className="muted">Valor </span>
                      <select id={inputId} value={String(draft)} aria-describedby={`${inputId}-help`} onChange={e => setDrafts(prev => ({ ...prev, [setting.key]: e.target.value }))}>
                        {(setting.values ?? []).map(option => <option key={option} value={option}>{option}</option>)}
                      </select>
                    </label>
                  ) : null}
                  {setting.type === 'bool' ? (
                    <button
                      type="button" role="switch" className="switch" aria-checked={draft === true} aria-labelledby={`${inputId}-label`} aria-describedby={`${inputId}-help`}
                      onClick={() => setDrafts(prev => ({ ...prev, [setting.key]: !(draft === true) }))}
                    >
                      <span className="knob" aria-hidden="true" />{draft === true ? 'Activado' : 'Desactivado'}
                    </button>
                  ) : null}
                  <button type="button" className="primary" onClick={() => askSave(setting)} disabled={busy}>Guardar</button>
                  <button type="button" onClick={() => setPending({ setting, action: 'reset', value: setting.envValue })} disabled={busy || setting.source !== 'db'}>
                    Restablecer al entorno
                  </button>
                </div>
                <div className="muted">
                  Valor del entorno: {show(setting, setting.envValue)}.
                  {setting.updatedAt ? ` Último cambio: ${dateTime(setting.updatedAt)}${setting.updatedBy ? ` por ${setting.updatedBy.username ?? `#${setting.updatedBy.id ?? '?'}`}` : ''}.` : ''}
                </div>
                <div aria-live="polite">{error ? <Banner tone="error">{error}</Banner> : null}</div>
              </div>
            );
          })}
        </section>
      ))}

      <ConfirmDialog
        open={pending !== null}
        title={pending ? (pending.action === 'save' ? `Guardar «${pending.setting.label}»` : `Restablecer «${pending.setting.label}»`) : ''}
        confirmLabel={pending?.action === 'save' ? 'Guardar' : 'Restablecer'}
        requireReason busy={busy} onConfirm={reason => void confirm(reason)} onCancel={() => setPending(null)}
      >
        {pending ? (
          <p>
            {show(pending.setting, pending.setting.value)} → <strong>{show(pending.setting, pending.value)}</strong>.
            Si el cambio reduce la seguridad, quedará pendiente hasta que otro administrador lo apruebe; si no, se aplica ya.
          </p>
        ) : null}
      </ConfirmDialog>
    </div>
  );
}
