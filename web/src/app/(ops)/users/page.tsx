'use client';

import { useState, type FormEvent } from 'react';
import { ConfirmDialog } from '@/components/ConfirmDialog';
import { useToast } from '@/components/Toasts';
import { Banner, JsonView } from '@/components/ui';
import { apiCall } from '@/lib/client';

type Pending = null | { kind: 'revoke-user' | 'revoke-all' | 'erase' | 'mfa-reset'; run: (reason: string) => Promise<void>; title: string; phrase?: string; text: string };

export default function UsersPage() {
  const { toast } = useToast();
  const [userId, setUserId] = useState('');
  const [username, setUsername] = useState('');
  const [confirmName, setConfirmName] = useState('');
  const [exported, setExported] = useState<unknown>(null);
  const [pending, setPending] = useState<Pending>(null);
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState<string | null>(null);

  const id = /^[1-9]\d{0,9}$/.test(userId.trim()) ? userId.trim() : null;

  async function run(task: (reason: string) => Promise<void>, reason: string) {
    setBusy(true);
    try { await task(reason); } finally { setBusy(false); setPending(null); }
  }

  async function exportData(event: FormEvent) {
    event.preventDefault();
    if (!id) return;
    const result = await apiCall<{ export: unknown }>('GET', `/api/system/users/${id}/export`);
    if (!result.ok) { toast(result.message, 'error'); return; }
    setExported(result.data?.export ?? null);
    toast('Datos exportados (quedan en la auditoría)', 'ok');
  }

  const downloadExport = () => {
    const url = URL.createObjectURL(new Blob([JSON.stringify(exported, null, 2)], { type: 'application/json' }));
    const link = document.createElement('a');
    link.href = url; link.download = `usuario-${id}-exportacion.json`;
    document.body.appendChild(link); link.click(); link.remove(); URL.revokeObjectURL(url);
  };

  const approvalNote = (data: { status?: string; approvalId?: number } | null, fallback: string) =>
    setNote(data?.status === 'pending' ? `Solicitud #${data.approvalId} creada: otro administrador debe aprobarla en «Aprobaciones».` : fallback);

  return (
    <div className="stack">
      <h1>Usuarios y sesiones</h1>
      {note ? <Banner tone="ok">{note}</Banner> : null}

      <section className="card stack">
        <h2>Cerrar sesiones</h2>
        <div className="field-row">
          <label>Id de usuario<input value={userId} onChange={e => setUserId(e.target.value)} inputMode="numeric" maxLength={10} /></label>
          <button type="button" disabled={!id} onClick={() => setPending({
            kind: 'revoke-user', title: `Cerrar todas las sesiones del usuario #${id}`, text: 'Tendrá que iniciar sesión de nuevo en todos sus dispositivos.',
            run: async (reason) => { const r = await apiCall<{ closed: number }>('POST', `/api/system/users/${id}/revoke-sessions`, { reason }); if (r.ok) toast(`${r.data?.closed ?? 0} sesión(es) cerradas`, 'ok'); else toast(r.message, 'error'); }
          })}>Cerrar sus sesiones</button>
        </div>
        <hr />
        <div className="row">
          <div><strong>Cerrar las sesiones de TODOS los usuarios</strong><div className="muted">Para un incidente grave (p. ej. se sospecha de la clave de firma). También cierra la tuya.</div></div>
          <button type="button" className="danger" onClick={() => setPending({
            kind: 'revoke-all', title: 'Cerrar TODAS las sesiones', phrase: 'REVOKE-ALL-SESSIONS', text: 'Nadie podrá seguir usando la plataforma hasta volver a iniciar sesión.',
            run: async (reason) => { const r = await apiCall<{ closed: number }>('POST', '/api/system/sessions/revoke-all', { reason, confirm: 'REVOKE-ALL-SESSIONS' }); if (r.ok) { toast(`${r.data?.closed ?? 0} sesiones cerradas`, 'ok'); window.setTimeout(() => window.location.assign('/login'), 1200); } else toast(r.message, 'error'); }
          })}>Cerrar todas…</button>
        </div>
      </section>

      <section className="card stack">
        <h2>Datos personales</h2>
        <form className="field-row" onSubmit={exportData}>
          <label>Id de usuario<input value={userId} onChange={e => setUserId(e.target.value)} inputMode="numeric" maxLength={10} /></label>
          <button type="submit" className="primary" disabled={!id}>Exportar sus datos</button>
          <label>Para pedir el borrado, nombre exacto del usuario<input value={confirmName} onChange={e => setConfirmName(e.target.value)} maxLength={64} autoComplete="off" /></label>
          <button type="button" className="danger" disabled={!id || !confirmName.trim()} onClick={() => {
            const confirmUsername = confirmName.trim();
            setPending({
              kind: 'erase', title: `Pedir el borrado de los datos del usuario #${id}`, text: 'Es irreversible. Se ejecuta solo cuando OTRO administrador lo aprueba. Los eventos de seguridad se anonimizan; las copias de seguridad existentes conservan los datos hasta que caduquen.',
              run: async (reason) => { const r = await apiCall<{ status?: string; approvalId?: number }>('POST', `/api/system/users/${id}/erase`, { reason, confirmUsername }); if (r.ok) approvalNote(r.data, 'Datos borrados'); else toast(r.message, 'error'); }
            });
          }}>Pedir borrado…</button>
        </form>
        {exported ? <div className="stack"><div className="row"><strong>Exportación</strong><button type="button" className="small" onClick={downloadExport}>Descargar JSON</button><button type="button" className="small ghost" onClick={() => setExported(null)}>Ocultar</button></div><JsonView value={exported} /></div> : null}
      </section>

      <section className="card stack">
        <h2>Reset de MFA</h2>
        <p className="muted">Para quien perdió su dispositivo y sus códigos de recuperación. Desactiva su segundo factor y cierra todas sus sesiones, pero solo cuando otro administrador lo aprueba.</p>
        <div className="field-row">
          <label>Nombre de usuario<input value={username} onChange={e => setUsername(e.target.value)} maxLength={64} autoComplete="off" /></label>
          <button type="button" disabled={!username.trim()} onClick={() => setPending({
            kind: 'mfa-reset', title: `Pedir el reset de MFA de «${username.trim()}»`, text: 'Quedará pendiente hasta que otro administrador lo apruebe.',
            run: async (reason) => { const r = await apiCall<{ status?: string; approvalId?: number }>('POST', '/api/system/accounts/mfa-reset', { username: username.trim(), reason }); if (r.ok) approvalNote(r.data, 'MFA desactivado'); else toast(r.message, 'error'); }
          })}>Pedir reset…</button>
        </div>
      </section>

      <ConfirmDialog open={Boolean(pending)} busy={busy} danger title={pending?.title ?? ''} requireReason requirePhrase={pending?.phrase}
        confirmLabel="Confirmar" onCancel={() => setPending(null)} onConfirm={(reason) => { if (pending) void run(pending.run, reason); }}>
        <p>{pending?.text}</p>
      </ConfirmDialog>
    </div>
  );
}
