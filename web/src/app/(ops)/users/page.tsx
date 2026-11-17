'use client';

import { useState, type FormEvent } from 'react';
import { ConfirmDialog } from '@/components/ConfirmDialog';
import { useToast } from '@/components/Toasts';
import { Badge, Banner, Empty, JsonView, Loading } from '@/components/ui';
import { useApi } from '@/hooks/useApi';
import { apiCall } from '@/lib/client';
import { dateTime } from '@/lib/format';

const ROLES = ['user', 'auditor', 'operator', 'admin'] as const;
type Role = typeof ROLES[number];
const ROLE_LABEL: Record<Role, string> = { user: 'Usuario', auditor: 'Auditor', operator: 'Operador', admin: 'Administrador' };
const ROLE_TONE: Record<Role, 'neutral' | 'info' | 'medium' | 'high'> = { user: 'neutral', auditor: 'info', operator: 'medium', admin: 'high' };

interface UserRow { id: number; username: string | null; role: Role; mfaEnabled: boolean; createdAt: string; mustChangePassword: boolean; activeSessions: number }
interface UsersPage { users: UserRow[]; nextBefore: number | null }
interface Created { user: { id: number; username: string; role: Role }; temporaryPassword: string | null; approvalId?: number; status?: string }

// Contraseña aleatoria para el campo opcional (el servidor genera otra igual de fuerte si el campo queda vacío)
function randomPassword(): string {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789-_.!#$%*+=';
  const limit = 256 - (256 % alphabet.length);
  const out: string[] = [];
  while (out.length < 24) {
    for (const byte of crypto.getRandomValues(new Uint8Array(48))) if (byte < limit && out.length < 24) out.push(alphabet[byte % alphabet.length] as string);
  }
  return out.join('');
}

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

  // Crear usuario
  const [newName, setNewName] = useState('');
  const [newRole, setNewRole] = useState<Role>('user');
  const [newReason, setNewReason] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [creating, setCreating] = useState(false);
  const [created, setCreated] = useState<Created | null>(null);
  const [createError, setCreateError] = useState<string | null>(null);

  // Tabla de usuarios
  const [search, setSearch] = useState('');
  const [query, setQuery] = useState('');
  const [roleFilter, setRoleFilter] = useState<'' | Role>('');
  const list = useApi<UsersPage>(`/api/system/users?limit=100${query ? `&q=${encodeURIComponent(query)}` : ''}${roleFilter ? `&role=${roleFilter}` : ''}`);
  const [roleTarget, setRoleTarget] = useState<UserRow | null>(null);
  const [targetRole, setTargetRole] = useState<Role>('user');

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

  async function createUser(event: FormEvent) {
    event.preventDefault();
    setCreating(true); setCreateError(null); setCreated(null);
    const result = await apiCall<Created>('POST', '/api/system/users', {
      username: newName.trim(), role: newRole, reason: newReason.trim(), ...(newPassword ? { password: newPassword } : {})
    });
    setCreating(false);
    if (!result.ok || !result.data) { setCreateError(result.message); return; }
    setCreated(result.data);
    setNewName(''); setNewReason(''); setNewPassword(''); setNewRole('user');
    if (result.status === 202) toast(`Rol admin pendiente de aprobación (#${result.data.approvalId})`, 'ok');
    void list.reload();
  }

  async function copyPassword() {
    if (!created?.temporaryPassword) return;
    try { await navigator.clipboard.writeText(created.temporaryPassword); toast('Contraseña copiada', 'ok'); }
    catch { toast('No se pudo copiar: selecciónala y cópiala a mano', 'error'); }
  }

  async function changeRole(reason: string) {
    if (!roleTarget) return;
    setBusy(true);
    const result = await apiCall<{ status?: string; approvalId?: number }>('POST', `/api/system/users/${roleTarget.id}/role`, { role: targetRole, reason });
    setBusy(false);
    setRoleTarget(null);
    if (!result.ok) { toast(result.message, 'error'); return; }
    if (result.status === 202) setNote(`Solicitud #${result.data?.approvalId} creada: otro administrador debe aprobar el rol de administrador en «Aprobaciones».`);
    else { setNote(`Rol de «${roleTarget.username ?? `#${roleTarget.id}`}» cambiado a ${ROLE_LABEL[targetRole]}; sus sesiones se cerraron.`); void list.reload(); }
  }

  const rows = list.data?.users ?? [];

  return (
    <div className="stack">
      <h1>Usuarios y sesiones</h1>
      {note ? <Banner tone="ok">{note}</Banner> : null}

      <section className="card stack">
        <h2>Crear usuario</h2>
        <p className="muted">La cuenta nace con una contraseña temporal y el usuario debe cambiarla al entrar. El rol de administrador exige además la aprobación de otro administrador.</p>
        <form className="stack" onSubmit={createUser} aria-label="Crear usuario">
          <div className="field-row">
            <label>Usuario<input value={newName} onChange={e => setNewName(e.target.value)} required minLength={3} maxLength={64} autoComplete="off" /></label>
            <label>Rol
              <select value={newRole} onChange={e => setNewRole(e.target.value as Role)}>
                {ROLES.map(role => <option key={role} value={role}>{ROLE_LABEL[role]}</option>)}
              </select>
            </label>
          </div>
          <label>Motivo (mínimo 10 caracteres, queda en la auditoría)<input value={newReason} onChange={e => setNewReason(e.target.value)} required minLength={10} maxLength={255} autoComplete="off" /></label>
          <div className="field-row">
            <label>Contraseña (opcional)<input value={newPassword} onChange={e => setNewPassword(e.target.value)} minLength={10} maxLength={72} autoComplete="new-password" spellCheck={false} /></label>
            <button type="button" onClick={() => setNewPassword(randomPassword())}>Generar automáticamente</button>
          </div>
          <p className="muted">Si la dejas vacía, el servidor genera una temporal fuerte y te la muestra una sola vez.</p>
          <div className="row"><button type="submit" className="primary" disabled={creating || newName.trim().length < 3 || newReason.trim().length < 10}>{creating ? 'Creando…' : 'Crear usuario'}</button></div>
        </form>
        <div aria-live="polite">
          {createError ? <Banner tone="error">{createError}</Banner> : null}
          {created ? (
            <Banner tone="ok">
              Usuario «{created.user.username}» creado (#{created.user.id}).
              {created.status === 'pending' ? ` Entra con rol Usuario hasta que otro administrador apruebe el rol de administrador (solicitud #${created.approvalId}).` : ''}
              {created.temporaryPassword ? (
                <div className="stack">
                  <div className="row"><strong>Contraseña temporal:</strong> <code className="mono">{created.temporaryPassword}</code> <button type="button" className="small" onClick={() => void copyPassword()}>Copiar</button></div>
                  <div className="muted">Se muestra UNA sola vez: no se guarda en ningún sitio. Entrégala por un canal seguro; el usuario deberá cambiarla al entrar.</div>
                  <div><button type="button" className="small ghost" onClick={() => setCreated(null)}>Ocultar</button></div>
                </div>
              ) : <div className="muted">Usó la contraseña que escribiste; deberá cambiarla al entrar.</div>}
            </Banner>
          ) : null}
        </div>
      </section>

      <section className="card stack">
        <h2>Usuarios</h2>
        <form className="field-row" onSubmit={e => { e.preventDefault(); setQuery(search.trim()); }} role="search" aria-label="Buscar usuarios">
          <label>Nombre exacto<input value={search} onChange={e => setSearch(e.target.value)} maxLength={64} autoComplete="off" /></label>
          <label>Rol
            <select value={roleFilter} onChange={e => setRoleFilter(e.target.value as '' | Role)}>
              <option value="">Todos</option>
              {ROLES.map(role => <option key={role} value={role}>{ROLE_LABEL[role]}</option>)}
            </select>
          </label>
          <button type="submit">Buscar</button>
          {query ? <button type="button" className="ghost" onClick={() => { setSearch(''); setQuery(''); }}>Quitar búsqueda</button> : null}
        </form>
        {list.loading && !list.data ? <Loading /> : null}
        {list.error ? <Banner tone="error">{list.error.message}</Banner> : null}
        {list.data && rows.length === 0 ? <Empty>No hay usuarios con este filtro.</Empty> : null}
        {rows.length > 0 ? (
          <div className="table-wrap" tabIndex={0}><table>
            <thead><tr><th>#</th><th>Usuario</th><th>Rol</th><th>MFA</th><th>Contraseña</th><th>Sesiones</th><th>Alta</th><th>Acciones</th></tr></thead>
            <tbody>{rows.map(user => (
              <tr key={user.id}>
                <td className="mono">{user.id}</td>
                <td>{user.username ?? '(sin nombre)'}</td>
                <td><Badge tone={ROLE_TONE[user.role]}>{ROLE_LABEL[user.role]}</Badge></td>
                <td>{user.mfaEnabled ? <Badge tone="ok">Activo</Badge> : <span className="muted">No</span>}</td>
                <td>{user.mustChangePassword ? <Badge tone="medium">Debe cambiarla</Badge> : <span className="muted">—</span>}</td>
                <td>{user.activeSessions}</td>
                <td>{dateTime(user.createdAt)}</td>
                <td><button type="button" className="small" onClick={() => { setRoleTarget(user); setTargetRole(ROLES.find(role => role !== user.role) ?? 'user'); }}>Cambiar rol…</button></td>
              </tr>
            ))}</tbody>
          </table></div>
        ) : null}
        {list.data?.nextBefore ? <p className="muted">Hay más usuarios: afina la búsqueda o el filtro de rol (se muestran los 100 más recientes).</p> : null}
      </section>

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

      <ConfirmDialog open={Boolean(roleTarget)} busy={busy} title={`Cambiar el rol de «${roleTarget?.username ?? `#${roleTarget?.id ?? ''}`}»`} requireReason
        confirmLabel="Cambiar rol" onCancel={() => setRoleTarget(null)} onConfirm={(reason) => void changeRole(reason)}>
        <label>Rol nuevo
          <select value={targetRole} onChange={e => setTargetRole(e.target.value as Role)}>
            {ROLES.filter(role => role !== roleTarget?.role).map(role => <option key={role} value={role}>{ROLE_LABEL[role]}</option>)}
          </select>
        </label>
        <p className="muted">{targetRole === 'admin' ? 'Dar el rol de administrador exige la aprobación de otro administrador (quedará pendiente).' : 'Se aplica al momento y se cierran todas las sesiones del usuario.'}</p>
      </ConfirmDialog>

      <ConfirmDialog open={Boolean(pending)} busy={busy} danger title={pending?.title ?? ''} requireReason requirePhrase={pending?.phrase}
        confirmLabel="Confirmar" onCancel={() => setPending(null)} onConfirm={(reason) => { if (pending) void run(pending.run, reason); }}>
        <p>{pending?.text}</p>
      </ConfirmDialog>
    </div>
  );
}
