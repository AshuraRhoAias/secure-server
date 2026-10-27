'use client';

import { useState, type FormEvent } from 'react';
import { Banner } from '@/components/ui';
import { apiCall } from '@/lib/client';

type Step = 'password' | 'mfa';

export default function LoginPage() {
  const [step, setStep] = useState<Step>('password');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [recovery, setRecovery] = useState(false);
  const expired = typeof window !== 'undefined' && new URLSearchParams(window.location.search).has('expired');

  async function submitPassword(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    setBusy(true); setError(null);
    const result = await apiCall<{ mfaRequired?: boolean }>('POST', '/session/login', { username: String(form.get('username') ?? ''), password: String(form.get('password') ?? '') });
    setBusy(false);
    if (result.ok && result.data?.mfaRequired) { setStep('mfa'); return; }
    if (result.ok) { window.location.assign('/'); return; }
    setError(result.status === 429 ? `${result.message}. Espera un momento y vuelve a intentarlo.` : result.message);
  }

  async function submitMfa(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const code = String(form.get('code') ?? '').trim();
    setBusy(true); setError(null);
    const result = await apiCall('POST', '/session/mfa', recovery ? { recoveryCode: code } : { otp: code });
    setBusy(false);
    if (result.ok) { window.location.assign('/'); return; }
    if (result.code === 'MFA_EXPIRED') setStep('password');
    setError(result.message);
  }

  return (
    <div className="login-wrap">
      <div className="card login-card">
        <div className="brand"><span className="brand-mark" aria-hidden="true">⛨</span><span>secure-server<br /><span className="muted">Operación y observabilidad</span></span></div>
        {expired ? <Banner tone="warn">Tu sesión terminó. Inicia sesión de nuevo.</Banner> : null}
        {error ? <Banner tone="error">{error}</Banner> : null}

        {step === 'password' ? (
          <form onSubmit={submitPassword} aria-label="Iniciar sesión">
            <label>Usuario<input name="username" autoComplete="username" required maxLength={64} autoFocus /></label>
            <label>Contraseña<input name="password" type="password" autoComplete="current-password" required maxLength={128} /></label>
            <button type="submit" className="primary" disabled={busy}>{busy ? 'Entrando…' : 'Entrar'}</button>
            <p className="muted">Solo para administradores. Las cuentas con privilegios necesitan segundo factor.</p>
          </form>
        ) : (
          <form onSubmit={submitMfa} aria-label="Segundo factor">
            <p>{recovery ? 'Escribe uno de tus códigos de recuperación.' : 'Escribe el código de 6 dígitos de tu aplicación de autenticación.'}</p>
            <label>{recovery ? 'Código de recuperación' : 'Código'}
              <input name="code" inputMode={recovery ? 'text' : 'numeric'} autoComplete="one-time-code" required maxLength={recovery ? 40 : 6} pattern={recovery ? undefined : '\\d{6}'} autoFocus />
            </label>
            <button type="submit" className="primary" disabled={busy}>{busy ? 'Comprobando…' : 'Verificar'}</button>
            <button type="button" className="ghost" onClick={() => { setRecovery(r => !r); setError(null); }}>{recovery ? 'Usar el código de la aplicación' : 'Usar un código de recuperación'}</button>
            <button type="button" className="ghost" onClick={() => { setStep('password'); setError(null); }}>Volver</button>
          </form>
        )}
      </div>
    </div>
  );
}
