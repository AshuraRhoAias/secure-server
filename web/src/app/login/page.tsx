'use client';

import { useEffect, useState, type FormEvent } from 'react';
import { Banner } from '@/components/ui';
import { apiCall } from '@/lib/client';
import { passkeyErrorMessage, passkeysSupported, signWithPasskey } from '@/lib/webauthn-client';

type Step = 'password' | 'mfa' | 'change';

// Mensajes de vuelta del SSO (/session/sso/callback → /login?sso_error=CÓDIGO): nunca se muestra texto que venga en la URL
const SSO_ERRORS: Record<string, string> = {
  SSO_EXPIRED: 'El inicio de sesión con el proveedor caducó. Vuelve a intentarlo.',
  SSO_HANDOFF_INVALID: 'El inicio de sesión con el proveedor caducó o ya se usó. Vuelve a intentarlo.',
  NOT_ADMIN: 'Tu cuenta no es de administrador: esta interfaz es solo para administradores.',
  MFA_REQUIRED: 'Los administradores necesitan un segundo factor también con SSO: actívalo en tu cuenta.',
  SSO_FORBIDDEN: 'El inicio de sesión con SSO solo puede empezar desde esta página.',
  UPSTREAM_UNAVAILABLE: 'El servidor no responde. Inténtalo en un momento.'
};

export default function LoginPage() {
  const [step, setStep] = useState<Step>('password');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [recovery, setRecovery] = useState(false);
  const [methods, setMethods] = useState<string[]>([]);
  const [sso, setSso] = useState<{ oidc: boolean; saml: boolean }>({ oidc: false, saml: false });
  const [canPasskey, setCanPasskey] = useState(false);
  const params = typeof window !== 'undefined' ? new URLSearchParams(window.location.search) : null;
  const expired = params?.has('expired') ?? false;

  useEffect(() => {
    setCanPasskey(passkeysSupported());
    const code = new URLSearchParams(window.location.search).get('sso_error');
    if (code) setError(SSO_ERRORS[code] ?? 'No se pudo iniciar sesión con el proveedor.');
    void apiCall<{ oidc: boolean; saml: boolean }>('GET', '/session/sso/status').then(r => { if (r.ok && r.data) setSso({ oidc: r.data.oidc === true, saml: r.data.saml === true }); });
  }, []);

  // Login correcto: si el administrador puso una contraseña temporal, primero hay que cambiarla
  function afterLogin(data: { passwordChangeRequired?: boolean } | null) {
    if (data?.passwordChangeRequired === true) { setStep('change'); setError(null); return; }
    window.location.assign('/');
  }

  async function submitChange(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const currentPassword = String(form.get('currentPassword') ?? '');
    const newPassword = String(form.get('newPassword') ?? '');
    if (newPassword !== String(form.get('repeatPassword') ?? '')) { setError('Las contraseñas nuevas no coinciden.'); return; }
    if (newPassword === currentPassword) { setError('La contraseña nueva debe ser distinta de la temporal.'); return; }
    setBusy(true); setError(null);
    const result = await apiCall('POST', '/session/password', { currentPassword, newPassword });
    setBusy(false);
    if (result.ok) { window.location.assign('/'); return; }
    // NO_SESSION: caducó; NOT_ADMIN / MFA_REQUIRED: la contraseña YA se cambió y el BFF cerró la sesión → vuelta al inicio
    if (result.code === 'NO_SESSION' || result.code === 'NOT_ADMIN' || result.code === 'MFA_REQUIRED') { setStep('password'); }
    setError(result.message);
  }

  async function submitPassword(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    setBusy(true); setError(null);
    const result = await apiCall<{ mfaRequired?: boolean; methods?: string[]; passwordChangeRequired?: boolean }>('POST', '/session/login', { username: String(form.get('username') ?? ''), password: String(form.get('password') ?? '') });
    setBusy(false);
    if (result.ok && result.data?.mfaRequired) {
      const offered = Array.isArray(result.data.methods) ? result.data.methods : [];
      setMethods(offered);
      setRecovery(!offered.includes('totp') && !offered.includes('webauthn'));
      setStep('mfa');
      return;
    }
    if (result.ok) { afterLogin(result.data); return; }
    setError(result.status === 429 ? `${result.message}. Espera un momento y vuelve a intentarlo.` : result.message);
  }

  async function submitMfa(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const code = String(form.get('code') ?? '').trim();
    setBusy(true); setError(null);
    const result = await apiCall<{ passwordChangeRequired?: boolean }>('POST', '/session/mfa', recovery ? { recoveryCode: code } : { otp: code });
    setBusy(false);
    if (result.ok) { afterLogin(result.data); return; }
    if (result.code === 'MFA_EXPIRED') setStep('password');
    setError(result.message);
  }

  async function usePasskey() {
    setBusy(true); setError(null);
    const options = await apiCall<{ options: Parameters<typeof signWithPasskey>[0] }>('POST', '/session/webauthn/options', {});
    if (!options.ok || !options.data?.options) {
      setBusy(false);
      if (options.code === 'MFA_EXPIRED') setStep('password');
      setError(options.message || 'No se pudo preparar la llave.');
      return;
    }
    let credential: Record<string, unknown>;
    try { credential = await signWithPasskey(options.data.options); }
    catch (e) { setBusy(false); setError(passkeyErrorMessage(e)); return; }
    const result = await apiCall<{ passwordChangeRequired?: boolean }>('POST', '/session/webauthn', { credential });
    setBusy(false);
    if (result.ok) { afterLogin(result.data); return; }
    if (result.code === 'MFA_EXPIRED') setStep('password');
    setError(result.message);
  }

  const hasTotp = methods.includes('totp');
  const hasPasskey = methods.includes('webauthn') && canPasskey;

  return (
    <div className="login-wrap">
      <main className="card login-card" id="contenido">
        <div className="brand"><span className="brand-mark" aria-hidden="true">⛨</span><span>secure-server<br /><span className="muted">Operación y observabilidad</span></span></div>
        <h1 className="visually-hidden">Iniciar sesión</h1>
        {expired ? <Banner tone="warn">Tu sesión terminó. Inicia sesión de nuevo.</Banner> : null}
        {error ? <Banner tone="error">{error}</Banner> : null}

        {step === 'change' ? (
          <form onSubmit={submitChange} aria-label="Cambia tu contraseña">
            <h2>Cambia tu contraseña</h2>
            <p id="change-help" className="muted">Tu cuenta tiene una contraseña temporal. Elige una nueva (mínimo 10 caracteres) para continuar.</p>
            <label>Contraseña actual (la temporal)<input name="currentPassword" type="password" autoComplete="current-password" required maxLength={128} autoFocus /></label>
            <label>Contraseña nueva<input name="newPassword" type="password" autoComplete="new-password" required minLength={10} maxLength={128} aria-describedby="change-help" /></label>
            <label>Repite la contraseña nueva<input name="repeatPassword" type="password" autoComplete="new-password" required minLength={10} maxLength={128} /></label>
            <button type="submit" className="primary" disabled={busy}>{busy ? 'Guardando…' : 'Cambiar contraseña y continuar'}</button>
          </form>
        ) : step === 'password' ? (
          <>
            <form onSubmit={submitPassword} aria-label="Iniciar sesión">
              <label>Usuario<input name="username" autoComplete="username" required maxLength={64} autoFocus /></label>
              <label>Contraseña<input name="password" type="password" autoComplete="current-password" required maxLength={128} /></label>
              <button type="submit" className="primary" disabled={busy}>{busy ? 'Entrando…' : 'Entrar'}</button>
              <p className="muted">Solo para administradores. Las cuentas con privilegios necesitan segundo factor.</p>
            </form>
            {sso.oidc || sso.saml ? (
              <nav aria-label="Inicio de sesión con proveedor de identidad">
                <div className="login-divider">o</div>
                <div className="stack">
                  {sso.oidc ? <a className="button" href="/session/sso/start?provider=oidc">Entrar con SSO (OpenID Connect)</a> : null}
                  {sso.saml ? <a className="button" href="/session/sso/start?provider=saml">Entrar con SSO (SAML)</a> : null}
                </div>
              </nav>
            ) : null}
          </>
        ) : (
          <form onSubmit={submitMfa} aria-label="Segundo factor">
            {hasPasskey ? (
              <>
                <button type="button" className="primary" onClick={() => void usePasskey()} disabled={busy}>{busy ? 'Esperando a la llave…' : 'Usar passkey o llave de seguridad'}</button>
                <div className="login-divider">o con un código</div>
              </>
            ) : null}
            <p id="mfa-help">{recovery ? 'Escribe uno de tus códigos de recuperación.' : 'Escribe el código de 6 dígitos de tu aplicación de autenticación.'}</p>
            {recovery || hasTotp ? (
              <>
                <label>{recovery ? 'Código de recuperación' : 'Código'}
                  <input name="code" aria-describedby="mfa-help" inputMode={recovery ? 'text' : 'numeric'} autoComplete="one-time-code" required maxLength={recovery ? 40 : 6} pattern={recovery ? undefined : '\\d{6}'} autoFocus={!hasPasskey} />
                </label>
                <button type="submit" className={hasPasskey ? undefined : 'primary'} disabled={busy}>{busy ? 'Comprobando…' : 'Verificar'}</button>
              </>
            ) : null}
            {hasTotp ? <button type="button" className="ghost" onClick={() => { setRecovery(r => !r); setError(null); }}>{recovery ? 'Usar el código de la aplicación' : 'Usar un código de recuperación'}</button> : null}
            {!hasTotp && !recovery ? <button type="button" className="ghost" onClick={() => { setRecovery(true); setError(null); }}>Usar un código de recuperación</button> : null}
            <button type="button" className="ghost" onClick={() => { setStep('password'); setError(null); }}>Volver</button>
          </form>
        )}
      </main>
    </div>
  );
}
