'use client';

import { useEffect, useRef, useState, type ReactNode } from 'react';

// Confirmación modal (<dialog> nativo: foco atrapado, Esc cierra). Para acciones destructivas puede exigir escribir una frase.
export function ConfirmDialog({
  open, title, children, confirmLabel = 'Confirmar', danger = false, requirePhrase, requireReason, busy = false, onConfirm, onCancel
}: {
  open: boolean; title: string; children?: ReactNode; confirmLabel?: string; danger?: boolean;
  requirePhrase?: string; requireReason?: boolean; busy?: boolean;
  onConfirm: (reason: string) => void; onCancel: () => void;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  const [phrase, setPhrase] = useState('');
  const [reason, setReason] = useState('');

  useEffect(() => {
    const dialog = ref.current;
    if (!dialog) return;
    if (open && !dialog.open) { setPhrase(''); setReason(''); dialog.showModal(); }
    if (!open && dialog.open) dialog.close();
  }, [open]);

  const reasonOk = !requireReason || reason.trim().length >= 10;
  const phraseOk = !requirePhrase || phrase === requirePhrase;

  return (
    <dialog ref={ref} onCancel={event => { event.preventDefault(); onCancel(); }} aria-labelledby="confirm-title">
      <form method="dialog" className="stack" onSubmit={event => { event.preventDefault(); if (reasonOk && phraseOk && !busy) onConfirm(reason.trim()); }}>
        <h2 id="confirm-title">{title}</h2>
        {children}
        {requireReason ? (
          <label>Motivo (mínimo 10 caracteres, queda en la auditoría)
            <textarea value={reason} onChange={e => setReason(e.target.value)} rows={3} maxLength={255} required />
          </label>
        ) : null}
        {requirePhrase ? (
          <label>Escribe <code>{requirePhrase}</code> para confirmar
            <input value={phrase} onChange={e => setPhrase(e.target.value)} autoComplete="off" spellCheck={false} />
          </label>
        ) : null}
        <div className="row">
          <button type="button" onClick={onCancel}>Cancelar</button>
          <button type="submit" className={danger ? 'danger' : 'primary'} disabled={!reasonOk || !phraseOk || busy}>{busy ? 'Procesando…' : confirmLabel}</button>
        </div>
      </form>
    </dialog>
  );
}
