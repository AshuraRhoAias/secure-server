'use client';

// Passkeys en el navegador: convierte las opciones JSON del API (base64url) al formato binario de navigator.credentials.get() y la
// respuesta firmada otra vez a JSON (el que entiende @simplewebauthn/server en el API). Sin dependencias.

const toBuffer = (base64url: string): ArrayBuffer => {
  const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(base64url.length / 4) * 4, '=');
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
};

const toBase64url = (buffer: ArrayBuffer | null): string | undefined => {
  if (!buffer) return undefined;
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};

interface RequestOptionsJson {
  challenge: string; timeout?: number; rpId?: string; userVerification?: UserVerificationRequirement;
  allowCredentials?: { id: string; type?: 'public-key'; transports?: AuthenticatorTransport[] }[];
}

export const passkeysSupported = (): boolean =>
  typeof window !== 'undefined' && typeof window.PublicKeyCredential === 'function' && typeof navigator.credentials?.get === 'function';

export async function signWithPasskey(options: RequestOptionsJson): Promise<Record<string, unknown>> {
  const publicKey: PublicKeyCredentialRequestOptions = {
    challenge: toBuffer(options.challenge),
    timeout: options.timeout,
    rpId: options.rpId,
    userVerification: options.userVerification,
    allowCredentials: (options.allowCredentials ?? []).map(c => ({ id: toBuffer(c.id), type: 'public-key', transports: c.transports }))
  };
  const credential = await navigator.credentials.get({ publicKey }) as PublicKeyCredential | null;
  if (!credential) throw new Error('No se obtuvo ninguna firma');
  const response = credential.response as AuthenticatorAssertionResponse;
  return {
    id: credential.id,
    rawId: toBase64url(credential.rawId),
    type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment ?? undefined,
    clientExtensionResults: credential.getClientExtensionResults(),
    response: {
      clientDataJSON: toBase64url(response.clientDataJSON),
      authenticatorData: toBase64url(response.authenticatorData),
      signature: toBase64url(response.signature),
      userHandle: toBase64url(response.userHandle)
    }
  };
}

// Mensaje claro para los errores del navegador (cancelado, sin llave, origen no permitido…)
export function passkeyErrorMessage(error: unknown): string {
  const name = error instanceof Error ? error.name : '';
  if (name === 'NotAllowedError') return 'Se canceló o caducó la solicitud de la llave.';
  if (name === 'SecurityError') return 'Este origen no está autorizado para las passkeys del servidor (revisa WEBAUTHN_RP_ID / WEBAUTHN_ORIGINS).';
  if (name === 'InvalidStateError') return 'La llave no está registrada para esta cuenta.';
  return 'No se pudo usar la llave de seguridad.';
}
