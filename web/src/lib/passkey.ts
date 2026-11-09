import { mfaCookieName } from './config';
import { csrfOk } from './csrf';
import { clearMfaCookie, readMfaChallenge } from './session';
import { completeLogin, cookieValue, json, upstreamError } from './bff';
import { callApi, parseJson, type UpstreamResult } from './upstream';

// Segundo factor con PASSKEY / llave de seguridad (WebAuthn) desde la interfaz.
//
//   1. POST /session/webauthn/options → el BFF pide al API el reto con el mfaToken que guarda la cookie httpOnly de MFA
//   2. el navegador firma con navigator.credentials.get() (la clave privada nunca sale del autenticador)
//   3. POST /session/webauthn { credential } → el BFF lo entrega al API con el mismo mfaToken → sesión de administrador
//
// El reto lo genera y lo comprueba el API (de un solo uso, ligado al usuario). El navegador nunca ve el mfaToken ni los tokens.
// Requisito de despliegue: WEBAUTHN_RP_ID / WEBAUTHN_ORIGINS del API deben incluir el ORIGEN DE ESTA INTERFAZ (la firma lo lleva dentro).

const forbidden = () => json(403, { success: false, message: 'Solicitud no permitida', code: 'CSRF' });
const expired = () => json(401, { success: false, message: 'El paso anterior caducó: vuelve a escribir usuario y contraseña', code: 'MFA_EXPIRED' }, [clearMfaCookie()]);
const MAX_CREDENTIAL_BYTES = 16 * 1024;

export async function passkeyOptions(request: Request): Promise<Response> {
  if (!csrfOk('POST', request.headers)) return forbidden();
  const challenge = readMfaChallenge(cookieValue(request, mfaCookieName()));
  if (!challenge) return expired();

  let result: UpstreamResult;
  try { result = await callApi('/api/auth/login/webauthn/options', { method: 'POST', json: { mfaToken: challenge.token }, headers: request.headers }); }
  catch { return json(502, { success: false, message: 'El API no responde', code: 'UPSTREAM_UNAVAILABLE' }); }

  const body = parseJson(result.body);
  if (result.status !== 200 || !body || typeof body.options !== 'object' || body.options === null) return upstreamError(result);
  // Solo las opciones públicas del reto (challenge, rpId, allowCredentials, timeout, userVerification)
  return json(200, { success: true, options: body.options });
}

export async function passkeyLogin(request: Request): Promise<Response> {
  if (!csrfOk('POST', request.headers)) return forbidden();
  const challenge = readMfaChallenge(cookieValue(request, mfaCookieName()));
  if (!challenge) return expired();

  const text = await request.text().catch(() => '');
  if (text.length > MAX_CREDENTIAL_BYTES) return json(413, { success: false, message: 'Respuesta de la llave demasiado grande' });
  const credential = parseJson(text)?.credential;
  if (!credential || typeof credential !== 'object' || Array.isArray(credential)) {
    return json(400, { success: false, message: 'Falta la respuesta de la llave', code: 'VALIDATION_ERROR' });
  }

  let result: UpstreamResult;
  try { result = await callApi('/api/auth/login/webauthn', { method: 'POST', json: { mfaToken: challenge.token, credential }, headers: request.headers }); }
  catch { return json(502, { success: false, message: 'El API no responde', code: 'UPSTREAM_UNAVAILABLE' }); }

  const body = parseJson(result.body);
  if (result.status !== 200 || !body) return upstreamError(result);
  return completeLogin(request, body);
}
