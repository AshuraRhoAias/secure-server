import { NextResponse, type NextRequest } from 'next/server';
import { cookieSecure, sessionCookieName } from '@/lib/config';
import { readSession } from '@/lib/session';

// Proxy de Next 16 (antes "middleware"): se ejecuta ANTES de cada página. Hace dos cosas:
//   1. Puerta de acceso: sin una cookie de sesión válida (descifrable y no caducada) las páginas redirigen a /login. Es solo comodidad y
//      defensa en profundidad: el control real lo hace el API con el Bearer en CADA petición de datos.
//   2. Content-Security-Policy con nonce por petición (+ cabeceras de seguridad), sin 'unsafe-inline' para scripts.

const PUBLIC_PATHS = ['/login'];

export function proxy(request: NextRequest) {
  const { pathname } = request.nextUrl;
  const authenticated = Boolean(readSession(request.cookies.get(sessionCookieName())?.value));

  if (!authenticated && !PUBLIC_PATHS.includes(pathname)) {
    const url = request.nextUrl.clone();
    url.pathname = '/login';
    url.search = '';
    return NextResponse.redirect(url);
  }
  if (authenticated && pathname === '/login') {
    const url = request.nextUrl.clone();
    url.pathname = '/';
    url.search = '';
    return NextResponse.redirect(url);
  }

  const nonce = Buffer.from(crypto.randomUUID()).toString('base64');
  const dev = process.env.NODE_ENV === 'development';
  const csp = [
    "default-src 'self'",
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'${dev ? " 'unsafe-eval'" : ''}`,
    `style-src 'self' 'nonce-${nonce}'${dev ? " 'unsafe-inline'" : ''}`,
    ...(dev ? [] : ["style-src-attr 'none'"]),
    "img-src 'self' data:",
    "font-src 'self'",
    "connect-src 'self'",
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'self'",
    "frame-ancestors 'none'",
    ...(cookieSecure() ? ['upgrade-insecure-requests'] : [])
  ].join('; ');

  const headers = new Headers(request.headers);
  headers.set('x-nonce', nonce);
  headers.set('Content-Security-Policy', csp);

  const response = NextResponse.next({ request: { headers } });
  response.headers.set('Content-Security-Policy', csp);
  if (cookieSecure()) response.headers.set('Strict-Transport-Security', 'max-age=63072000; includeSubDomains');
  return response;
}

export const config = {
  matcher: [
    {
      source: '/((?!bff|session|_next/static|_next/image|favicon.ico).*)',
      missing: [
        { type: 'header', key: 'next-router-prefetch' },
        { type: 'header', key: 'purpose', value: 'prefetch' }
      ]
    }
  ]
};
