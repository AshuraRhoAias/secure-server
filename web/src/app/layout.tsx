import type { Metadata, Viewport } from 'next';
import { connection } from 'next/server';
import type { ReactNode } from 'react';
import './globals.css';

export const metadata: Metadata = {
  title: { default: 'Operación · secure-server', template: '%s · secure-server' },
  description: 'Operación y observabilidad de secure-server (solo administradores)',
  robots: { index: false, follow: false }
};
export const viewport: Viewport = { width: 'device-width', initialScale: 1, colorScheme: 'light dark' };

export default async function RootLayout({ children }: { children: ReactNode }) {
  await connection(); // renderizado dinámico: la CSP lleva un nonce distinto en cada petición (ver proxy.ts)
  return (
    <html lang="es">
      <body>{children}</body>
    </html>
  );
}
