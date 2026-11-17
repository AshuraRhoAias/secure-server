import type { Metadata, Viewport } from 'next';
import { Inter, JetBrains_Mono } from 'next/font/google';
import { connection } from 'next/server';
import type { ReactNode } from 'react';
import { Backdrop3D } from '@/components/Backdrop3D';
import './globals.css';

// Fuentes autoalojadas por next/font (se descargan al compilar y se sirven desde 'self': cumplen font-src de la CSP)
const sans = Inter({ subsets: ['latin'], variable: '--font-sans', display: 'swap' });
const mono = JetBrains_Mono({ subsets: ['latin'], variable: '--font-mono', display: 'swap', preload: false }); // no se usa en todas las páginas

export const metadata: Metadata = {
  title: { default: 'Operación · secure-server', template: '%s · secure-server' },
  description: 'Operación y observabilidad de secure-server (solo administradores)',
  robots: { index: false, follow: false }
};
export const viewport: Viewport = { width: 'device-width', initialScale: 1, colorScheme: 'light dark' };

export default async function RootLayout({ children }: { children: ReactNode }) {
  await connection(); // renderizado dinámico: la CSP lleva un nonce distinto en cada petición (ver proxy.ts)
  return (
    <html lang="es" className={`${sans.variable} ${mono.variable}`}>
      <body>
        <Backdrop3D />
        {children}
      </body>
    </html>
  );
}
