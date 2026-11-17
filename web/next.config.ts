import path from 'path';
import type { NextConfig } from 'next';

// La raíz del proyecto web es esta carpeta: hay otro package-lock.json en la raíz del repositorio (el API) y, sin fijarla, Next la
// infería mal (aviso en cada build) y metía la raíz del repositorio en el trazado de `standalone`. web/ no importa nada de fuera.
const root = path.resolve(__dirname);

// Las cabeceras que dependen de cada petición (CSP con nonce) las pone proxy.ts; aquí van las estáticas.
const config: NextConfig = {
  poweredByHeader: false,
  reactStrictMode: true,
  output: 'standalone',
  outputFileTracingRoot: root,
  turbopack: { root },
  async headers() {
    return [
      {
        source: '/:path*',
        headers: [
          { key: 'X-Content-Type-Options', value: 'nosniff' },
          { key: 'X-Frame-Options', value: 'DENY' },
          { key: 'Referrer-Policy', value: 'no-referrer' },
          { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=(), payment=(), usb=()' },
          { key: 'Cross-Origin-Opener-Policy', value: 'same-origin' },
          { key: 'Cross-Origin-Resource-Policy', value: 'same-origin' },
          { key: 'Cache-Control', value: 'no-store' }
        ]
      }
    ];
  }
};

export default config;
