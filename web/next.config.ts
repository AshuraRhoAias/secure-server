import type { NextConfig } from 'next';

// Las cabeceras que dependen de cada petición (CSP con nonce) las pone proxy.ts; aquí van las estáticas.
const config: NextConfig = {
  poweredByHeader: false,
  reactStrictMode: true,
  output: 'standalone',
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
