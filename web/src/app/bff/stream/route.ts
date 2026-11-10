import { proxyStream } from '@/lib/stream';

// Novedades en vivo (Server-Sent Events) del API, con el Bearer de la sesión. Ver lib/stream.ts.
export const GET = (request: Request) => proxyStream(request);
export const dynamic = 'force-dynamic';
export const runtime = 'nodejs';
