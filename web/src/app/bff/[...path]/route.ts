import { proxyData } from '@/lib/bff';

// Proxy de datos hacia el API (lista cerrada de rutas en lib/allowlist.ts). Ver lib/bff.ts.
type Context = { params: Promise<{ path: string[] }> };

const handle = async (request: Request, context: Context): Promise<Response> => {
  const { path } = await context.params;
  return proxyData(request, path, new URL(request.url).search);
};

export const GET = handle;
export const POST = handle;
export const DELETE = handle;
export const dynamic = 'force-dynamic';
