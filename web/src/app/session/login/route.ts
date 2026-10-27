import { login } from '@/lib/bff';
export const POST = (request: Request) => login(request);
export const dynamic = 'force-dynamic';
