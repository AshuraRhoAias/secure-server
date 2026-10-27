import { logout } from '@/lib/bff';
export const POST = (request: Request) => logout(request);
export const dynamic = 'force-dynamic';
