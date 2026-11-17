import { changePassword } from '@/lib/bff';
export const POST = (request: Request) => changePassword(request);
export const dynamic = 'force-dynamic';
