import { loginMfa } from '@/lib/bff';
export const POST = (request: Request) => loginMfa(request);
export const dynamic = 'force-dynamic';
