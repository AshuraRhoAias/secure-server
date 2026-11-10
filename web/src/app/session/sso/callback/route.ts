import { ssoCallback } from '@/lib/sso';
export const GET = (request: Request) => ssoCallback(request);
export const dynamic = 'force-dynamic';
